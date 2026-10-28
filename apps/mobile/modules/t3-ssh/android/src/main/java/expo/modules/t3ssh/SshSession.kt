package expo.modules.t3ssh

import net.schmizz.keepalive.KeepAliveProvider
import net.schmizz.keepalive.KeepAliveRunner
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.common.KeyType
import net.schmizz.sshj.connection.channel.direct.Parameters
import net.schmizz.sshj.transport.DisconnectListener
import net.schmizz.sshj.transport.verification.HostKeyVerifier
import net.schmizz.sshj.userauth.keyprovider.KeyPairWrapper
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.security.KeyPair
import java.security.PublicKey
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** One SSH server on the way to the target. The last hop is the target. */
data class SshHop(
  val host: String,
  val port: Int,
  val user: String,
  val hostKeyAlias: String? = null
) {
  /** The known_hosts name this hop's key is checked under. */
  val knownHostsName: String
    get() = hostKeyAlias?.takeIf { it.isNotBlank() } ?: KnownHosts.name(host, port)
}

data class SshOptions(
  val connectTimeoutMs: Int = 15_000,
  // Matches the desktop's ServerAliveInterval=15 / ServerAliveCountMax=3.
  val keepAliveSeconds: Int = 15,
  val keepAliveMaxCount: Int = 3
)

data class ExecResult(val exitCode: Int?, val stdout: String, val stderr: String)

/** A host presented a key that known_hosts does not list under its name. */
data class HostKeyRejection(
  val hop: SshHop,
  val keyType: String,
  val keyBase64: String,
  val fingerprint: String,
  /** known_hosts already holds a different key under this name. */
  val changed: Boolean
) {
  val knownHostsLine: String get() = "${hop.knownHostsName} $keyType $keyBase64"
}

sealed interface SshConnectResult {
  data class Connected(val session: SshSession) : SshConnectResult

  data class Rejected(val rejection: HostKeyRejection) : SshConnectResult
}

/**
 * An authenticated connection to the last of a chain of hops. When any hop's transport dies,
 * the session stops accepting forwarded connections at once, so clients fail fast and
 * reconnect instead of hanging on a dead tunnel.
 */
class SshSession private constructor(private val clients: List<SSHClient>) : Closeable {
  private val listeners = CopyOnWriteArrayList<ServerSocket>()

  @Volatile private var closed = false

  private val target: SSHClient get() = clients.last()

  val isOpen: Boolean get() = !closed && clients.all { it.isConnected && it.isAuthenticated }

  /** Runs `command` on the target with `stdin` as its input, then waits for it to exit. */
  fun exec(command: String, stdin: String, timeoutMs: Long): ExecResult {
    target.startSession().use { session ->
      val cmd = session.exec(command)
      val stdout = Drain(cmd.inputStream)
      val stderr = Drain(cmd.errorStream)
      try {
        cmd.outputStream.use { it.write(stdin.toByteArray(Charsets.UTF_8)) }
      } catch (_: IOException) {
        // The command exited without reading all of its input; its status says why.
      }
      cmd.join(timeoutMs, TimeUnit.MILLISECONDS)
      return ExecResult(cmd.exitStatus, stdout.await(), stderr.await())
    }
  }

  /** Forwards a new loopback port on this device to `127.0.0.1:remotePort` on the target. */
  fun forward(remotePort: Int): Int {
    val server = ServerSocket(0, BACKLOG, InetAddress.getLoopbackAddress())
    listeners += server
    if (!isOpen) {
      closeQuietly(server)
      throw IOException("The SSH session is closed.")
    }
    val forwarder = target.newLocalPortForwarder(
      Parameters(LOOPBACK, server.localPort, LOOPBACK, remotePort),
      server,
    )
    thread(isDaemon = true, name = "t3-ssh-forward-${server.localPort}") {
      try {
        forwarder.listen()
      } catch (_: IOException) {
        // The listener was closed.
      } finally {
        closeQuietly(server)
        listeners -= server
      }
    }
    return server.localPort
  }

  override fun close() {
    stopListening()
    for (client in clients.asReversed()) {
      try {
        client.disconnect()
      } catch (_: IOException) {
        // Already gone.
      }
    }
  }

  // Runs on the dying transport's own thread, so it only flips state there.
  private fun onTransportDeath() {
    if (closed) return
    stopListening()
    thread(isDaemon = true, name = "t3-ssh-teardown") { close() }
  }

  private fun stopListening() {
    closed = true
    for (server in listeners) closeQuietly(server)
    listeners.clear()
  }

  companion object {
    private const val LOOPBACK = "127.0.0.1"
    private const val BACKLOG = 50

    fun connect(
      hops: List<SshHop>,
      key: KeyPair,
      knownHosts: List<KnownHost>,
      options: SshOptions = SshOptions()
    ): SshConnectResult {
      require(hops.isNotEmpty()) { "An SSH connection needs at least one host." }
      SshCrypto.ensureBouncyCastle()
      val clients = ArrayList<SSHClient>(hops.size)
      var handedOver = false
      try {
        for (hop in hops) {
          val verifier = PinnedHostKeyVerifier(hop.knownHostsName, knownHosts)
          val client = newClient(options, verifier)
          val rejection = connectHop(client, hop, clients.lastOrNull(), verifier)
          if (rejection != null) return SshConnectResult.Rejected(rejection)
          clients += client
          client.authPublickey(hop.user, KeyPairWrapper(key))
        }
        val session = SshSession(clients)
        for (client in clients) {
          client.transport.disconnectListener =
            DisconnectListener { _, _ -> session.onTransportDeath() }
        }
        handedOver = true
        return SshConnectResult.Connected(session)
      } finally {
        if (!handedOver) closeAll(clients)
      }
    }

    /** Opens the transport to `hop`, through `via` when there is one; null once verified. */
    private fun connectHop(
      client: SSHClient,
      hop: SshHop,
      via: SSHClient?,
      verifier: PinnedHostKeyVerifier
    ): HostKeyRejection? {
      try {
        if (via == null) {
          client.connect(hop.host, hop.port)
        } else {
          client.connectVia(via.newDirectConnection(hop.host, hop.port), hop.host, hop.port)
        }
        return null
      } catch (error: IOException) {
        closeQuietly(client)
        return verifier.rejection(hop) ?: throw error
      }
    }

    /** Drops SHA-1, MD5, CBC, 3DES/RC4/Blowfish and DSA, which no OpenSSH since 7.4 needs. */
    internal fun isAllowedAlgorithm(name: String): Boolean {
      val lower = name.lowercase()
      return lower !in WEAK_ALGORITHMS && WEAK_ALGORITHM_PARTS.none { it in lower }
    }

    private val WEAK_ALGORITHMS = setOf("ssh-rsa", "ssh-rsa-cert-v01@openssh.com")
    private val WEAK_ALGORITHM_PARTS =
      listOf("sha1", "md5", "ripemd", "-cbc", "3des", "arcfour", "blowfish", "dss")

    private fun newClient(options: SshOptions, verifier: HostKeyVerifier): SSHClient {
      // Strict key exchange (the Terrapin fix) is added by sshj's proposal, not these lists.
      val config = DefaultConfig().apply {
        keepAliveProvider = KeepAliveProvider.KEEP_ALIVE
        setKeyExchangeFactories(getKeyExchangeFactories().filter { isAllowedAlgorithm(it.name) })
        setCipherFactories(getCipherFactories().filter { isAllowedAlgorithm(it.name) })
        setMACFactories(getMACFactories().filter { isAllowedAlgorithm(it.name) })
        setKeyAlgorithms(getKeyAlgorithms().filter { isAllowedAlgorithm(it.name) })
      }
      return SSHClient(config).apply {
        addHostKeyVerifier(verifier)
        connectTimeout = options.connectTimeoutMs
        connection.keepAlive.keepAliveInterval = options.keepAliveSeconds
        (connection.keepAlive as? KeepAliveRunner)?.maxAliveCount = options.keepAliveMaxCount
      }
    }

    private fun closeAll(clients: List<SSHClient>) {
      for (client in clients.asReversed()) closeQuietly(client)
    }

    private fun closeQuietly(resource: Closeable) {
      try {
        resource.close()
      } catch (_: IOException) {
        // Nothing left to release.
      }
    }
  }
}

/** Accepts exactly the keys known_hosts lists under one name and remembers what it saw. */
private class PinnedHostKeyVerifier(
  private val name: String,
  knownHosts: List<KnownHost>
) : HostKeyVerifier {
  private val entries = knownHosts.filter { it.matches(name) }

  @Volatile private var presented: PublicKey? = null

  @Volatile private var accepted = false

  override fun verify(hostname: String, port: Int, key: PublicKey): Boolean {
    presented = key
    val type = KeyType.fromKey(key).toString()
    val encoded = Base64.getEncoder().encodeToString(blobOf(key))
    accepted = entries.any { it.keyType == type && it.keyBase64 == encoded }
    return accepted
  }

  // Lets sshj negotiate the key type already on file, as OpenSSH does.
  override fun findExistingAlgorithms(hostname: String, port: Int): List<String> =
    entries.flatMap { algorithmsFor(it.keyType) }.distinct()

  private fun algorithmsFor(keyType: String) =
    if (keyType == "ssh-rsa") listOf("rsa-sha2-512", "rsa-sha2-256") else listOf(keyType)

  fun rejection(hop: SshHop): HostKeyRejection? {
    val key = presented?.takeUnless { accepted } ?: return null
    val blob = blobOf(key)
    return HostKeyRejection(
      hop = hop,
      keyType = KeyType.fromKey(key).toString(),
      keyBase64 = Base64.getEncoder().encodeToString(blob),
      fingerprint = sshFingerprint(blob),
      changed = entries.isNotEmpty(),
    )
  }

  private fun blobOf(key: PublicKey): ByteArray = Buffer.PlainBuffer().putPublicKey(key).compactData
}

/** Reads a stream to its end on its own thread, keeping at most the first MiB. */
private class Drain(stream: InputStream) {
  private val bytes = ByteArrayOutputStream()

  private val worker = thread(isDaemon = true, name = "t3-ssh-exec-output") {
    val buffer = ByteArray(8192)
    try {
      stream.use {
        while (true) {
          val read = it.read(buffer)
          if (read < 0) break
          val room = MAX_OUTPUT_BYTES - bytes.size()
          if (room > 0) bytes.write(buffer, 0, minOf(read, room))
        }
      }
    } catch (_: IOException) {
      // The channel closed; keep what arrived.
    }
  }

  fun await(): String {
    worker.join(DRAIN_GRACE_MS)
    return bytes.toString(Charsets.UTF_8.name())
  }

  private companion object {
    const val MAX_OUTPUT_BYTES = 1 shl 20
    const val DRAIN_GRACE_MS = 5_000L
  }
}
