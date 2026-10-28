package expo.modules.t3ssh

import java.io.Closeable
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * IPv4 loopback, spelled out: with IPv6 preferred (as on Android) getLoopbackAddress() is ::1,
 * and the servers and the app's URLs use 127.0.0.1.
 */
val LOCALHOST: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

/** A throwaway OpenSSH server on loopback, configured and owned by one test. */
class TestSshd(
  private val dir: File,
  authorizedKeys: String,
  extraConfig: String = ""
) : Closeable {
  val port: Int = freeLoopbackPort()
  val hostKeyPublicFile = File(dir, "host_ed25519.pub")
  val hostKeyType: String
  val hostKeyBase64: String
  private val process: Process

  init {
    val hostKey = File(dir, "host_ed25519")
    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostKey.path)
    hostKeyPublicFile.readText().trim().split(" ").let {
      hostKeyType = it[0]
      hostKeyBase64 = it[1]
    }
    File(dir, "authorized_keys").writeText(authorizedKeys.trimEnd() + "\n")
    val config = File(dir, "sshd_config")
    config.writeText(
      """
      Port $port
      ListenAddress 127.0.0.1
      HostKey ${hostKey.path}
      PidFile none
      UsePAM no
      StrictModes no
      PubkeyAuthentication yes
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      PermitRootLogin prohibit-password
      AuthorizedKeysFile ${File(dir, "authorized_keys").path}
      AllowTcpForwarding yes
      LogLevel VERBOSE
      $extraConfig
      """.trimIndent() + "\n",
    )
    process = ProcessBuilder(SSHD, "-D", "-e", "-f", config.path)
      .redirectErrorStream(true)
      .redirectOutput(File(dir, "sshd.log"))
      .start()
    awaitListening(port) { check(process.isAlive) { "sshd exited:\n${log()}" } }
  }

  /** This server's entry, filed under `[127.0.0.1]:port` unless given another name. */
  fun knownHost(
    name: String = KnownHosts.name("127.0.0.1", port)
  ) = KnownHost(listOf(name), hostKeyType, hostKeyBase64)

  fun log(): String = File(dir, "sshd.log").takeIf { it.exists() }?.readText().orEmpty()

  // Tests close their sessions first, which ends the per-connection sshd children.
  override fun close() {
    process.destroyForcibly()
    process.waitFor(5, TimeUnit.SECONDS)
  }

  companion object {
    private const val SSHD = "/usr/sbin/sshd"
    val user: String = System.getProperty("user.name") ?: error("no user.name")

    val available: Boolean
      get() = File(SSHD).canExecute() &&
        runCatching { run("ssh-keygen", "-?", check = false) }.isSuccess
  }
}

/**
 * Relays loopback TCP to a port. [blackhole] keeps every connection open but stops moving
 * bytes, which is what a dropped mobile network looks like to both ends.
 */
class TcpRelay(private val targetPort: Int) : Closeable {
  private val server = ServerSocket(0, 50, LOCALHOST)
  private val sockets = CopyOnWriteArrayList<Socket>()

  @Volatile private var flowing = true

  val port: Int get() = server.localPort

  init {
    thread(isDaemon = true, name = "test-relay-accept") {
      while (!server.isClosed) {
        val client = try {
          server.accept()
        } catch (_: IOException) {
          break
        }
        val upstream = Socket(LOCALHOST, targetPort)
        sockets += client
        sockets += upstream
        pump(client, upstream)
        pump(upstream, client)
      }
    }
  }

  fun blackhole() {
    flowing = false
  }

  override fun close() {
    server.close()
    for (socket in sockets) runCatching { socket.close() }
  }

  private fun pump(from: Socket, to: Socket) = thread(isDaemon = true, name = "test-relay-pump") {
    val buffer = ByteArray(8192)
    try {
      while (true) {
        val read = from.getInputStream().read(buffer)
        if (read < 0) break
        if (flowing) to.getOutputStream().write(buffer, 0, read)
      }
    } catch (_: IOException) {
      // Either side closed.
    } finally {
      runCatching { to.close() }
    }
  }
}

/** Answers every HTTP request on loopback with one fixed body, then closes the connection. */
class TestHttpService(body: String) : Closeable {
  private val server = ServerSocket(0, 50, LOCALHOST)
  private val response = body.toByteArray().let { bytes ->
    "HTTP/1.1 200 OK\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n".toByteArray() +
      bytes
  }

  val port: Int get() = server.localPort

  init {
    thread(isDaemon = true, name = "test-http-accept") {
      while (!server.isClosed) {
        val socket = try {
          server.accept()
        } catch (_: IOException) {
          break
        }
        thread(isDaemon = true, name = "test-http-request") {
          socket.use {
            val reader = it.getInputStream().bufferedReader()
            while (reader.readLine()?.isNotEmpty() == true) {
              // Skip the request line and headers.
            }
            it.getOutputStream().write(response)
          }
        }
      }
    }
  }

  override fun close() = server.close()
}

fun freeLoopbackPort(): Int = ServerSocket(0, 1, LOCALHOST).use {
  it.localPort
}

fun run(vararg command: String, check: Boolean = true): String {
  val process = ProcessBuilder(*command).redirectErrorStream(true).start()
  val output = process.inputStream.bufferedReader().readText()
  check(process.waitFor(30, TimeUnit.SECONDS)) { "${command.first()} timed out" }
  if (check) check(process.exitValue() == 0) { "${command.joinToString(" ")} failed:\n$output" }
  return output
}

/** Waits until something accepts connections on loopback `port`, with a hard ceiling. */
fun awaitListening(port: Int, ceilingMs: Long = 10_000, stillStarting: () -> Unit = {}) {
  val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(ceilingMs)
  while (true) {
    stillStarting()
    try {
      Socket().use { it.connect(InetSocketAddress(LOCALHOST, port), 200) }
      return
    } catch (_: IOException) {
      check(System.nanoTime() < deadline) { "Nothing listened on $port within ${ceilingMs}ms." }
      Thread.sleep(50)
    }
  }
}

/** Evaluates `condition` until it holds, failing after a hard ceiling. */
fun eventually(ceilingMs: Long = 15_000, condition: () -> Boolean) {
  val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(ceilingMs)
  while (!condition()) {
    check(System.nanoTime() < deadline) { "Condition did not hold within ${ceilingMs}ms." }
    Thread.sleep(50)
  }
}
