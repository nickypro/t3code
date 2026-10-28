package expo.modules.t3ssh

import net.schmizz.sshj.userauth.UserAuthException
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.Closeable
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.Callable
import java.util.concurrent.Executors

/** Runs against real OpenSSH servers this test starts on loopback. */
class SshSessionTest {
  @get:Rule val tmp = TemporaryFolder()

  private val key = Ed25519Key.generate()
  private val cleanup = mutableListOf<Closeable>()

  @Before
  fun requireOpenSsh() = assumeTrue("needs OpenSSH's sshd and ssh-keygen", TestSshd.available)

  @After
  fun tearDown() {
    for (resource in cleanup.asReversed()) runCatching { resource.close() }
  }

  @Test
  fun execPassesStdinAndReportsOutputAndExitCode() {
    val server = sshd()
    val session = connected(listOf(hop(server)), listOf(server.knownHost()))

    val result = session.exec(
      "sh -s -- first",
      "echo \"out \$1\"; echo err >&2; cat; exit 3\nrest of stdin\n",
      10_000
    )

    assertEquals(3, result.exitCode)
    assertEquals("out first\n", result.stdout)
    assertEquals("err\n", result.stderr)
  }

  @Test
  fun anUnknownHostKeyIsRejectedWithTheFingerprintSshKeygenShows() {
    val server = sshd()

    val rejection = rejected(listOf(hop(server)), emptyList())

    val keygen = run(
      "ssh-keygen",
      "-l",
      "-E",
      "sha256",
      "-f",
      server.hostKeyPublicFile.path
    ).split(" ")[1]
    assertEquals(keygen, rejection.fingerprint)
    assertFalse(rejection.changed)
    assertEquals(
      "[127.0.0.1]:${server.port} ${server.hostKeyType} ${server.hostKeyBase64}",
      rejection.knownHostsLine
    )
  }

  @Test
  fun aDifferentKeyOnFileIsReportedAsChanged() {
    val server = sshd()
    val other = Ed25519Key.generate().publicKeyLine("").split(" ")
    val stale = KnownHost(listOf(KnownHosts.name("127.0.0.1", server.port)), other[0], other[1])

    val rejection = rejected(listOf(hop(server)), listOf(stale))

    assertTrue(rejection.changed)
  }

  @Test
  fun aHostKeyAliasNamesTheEntryThatIsChecked() {
    val server = sshd()
    val filedUnderAlias = server.knownHost("box")

    connected(listOf(hop(server, alias = "box")), listOf(filedUnderAlias))
    assertFalse(rejected(listOf(hop(server)), listOf(filedUnderAlias)).changed)
  }

  @Test
  fun connectsThroughAJumpHostWhoseKeyCanOnlyReachTheTarget() {
    val target = sshd()
    val jump = sshd(authorized = tunnelOnly(target.port))
    val known = listOf(jump.knownHost(), target.knownHost())

    val session = connected(listOf(hop(jump), hop(target)), known)
    assertEquals("via jump\n", session.exec("echo via jump", "", 10_000).stdout)

    // The same key gets no shell on the jump host and no other destination.
    val onJump = connected(listOf(hop(jump)), known)
    assertNotEquals(0, onJump.exec("echo shell", "", 10_000).exitCode)
    val elsewhere = freeLoopbackPort()
    assertThrows(IOException::class.java) {
      SshSession.connect(
        listOf(hop(jump), SshHop("127.0.0.1", elsewhere, TestSshd.user)),
        key.toKeyPair(),
        known
      )
    }
  }

  @Test
  fun aForwardReachesALoopbackServiceOnTheTarget() {
    val server = sshd()
    val service = httpService("hello from the target")
    val session = connected(listOf(hop(server)), listOf(server.knownHost()))

    val localPort = session.forward(service)

    val pool = Executors.newFixedThreadPool(4)
    try {
      val bodies = pool.invokeAll(List(8) { Callable { get(localPort) } }).map { it.get() }
      assertEquals(List(8) { "hello from the target" }, bodies)
    } finally {
      pool.shutdownNow()
    }
  }

  @Test
  fun aDeadNetworkClosesTheForwardedPortInsteadOfLeavingItHanging() {
    val server = sshd()
    val relay = TcpRelay(server.port).also(cleanup::add)
    val service = httpService("alive")
    val hop = SshHop("127.0.0.1", relay.port, TestSshd.user, hostKeyAlias = "relayed")
    val options = SshOptions(keepAliveSeconds = 1, keepAliveMaxCount = 2)
    val session = connected(listOf(hop), listOf(server.knownHost("relayed")), options)
    val localPort = session.forward(service)
    assertEquals("alive", get(localPort))

    relay.blackhole()

    eventually { !session.isOpen }
    eventually { refusesConnections(localPort) }
  }

  @Test
  fun aKeyTheServerDoesNotListFailsAuthentication() {
    val server = sshd(authorized = Ed25519Key.generate().publicKeyLine("someone else"))

    assertThrows(UserAuthException::class.java) {
      SshSession.connect(listOf(hop(server)), key.toKeyPair(), listOf(server.knownHost()))
    }
  }

  @Test
  fun closingTheSessionClosesItsForwards() {
    val server = sshd()
    val session = connected(listOf(hop(server)), listOf(server.knownHost()))
    val localPort = session.forward(httpService("x"))

    session.close()

    assertFalse(session.isOpen)
    eventually { refusesConnections(localPort) }
  }

  @Test
  fun weakAlgorithmsAreNotOffered() {
    for (weak in listOf(
      "hmac-sha1",
      "diffie-hellman-group14-sha1",
      "aes128-cbc",
      "ssh-rsa",
      "ssh-dss",
      "3des-cbc"
    )) {
      assertFalse(weak, SshSession.isAllowedAlgorithm(weak))
    }
    for (modern in listOf(
      "curve25519-sha256",
      "chacha20-poly1305@openssh.com",
      "aes256-gcm@openssh.com",
      "hmac-sha2-256-etm@openssh.com",
      "ssh-ed25519",
      "rsa-sha2-512",
      "ecdh-sha2-nistp256"
    )) {
      assertTrue(modern, SshSession.isAllowedAlgorithm(modern))
    }
  }

  private fun sshd(authorized: String = key.publicKeyLine("test"), extra: String = "") =
    TestSshd(tmp.newFolder(), authorized, extra).also(cleanup::add)

  private fun tunnelOnly(targetPort: Int): String {
    val options = "restrict,port-forwarding," +
      "permitopen=\"127.0.0.1:$targetPort\",command=\"/bin/false\""
    return "$options ${key.publicKeyLine("jump")}"
  }

  private fun hop(server: TestSshd, alias: String? = null) = SshHop(
    "127.0.0.1",
    server.port,
    TestSshd.user,
    alias
  )

  private fun connected(
    hops: List<SshHop>,
    known: List<KnownHost>,
    options: SshOptions = SshOptions()
  ): SshSession {
    val result = SshSession.connect(hops, key.toKeyPair(), known, options)
    check(result is SshConnectResult.Connected) { "expected a connection, got $result" }
    cleanup += result.session
    return result.session
  }

  private fun rejected(hops: List<SshHop>, known: List<KnownHost>): HostKeyRejection {
    val result = SshSession.connect(hops, key.toKeyPair(), known)
    if (result is SshConnectResult.Connected) cleanup += result.session
    check(result is SshConnectResult.Rejected) { "expected a host key rejection, got $result" }
    return result.rejection
  }

  private fun httpService(body: String): Int = TestHttpService(body).also(cleanup::add).port

  private fun get(port: Int): String {
    val connection = URL("http://127.0.0.1:$port/").openConnection() as HttpURLConnection
    connection.connectTimeout = 5_000
    connection.readTimeout = 5_000
    return connection.inputStream.use { it.readBytes().decodeToString() }
  }

  private fun refusesConnections(port: Int): Boolean = try {
    Socket(LOCALHOST, port).use { false }
  } catch (_: IOException) {
    true
  }
}
