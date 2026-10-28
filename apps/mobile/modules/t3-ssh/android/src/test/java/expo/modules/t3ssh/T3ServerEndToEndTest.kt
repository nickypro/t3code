package expo.modules.t3ssh

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.Closeable
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * The desktop's own launch and pairing scripts, run through a tunnel-only jump host, start a
 * real t3 server in a throwaway HOME, and the forwarded port pairs and authenticates.
 *
 * Opt-in, because it downloads a t3 release: write the scripts with
 * `node apps/mobile/modules/t3-ssh/e2e/write-remote-scripts.ts <dir> <t3 version>` (from
 * apps/mobile), then run the unit tests with T3_SSH_E2E_SCRIPTS=<dir> and
 * T3_SSH_E2E_HOME=<empty directory>.
 */
class T3ServerEndToEndTest {
  @get:Rule val tmp = TemporaryFolder()

  private val key = Ed25519Key.generate()
  private val cleanup = mutableListOf<Closeable>()

  @After
  fun tearDown() {
    for (resource in cleanup.asReversed()) runCatching { resource.close() }
  }

  @Test
  fun theDesktopScriptsStartAPairableServerThroughAJumpHost() {
    val scripts = System.getenv("T3_SSH_E2E_SCRIPTS")?.let(::File)
    val home = System.getenv("T3_SSH_E2E_HOME")
    assumeTrue("set T3_SSH_E2E_SCRIPTS and T3_SSH_E2E_HOME", scripts != null && home != null && TestSshd.available)
    scripts!!
    val stateKey = File(scripts, "state-key").readText().trim()

    val target = sshd("environment=\"HOME=$home\" ${key.publicKeyLine("e2e")}", "PermitUserEnvironment yes")
    val jump = sshd(
      "restrict,port-forwarding,permitopen=\"127.0.0.1:${target.port}\",command=\"/bin/false\" " +
        key.publicKeyLine("e2e jump"),
    )
    val result = SshSession.connect(
      listOf(SshHop("127.0.0.1", jump.port, TestSshd.user), SshHop("127.0.0.1", target.port, TestSshd.user)),
      key.toKeyPair(),
      listOf(jump.knownHost(), target.knownHost()),
    )
    val session = (result as SshConnectResult.Connected).session.also(cleanup::add)

    val launch = session.exec("sh -l -s -- $stateKey", File(scripts, "launch.sh").readText(), LAUNCH_TIMEOUT_MS)
    assertEquals(launch.stderr, 0, launch.exitCode)
    val remotePort = field(launch.stdout, "remotePort").toInt()
    try {
      val localPort = session.forward(remotePort)

      val descriptor = http(localPort, "/.well-known/t3/environment")
      assertTrue(descriptor, descriptor.contains("\"environmentId\""))

      val pairing = session.exec("sh -s", File(scripts, "pairing.sh").readText(), LAUNCH_TIMEOUT_MS)
      assertEquals(pairing.stderr, 0, pairing.exitCode)
      val token = http(
        localPort,
        "/oauth/token",
        form = mapOf(
          "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange",
          "subject_token" to field(pairing.stdout, "credential"),
          "subject_token_type" to "urn:t3:params:oauth:token-type:environment-bootstrap",
          "requested_token_type" to "urn:ietf:params:oauth:token-type:access_token",
        ),
      )
      val sessionState = http(localPort, "/api/auth/session", bearer = field(token, "access_token"))
      assertTrue(sessionState, sessionState.contains("\"authenticated\":true"))

      // A second launch finds the running server instead of starting another.
      val again = session.exec("sh -l -s -- $stateKey", File(scripts, "launch.sh").readText(), LAUNCH_TIMEOUT_MS)
      assertEquals(remotePort, field(again.stdout, "remotePort").toInt())
    } finally {
      session.exec("sh -s", File(scripts, "stop.sh").readText(), 60_000)
    }
  }

  private fun sshd(authorized: String, extra: String = "") =
    TestSshd(tmp.newFolder(), authorized, extra).also(cleanup::add)

  private fun field(json: String, name: String): String =
    Regex("\"$name\"\\s*:\\s*\"?([^\",}]+)").find(json)?.groupValues?.get(1)
      ?: throw AssertionError("no $name in: $json")

  private fun http(port: Int, path: String, form: Map<String, String>? = null, bearer: String? = null): String {
    val connection = URL("http://127.0.0.1:$port$path").openConnection() as HttpURLConnection
    connection.connectTimeout = 10_000
    connection.readTimeout = 30_000
    bearer?.let { connection.setRequestProperty("Authorization", "Bearer $it") }
    if (form != null) {
      connection.requestMethod = "POST"
      connection.doOutput = true
      connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
      val body = form.entries.joinToString("&") { (k, v) -> "$k=${URLEncoder.encode(v, "UTF-8")}" }
      connection.outputStream.use { it.write(body.toByteArray()) }
    }
    val stream = if (connection.responseCode < 400) connection.inputStream else connection.errorStream
    val text = stream.use { it.readBytes().decodeToString() }
    check(connection.responseCode < 400) { "$path answered ${connection.responseCode}: $text" }
    return text
  }

  private companion object {
    // The desktop's budget for a cold archive launch (download, unpack, start).
    const val LAUNCH_TIMEOUT_MS = 900_000L
  }
}
