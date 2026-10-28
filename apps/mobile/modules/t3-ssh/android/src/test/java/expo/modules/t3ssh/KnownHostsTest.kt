package expo.modules.t3ssh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class KnownHostsTest {
  private val key = Ed25519Key.generate().publicKeyLine("").split(" ")[1]

  @Test
  fun port22IsFiledUnderTheBareHostAndOtherPortsInBrackets() {
    assertEquals("example.com", KnownHosts.name("example.com", 22))
    assertEquals("[127.0.0.1]:2222", KnownHosts.name("127.0.0.1", 2222))
  }

  @Test
  fun parsesPlainEntriesWithSeveralNamesAndAComment() {
    val entries = KnownHosts.parse(
      """
      # comment

      example.com,[10.0.0.1]:2222 ssh-ed25519 $key laptop
      """.trimIndent(),
    )

    assertEquals(
      listOf(KnownHost(listOf("example.com", "[10.0.0.1]:2222"), "ssh-ed25519", key)),
      entries
    )
    assertEquals(true, entries.single().matches("[10.0.0.1]:2222"))
  }

  @Test
  fun entriesThatCouldTrustTheWrongHostAreSkipped() {
    for (line in listOf(
      "|1|c2FsdA==|aGFzaA== ssh-ed25519 $key",
      "@cert-authority *.example.com ssh-ed25519 $key",
      "@revoked example.com ssh-ed25519 $key",
      "*.example.com ssh-ed25519 $key",
      "host?.example.com ssh-ed25519 $key",
      "example.com ssh-ed25519 not*base64",
      "example.com ssh-ed25519",
    )) {
      assertNull(line, KnownHosts.parseLine(line))
    }
  }
}
