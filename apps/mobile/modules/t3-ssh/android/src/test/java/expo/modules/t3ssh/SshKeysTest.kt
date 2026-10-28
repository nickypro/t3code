package expo.modules.t3ssh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.Signature

class SshKeysTest {
  @get:Rule val tmp = TemporaryFolder()

  @Test
  fun thePublicLineIsOneSshKeygenReadsWithTheSameFingerprint() {
    assumeTrue(TestSshd.available)
    val key = Ed25519Key.generate()
    val file = File(tmp.root, "id.pub").apply { writeText(key.publicKeyLine("t3 phone") + "\n") }

    val listed = run("ssh-keygen", "-l", "-E", "sha256", "-f", file.path).trim().split(" ")

    assertEquals("256", listed[0])
    assertEquals(key.fingerprint(), listed[1])
    assertEquals("t3", listed[2])
    assertEquals("(ED25519)", listed.last())
  }

  @Test
  fun aSeedAlwaysGivesTheSameKeyAndItsKeyPairSigns() {
    val key = Ed25519Key.generate()
    val again = Ed25519Key(key.seedCopy())
    assertArrayEquals(key.publicKey, again.publicKey)

    val pair = again.toKeyPair()
    val message = "challenge".toByteArray()
    val signature = Signature.getInstance("Ed25519", "BC").run {
      initSign(pair.private)
      update(message)
      sign()
    }
    val verifies = Signature.getInstance("Ed25519", "BC").run {
      initVerify(key.toKeyPair().public)
      update(message)
      verify(signature)
    }
    assertTrue(verifies)
  }

  @Test
  fun aBlankCommentLeavesItOff() {
    assertEquals(2, Ed25519Key.generate().publicKeyLine("  ").split(" ").size)
  }

  @Test
  fun aSeedMustBe32Bytes() {
    assertThrows(IllegalArgumentException::class.java) { Ed25519Key(ByteArray(31)) }
  }
}
