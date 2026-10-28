package expo.modules.t3ssh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class SshStoreTest {
  @get:Rule val tmp = TemporaryFolder()

  // Like AES-GCM, opening with a different key fails instead of yielding other bytes.
  private class XorSealer : SeedSealer {
    var mask: Byte = 0x5a

    override fun seal(plain: ByteArray) = byteArrayOf(mask) + xor(plain)

    override fun open(sealed: ByteArray): ByteArray {
      check(sealed[0] == mask) { "tag mismatch" }
      return xor(sealed.copyOfRange(1, sealed.size))
    }

    override fun forget() {
      mask = 0x11
    }

    private fun xor(bytes: ByteArray) = ByteArray(bytes.size) { (bytes[it].toInt() xor mask.toInt()).toByte() }
  }

  private val sealer = XorSealer()
  private val store by lazy { SshStore(tmp.newFolder("t3-ssh"), sealer) }

  @Test
  fun aCreatedKeyReopensWithTheSamePublicLine() {
    val line = store.createKey("t3 test")

    assertEquals(line, store.publicKeyLine())
    assertEquals(line, store.key()?.publicKeyLine("t3 test"))
  }

  @Test
  fun aKeyThisDeviceCanNoLongerOpenReadsAsMissing() {
    store.createKey("t3")
    sealer.mask = 0x22

    assertNull(store.key())
  }

  @Test
  fun deletingTheKeyForgetsItsSealingKeyToo() {
    store.createKey("t3")

    store.deleteKey()

    assertNull(store.key())
    assertNull(store.publicKeyLine())
    assertEquals(0x11.toByte(), sealer.mask)
  }

  @Test
  fun trustingIsIdempotentAndRefusesASecondKeyForAName() {
    val first = "[127.0.0.1]:2222 ssh-ed25519 ${keyBase64()}"
    store.trust(first)
    store.trust(first)
    assertEquals(listOf(first), store.knownHosts().map { it.line })

    assertThrows(IllegalStateException::class.java) {
      store.trust("[127.0.0.1]:2222 ssh-ed25519 ${keyBase64()}")
    }

    store.forget(first)
    assertEquals(emptyList<KnownHost>(), store.knownHosts())
  }

  @Test
  fun theConfigTextRoundTrips() {
    assertEquals("", store.readConfig())
    store.writeConfig("Host box\n  HostName 127.0.0.1\n")

    assertEquals("Host box\n  HostName 127.0.0.1\n", store.readConfig())
  }

  private fun keyBase64() = Ed25519Key.generate().publicKeyLine("").split(" ")[1]
}
