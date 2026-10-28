package expo.modules.t3ssh

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * sshj needs the full BouncyCastle provider. Android ships a cut-down one under
 * the same name, so it is replaced; appending it leaves TLS and every other
 * provider the platform prefers in place.
 */
object SshCrypto {
  @Synchronized
  fun ensureBouncyCastle() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) is BouncyCastleProvider) return
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
    Security.addProvider(BouncyCastleProvider())
  }
}

/** An ed25519 key kept as its 32-byte seed; the public key and signer derive from it. */
class Ed25519Key(seed: ByteArray) {
  private val seed = seed.copyOf()

  init {
    require(seed.size == SEED_BYTES) { "An ed25519 seed is $SEED_BYTES bytes." }
  }

  val publicKey: ByteArray = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded

  /** The SSH wire encoding of the public key, as in `authorized_keys`. */
  val publicKeyBlob: ByteArray = sshStrings(KEY_TYPE.toByteArray(), publicKey)

  fun seedCopy(): ByteArray = seed.copyOf()

  fun publicKeyLine(comment: String): String {
    val base = "$KEY_TYPE ${Base64.getEncoder().encodeToString(publicKeyBlob)}"
    val trimmed = comment.trim()
    return if (trimmed.isEmpty()) base else "$base $trimmed"
  }

  fun fingerprint(): String = sshFingerprint(publicKeyBlob)

  /** A JCA key pair from BouncyCastle, which sshj signs with. */
  fun toKeyPair(): KeyPair {
    SshCrypto.ensureBouncyCastle()
    val factory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME)
    return KeyPair(
      factory.generatePublic(X509EncodedKeySpec(X509_PREFIX + publicKey)),
      factory.generatePrivate(PKCS8EncodedKeySpec(PKCS8_PREFIX + seed)),
    )
  }

  companion object {
    const val KEY_TYPE = "ssh-ed25519"
    const val SEED_BYTES = 32

    fun generate(random: SecureRandom = SecureRandom()): Ed25519Key {
      val seed = ByteArray(SEED_BYTES)
      random.nextBytes(seed)
      return Ed25519Key(seed)
    }

    // RFC 8410 DER headers for a bare ed25519 private seed and public key.
    private val PKCS8_PREFIX = hex("302e020100300506032b657004220420")
    private val X509_PREFIX = hex("302a300506032b6570032100")
  }
}

/** OpenSSH's `SHA256:` fingerprint of a public key blob. */
fun sshFingerprint(blob: ByteArray): String =
  "SHA256:" +
    Base64.getEncoder().withoutPadding().encodeToString(
      MessageDigest.getInstance("SHA-256").digest(blob)
    )

private fun sshStrings(vararg values: ByteArray): ByteArray {
  val bytes = ByteArrayOutputStream()
  DataOutputStream(bytes).use { out ->
    for (value in values) {
      out.writeInt(value.size)
      out.write(value)
    }
  }
  return bytes.toByteArray()
}

private fun hex(value: String): ByteArray = ByteArray(value.length / 2) { i ->
  value.substring(i * 2, i * 2 + 2).toInt(16).toByte()
}
