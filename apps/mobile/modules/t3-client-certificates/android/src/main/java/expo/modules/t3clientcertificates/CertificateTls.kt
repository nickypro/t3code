package expo.modules.t3clientcertificates

import java.net.InetAddress
import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.net.ssl.*
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/** HTTPS and WSS share an identity; paths, credentials and fragments never enter the key. */
internal fun certificateOrigin(url: String): String? {
  val normalized = if (url.startsWith("wss://", true)) "https://" + url.substring(6) else url
  val parsed = normalized.toHttpUrlOrNull() ?: return null
  if (parsed.scheme != "https" || parsed.username.isNotEmpty() || parsed.password.isNotEmpty()) return null
  return parsed.newBuilder().encodedPath("/").query(null).fragment(null).build().toString()
}

internal class SelectedIdentity(
  private val alias: String,
  private val key: PrivateKey,
  private val chain: Array<X509Certificate>,
) : X509ExtendedKeyManager() {
  private fun accepts(types: Array<out String>?, issuers: Array<out Principal>?): Boolean =
    types?.any { it.substringBefore('_').equals(key.algorithm, true) } == true &&
      (issuers.isNullOrEmpty() || chain.any { cert -> issuers.any { it == cert.issuerX500Principal } })
  override fun chooseClientAlias(types: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?) =
    if (accepts(types, issuers)) alias else null
  override fun chooseEngineClientAlias(types: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?) =
    if (accepts(types, issuers)) alias else null
  override fun getClientAliases(type: String?, issuers: Array<out Principal>?) =
    if (type != null && accepts(arrayOf(type), issuers)) arrayOf(alias) else null
  override fun getPrivateKey(requestedAlias: String?) = if (requestedAlias == alias) key else null
  override fun getCertificateChain(requestedAlias: String?) = if (requestedAlias == alias) chain.clone() else null
  override fun chooseServerAlias(type: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null
  override fun getServerAliases(type: String?, issuers: Array<out Principal>?): Array<String>? = null
}

/** Identity changes invalidate queued work even when the selected alias stays the same.
 * Callers hold the transport lock while capturing, checking, or invalidating tokens.
 */
internal class CertificateGenerations {
  private val tokens = mutableMapOf<String, Any>()
  fun generation(origin: String): Any = tokens.getOrPut(origin) { Any() }
  fun invalidate(origin: String) { tokens.remove(origin) }
  fun invalidateAll() { tokens.clear() }
}

/** Select using OkHttp's original hostname, never reverse DNS or the resolved IP address. */
internal class OriginSocketFactory(
  private val fallback: SSLSocketFactory,
  private val factory: (String) -> SSLSocketFactory,
  private val opened: (String, Socket) -> Unit,
  private val lock: Any = Any(),
) : SSLSocketFactory() {
  override fun getDefaultCipherSuites(): Array<String> = fallback.defaultCipherSuites
  override fun getSupportedCipherSuites(): Array<String> = fallback.supportedCipherSuites
  override fun createSocket(socket: Socket, host: String, port: Int, autoClose: Boolean): Socket = synchronized(lock) {
    val authority = if (host.contains(':')) "[$host]" else host
    val origin = requireNotNull(certificateOrigin("https://$authority:$port"))
    factory(origin).createSocket(socket, host, port, autoClose).also { opened(origin, it) }
  }
  // OkHttp uses the layered overload. Refuse ambiguous forms instead of guessing a destination.
  override fun createSocket(host: String, port: Int): Socket = throw UnsupportedOperationException("Layered TLS required")
  override fun createSocket(host: String, port: Int, local: InetAddress, localPort: Int): Socket = throw UnsupportedOperationException("Layered TLS required")
  override fun createSocket(host: InetAddress, port: Int): Socket = throw UnsupportedOperationException("Hostname required")
  override fun createSocket(host: InetAddress, port: Int, local: InetAddress, localPort: Int): Socket = throw UnsupportedOperationException("Hostname required")
}
