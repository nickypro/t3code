package expo.modules.t3clientcertificates

import android.content.Context
import android.security.KeyChain
import com.facebook.react.modules.network.*
import com.facebook.react.modules.websocket.WebSocketModule
import java.io.IOException
import java.net.Socket
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import javax.net.ssl.*
import okhttp3.*

/** Process-wide transport, installed before React Native, Expo fetch, or Fresco creates a client. */
class T3CertificateTransport private constructor(private val context: Context) {
  internal val lock = Any()
  internal val preferences = context.getSharedPreferences("t3-client-certificates", Context.MODE_PRIVATE)
  internal val calls = ConcurrentHashMap<String, Call>()
  internal val sockets = ConcurrentHashMap<Socket, String>()
  // Accessed only under lock. Tokens distinguish remove/re-add and same-alias replacement.
  private val generations = CertificateGenerations()
  internal fun generation(origin: String): Any = generations.generation(origin)
  internal fun invalidate(origin: String) { generations.invalidate(origin) }
  internal fun invalidateAll() { generations.invalidateAll() }
  private val trust: X509TrustManager
  private val socketFactory: SSLSocketFactory
  internal val fileClient: OkHttpClient

  init {
    val tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    tm.init(null as KeyStore?)
    trust = tm.trustManagers.filterIsInstance<X509TrustManager>().single()
    val defaultTls = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }
    socketFactory = OriginSocketFactory(defaultTls.socketFactory, { origin ->
      val alias = preferences.getString(origin, null)
      if (alias == null) defaultTls.socketFactory else {
        try {
          val key = KeyChain.getPrivateKey(context, alias)
            ?: throw IOException("Client certificate is unavailable. Select it again in Connections.")
          val chain = KeyChain.getCertificateChain(context, alias)
            ?: throw IOException("Client certificate chain is unavailable. Select it again in Connections.")
          chain.forEach { it.checkValidity() }
          // Resolve the KeyChain grant on each new connection. No exported keys or TLS session
          // resumption across a removed/replaced identity.
          SSLContext.getInstance("TLS").apply {
            init(arrayOf(SelectedIdentity(alias, key, chain)), arrayOf(trust), null)
          }.socketFactory
        } catch (error: Exception) {
          throw IOException("Client certificate '$alias' could not be used: ${error.message}", error)
        }
      }
    }, { origin, socket ->
      sockets.entries.removeIf { it.key.isClosed }
      sockets[socket] = origin
    }, lock, ::generation)
    OkHttpClientProvider.setOkHttpClientFactory(OkHttpClientFactory {
      // Networking and Fresco must not open separate caches over the same directory.
      configure(OkHttpClientProvider.createClientBuilder()).build()
    })
    val customize = CustomClientBuilder { builder -> configure(builder) }
    NetworkingModule.setCustomClientBuilder(customize)
    WebSocketModule.setCustomClientBuilder(customize)
    fileClient = configure(OkHttpClient.Builder())
      .connectTimeout(30, TimeUnit.SECONDS).readTimeout(60, TimeUnit.SECONDS)
      .followRedirects(false).followSslRedirects(false).build()
  }

  private fun configure(builder: OkHttpClient.Builder): OkHttpClient.Builder = builder
    .sslSocketFactory(socketFactory, trust)
    .hostnameVerifier(originHostnameVerifier)

  companion object {
    @Volatile private var instance: T3CertificateTransport? = null

    @JvmStatic @Synchronized
    fun install(context: Context): T3CertificateTransport = instance
      ?: T3CertificateTransport(context.applicationContext).also { instance = it }
  }
}
