package expo.modules.t3clientcertificates

import android.content.Context
import android.content.BroadcastReceiver
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import android.net.Uri
import android.security.KeyChain
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.io.File
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import okhttp3.*
import okio.buffer
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.asRequestBody

class T3ClientCertificatesModule : Module() {
  private val io = Executors.newCachedThreadPool()
  private lateinit var transport: T3CertificateTransport
  private val calls get() = transport.calls
  private val cancelled = ConcurrentHashMap.newKeySet<String>()
  private val sockets get() = transport.sockets
  private val lock get() = transport.lock
  private lateinit var context: Context
  private val preferences get() = transport.preferences
  private val fileClient get() = transport.fileClient
  @Volatile private var choosing = false
  private val keyChainChanges = object : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
      synchronized(lock) {
        transport.invalidateAll()
        sockets.keys.forEach { runCatching { it.close() } }
        sockets.clear()
        calls.values.forEach { it.cancel() }
        fileClient.connectionPool.evictAll()
      }
      sendEvent("changed", mapOf("origin" to ""))
    }
  }

  override fun definition() = ModuleDefinition {
    Name("T3ClientCertificates")
    Events("transferProgress", "changed")
    OnCreate {
      context = requireNotNull(appContext.reactContext).applicationContext
      transport = T3CertificateTransport.install(context)
      context.cacheDir.listFiles()?.filter { it.name.startsWith("t3-mtls-media-") }?.forEach { it.delete() }
      val changes = IntentFilter().apply {
        addAction(KeyChain.ACTION_KEYCHAIN_CHANGED)
        addAction(KeyChain.ACTION_KEY_ACCESS_CHANGED)
        addAction(KeyChain.ACTION_TRUST_STORE_CHANGED)
        if (android.os.Build.VERSION.SDK_INT < 26) addAction(KeyChain.ACTION_STORAGE_CHANGED)
      }
      ContextCompat.registerReceiver(context, keyChainChanges, changes, ContextCompat.RECEIVER_EXPORTED)
    }
    Function("getAlias") { url: String -> certificateOrigin(url)?.let { preferences.getString(it, null) } }
    AsyncFunction("choose") { url: String, promise: Promise ->
      val origin = certificateOrigin(url)
      val activity = appContext.currentActivity
      if (origin == null || activity == null) {
        promise.reject("CERTIFICATE_PICKER", "Enter an HTTPS host and open this screen in the foreground.", null)
      } else if (choosing) {
        promise.reject("CERTIFICATE_PICKER", "A certificate picker is already open.", null)
      } else {
        choosing = true
        activity.runOnUiThread {
          try {
            val uri = Uri.parse(origin)
            KeyChain.choosePrivateKeyAlias(activity, { alias ->
              io.execute {
                try {
                  if (alias != null) {
                    requireNotNull(KeyChain.getPrivateKey(context, alias)) { "Private key unavailable" }
                    val chain = requireNotNull(KeyChain.getCertificateChain(context, alias)) { "Certificate unavailable" }
                    chain.forEach { it.checkValidity() }
                    synchronized(lock) {
                      check(preferences.edit().putString(origin, alias).commit()) { "Could not save certificate choice" }
                      retire(origin)
                    }
                    sendEvent("changed", mapOf("origin" to origin))
                  }
                  promise.resolve(alias)
                } catch (error: Exception) {
                  promise.reject("CERTIFICATE_UNAVAILABLE", error.message, error)
                } finally { choosing = false }
              }
            }, null, null, uri.host, if (uri.port == -1) 443 else uri.port, preferences.getString(origin, null))
          } catch (error: Exception) {
            choosing = false
            promise.reject("CERTIFICATE_PICKER", error.message, error)
          }
        }
      }
    }
    AsyncFunction("remove") { url: String ->
      val origin = requireNotNull(certificateOrigin(url)) { "HTTPS host required" }
      synchronized(lock) {
        check(preferences.edit().remove(origin).commit()) { "Could not remove certificate choice" }
        retire(origin)
      }
      sendEvent("changed", mapOf("origin" to origin))
    }
    Function("cancel") { id: String ->
      cancelled.add(id)
      calls[id]?.cancel()
    }
    AsyncFunction("transfer") { id: String, url: String, fileUri: String, upload: Boolean, contentType: String, promise: Promise ->
      val requestedOrigin = certificateOrigin(url)
      val generation = requestedOrigin?.let { synchronized(lock) { transport.generation(it) } }
      io.execute {
        var file: File? = null
        try {
          val origin = requireNotNull(certificateOrigin(url)) { "HTTPS URL required" }
          check(preferences.contains(origin)) { "No client certificate selected for this host" }
          val uri = Uri.parse(fileUri)
          require(uri.scheme == "file") { "An app-owned file is required" }
          val target = File(requireNotNull(uri.path)).canonicalFile
          val roots = listOf(context.filesDir.canonicalFile, context.cacheDir.canonicalFile)
          require(roots.any { target.path.startsWith(it.path + File.separator) }) { "File must be inside app storage" }
          file = target
          if (cancelled.contains(id)) throw IOException("Transfer cancelled")
          val request = Request.Builder().url(url)
          if (upload) {
            val body = target.asRequestBody(contentType.toMediaTypeOrNull())
            request.post(object : RequestBody() {
              override fun contentType() = body.contentType()
              override fun contentLength() = body.contentLength()
              override fun writeTo(sink: okio.BufferedSink) {
                val total = contentLength()
                var sent = 0L
                var last = 0L
                val forwarding = object : okio.ForwardingSink(sink) {
                  override fun write(source: okio.Buffer, byteCount: Long) {
                    super.write(source, byteCount)
                    sent += byteCount
                    val now = System.nanoTime()
                    if (sent == total || now - last > 100_000_000L) {
                      last = now
                      sendEvent("transferProgress", mapOf("id" to id, "bytesSent" to sent, "totalBytes" to total))
                    }
                  }
                }
                val buffered = forwarding.buffer()
                body.writeTo(buffered)
                buffered.flush()
              }
            })
          }
          val call = synchronized(lock) {
            check(preferences.contains(origin)) { "Certificate selection changed. Try again." }
            check(transport.generation(origin) === generation) { "Certificate selection changed. Try again." }
            fileClient.newCall(request.build()).also { calls[id] = it }
          }
          if (cancelled.contains(id)) call.cancel()
          call.execute().use { response ->
            if (!upload) {
              if (!response.isSuccessful) throw IOException("Download returned HTTP ${response.code}")
              val body = response.body ?: throw IOException("Empty download response")
              target.outputStream().use { output -> body.byteStream().use { it.copyTo(output) } }
            }
            if (call.isCanceled()) throw IOException("Transfer cancelled")
            promise.resolve(mapOf("status" to response.code))
          }
        } catch (error: Exception) {
          if (!upload) file?.delete()
          promise.reject("CERTIFICATE_TRANSFER", error.message, error)
        } finally {
          calls.remove(id)
          cancelled.remove(id)
        }
      }
    }
    OnDestroy {
      context.unregisterReceiver(keyChainChanges)
      synchronized(lock) {
        transport.invalidateAll()
        calls.values.forEach { it.cancel() }
        sockets.keys.forEach { runCatching { it.close() } }
      }
      io.shutdown()
    }
  }

  private fun retire(origin: String) {
    transport.invalidate(origin)
    calls.values.filter { certificateOrigin(it.request().url.toString()) == origin }.forEach { it.cancel() }
    sockets.entries.filter { it.value == origin }.forEach {
      runCatching { it.key.close() }
      sockets.remove(it.key)
    }
    fileClient.connectionPool.evictAll()
  }
}
