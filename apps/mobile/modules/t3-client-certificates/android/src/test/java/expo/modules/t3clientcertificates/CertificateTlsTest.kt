package expo.modules.t3clientcertificates

import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import okhttp3.*
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.*
import org.junit.Test

class CertificateTlsTest {
  private val ca = HeldCertificate.Builder().certificateAuthority(1).commonName("test CA").build()
  private val serverIdentity = HeldCertificate.Builder().commonName("localhost").addSubjectAlternativeName("localhost").addSubjectAlternativeName("t3.test").signedBy(ca).build()
  private val phone = HeldCertificate.Builder().commonName("phone").signedBy(ca).build()
  private val serverTls = HandshakeCertificates.Builder().heldCertificate(serverIdentity, ca.certificate).addTrustedCertificate(ca.certificate).build()
  private val clientTrust = HandshakeCertificates.Builder().addTrustedCertificate(ca.certificate).build()

  private fun server(required: Boolean = true) = MockWebServer().apply {
    useHttps(serverTls.sslSocketFactory(), false)
    if (required) requireClientAuth() else requestClientAuth()
    protocols = listOf(Protocol.HTTP_1_1)
    start()
  }

  private fun client(
    origins: Set<String>,
    identity: HeldCertificate = phone,
    tlsVersion: TlsVersion? = null,
    opened: (String, Socket) -> Unit = { _, _ -> },
  ): OkHttpClient {
    val tls = SSLContext.getInstance("TLS").apply {
      init(arrayOf(SelectedIdentity("phone", identity.keyPair.private, arrayOf(identity.certificate, ca.certificate))), arrayOf(clientTrust.trustManager), null)
    }
    return OkHttpClient.Builder()
      .sslSocketFactory(OriginSocketFactory(clientTrust.sslSocketFactory(), { origin ->
        if (origin in origins) tls.socketFactory else clientTrust.sslSocketFactory()
      }, opened), clientTrust.trustManager)
      .protocols(listOf(Protocol.HTTP_1_1))
      .apply {
        if (tlsVersion != null) connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS).tlsVersions(tlsVersion).build()))
      }
      .callTimeout(5, TimeUnit.SECONDS)
      .build()
  }

  @Test fun originNormalizationRejectsCleartextAndUserInfo() {
    assertEquals("https://example.com/", certificateOrigin("https://EXAMPLE.com:443/path?token=secret#fragment"))
    assertEquals("https://example.com:8443/", certificateOrigin("wss://example.com:8443/ws"))
    assertEquals("https://[::1]:8443/", certificateOrigin("https://[::1]:8443/a"))
    assertNull(certificateOrigin("http://example.com"))
    assertNull(certificateOrigin("ws://example.com"))
    assertNull(certificateOrigin("https://user:pass@example.com"))
    assertNull(certificateOrigin("not a URL"))
  }

  @Test fun selectedIdentityHonorsRequestedKeyAndIssuer() {
    val identity = SelectedIdentity("phone", phone.keyPair.private, arrayOf(phone.certificate, ca.certificate))
    val algorithm = phone.keyPair.private.algorithm
    assertEquals("phone", identity.chooseClientAlias(arrayOf(algorithm), arrayOf(ca.certificate.subjectX500Principal), null))
    assertNull(identity.chooseClientAlias(arrayOf("UNSUPPORTED"), null, null))
    assertNull(identity.chooseClientAlias(arrayOf(algorithm), arrayOf(javax.security.auth.x500.X500Principal("CN=other")), null))
    assertNull(identity.getPrivateKey("other"))
    assertNull(identity.chooseServerAlias(algorithm, null, null))
  }

  @Test fun descriptorAndFileRoundTripUseCertificate() {
    val server = server()
    try {
      val client = client(setOf(certificateOrigin(server.url("/").toString())!!))
      server.enqueue(MockResponse().setBody("{\"environmentId\":\"test\"}"))
      server.enqueue(MockResponse().setBody("uploaded"))
      server.enqueue(MockResponse().setBody("attachment bytes"))
      client.newCall(Request.Builder().url(server.url("/.well-known/t3/environment")).build()).execute().use { assertEquals(200, it.code) }
      client.newCall(Request.Builder().url(server.url("/upload")).post("attachment bytes".toRequestBody()).build()).execute().close()
      client.newCall(Request.Builder().url(server.url("/download")).build()).execute().use { assertEquals("attachment bytes", it.body!!.string()) }
      repeat(3) { index ->
        val request = server.takeRequest(2, TimeUnit.SECONDS)!!
        assertEquals(phone.certificate, request.handshake!!.peerCertificates.first())
        if (index == 1) assertEquals("attachment bytes", request.body.readUtf8())
      }
      client.connectionPool.evictAll()
    } finally { server.shutdown() }
  }

  @Test fun websocketStreamsWithTheSameIdentity() {
    val server = server()
    try {
      server.enqueue(MockResponse().withWebSocketUpgrade(object : WebSocketListener() {
        override fun onMessage(webSocket: WebSocket, text: String) { webSocket.send("stream:$text") }
      }))
      val received = CountDownLatch(1)
      var message: String? = null
      val client = client(setOf(certificateOrigin(server.url("/").toString())!!))
      val socket = client.newWebSocket(Request.Builder().url(server.url("/ws")).build(), object : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) { webSocket.send("hello") }
        override fun onMessage(webSocket: WebSocket, text: String) { message = text; received.countDown() }
      })
      assertTrue(received.await(5, TimeUnit.SECONDS))
      assertEquals("stream:hello", message)
      assertEquals(phone.certificate, server.takeRequest(2, TimeUnit.SECONDS)!!.handshake!!.peerCertificates.first())
      socket.cancel()
      client.dispatcher.executorService.shutdown()
      client.connectionPool.evictAll()
    } finally { server.shutdown() }
  }

  @Test fun redirectToAnotherPortDoesNotReceiveTheCertificate() {
    val authenticated = server()
    val other = server(false)
    try {
      authenticated.enqueue(MockResponse().setResponseCode(302).addHeader("Location", other.url("/redirect-target")))
      other.enqueue(MockResponse().setBody("anonymous"))
      val client = client(setOf(certificateOrigin(authenticated.url("/").toString())!!))
      client.newCall(Request.Builder().url(authenticated.url("/redirect")).build()).execute().use { assertEquals("anonymous", it.body!!.string()) }
      assertEquals(phone.certificate, authenticated.takeRequest(2, TimeUnit.SECONDS)!!.handshake!!.peerCertificates.first())
      assertTrue(other.takeRequest(2, TimeUnit.SECONDS)!!.handshake!!.peerCertificates.isEmpty())
      client.connectionPool.evictAll()
    } finally { authenticated.shutdown(); other.shutdown() }
  }

  @Test fun missingIdentityFailsRequiredClientAuthentication() {
    val server = server()
    try {
      val client = client(emptySet())
      try {
        client.newCall(Request.Builder().url(server.url("/")).build()).execute().use { fail("mTLS must fail without identity") }
      } catch (_: java.io.IOException) { /* expected handshake rejection */ }
      client.connectionPool.evictAll()
    } finally { server.shutdown() }
  }
  @Test fun serverHostnameVerificationIsPreserved() {
    val server = server()
    try {
      val wrongHost = server.url("/").newBuilder().host("127.0.0.1").build()
      val client = client(setOf(certificateOrigin(wrongHost.toString())!!))
      try {
        client.newCall(Request.Builder().url(wrongHost).build()).execute().use { fail("Wrong server hostname must be rejected") }
      } catch (_: javax.net.ssl.SSLPeerUnverifiedException) { /* expected */ }
      client.connectionPool.evictAll()
    } finally { server.shutdown() }
  }

  @Test fun removingIdentityAndClosingItsSocketsPreventsAuthenticatedReuse() {
    val server = server()
    try {
      val origins = mutableSetOf(certificateOrigin(server.url("/").toString())!!)
      val sockets = mutableListOf<Socket>()
      val client = client(origins) { _, socket -> sockets.add(socket) }
      server.enqueue(MockResponse().setBody("authenticated"))
      client.newCall(Request.Builder().url(server.url("/")).build()).execute().use { assertEquals(200, it.code) }
      origins.clear()
      sockets.forEach { it.close() }
      try {
        client.newCall(Request.Builder().url(server.url("/")).build()).execute().use { fail("Old authenticated socket must not be reused") }
      } catch (_: java.io.IOException) { /* required client identity was removed */ }
      client.connectionPool.evictAll()
    } finally { server.shutdown() }
  }

  @Test fun rsaAndEcIdentitiesAuthenticateWithTls12AndTls13() {
    val rsa = HeldCertificate.Builder().rsa2048().commonName("RSA phone").signedBy(ca).build()
    for (identity in listOf(phone, rsa)) {
      for (version in listOf(TlsVersion.TLS_1_2, TlsVersion.TLS_1_3)) {
        val server = server()
        val client = client(setOf(certificateOrigin(server.url("/").toString())!!), identity, version)
        try {
          server.enqueue(MockResponse().setBody("authenticated"))
          client.newCall(Request.Builder().url(server.url("/")).build()).execute().use {
            assertEquals("${identity.keyPair.private.algorithm} $version", 200, it.code)
            assertEquals(version, it.handshake!!.tlsVersion)
          }
          assertEquals(identity.certificate, server.takeRequest(2, TimeUnit.SECONDS)!!.handshake!!.peerCertificates.first())
        } finally {
          client.connectionPool.evictAll()
          server.shutdown()
        }
      }
    }
  }

  @Test fun intermediateChainMatchesEitherAcceptedIssuer() {
    val intermediate = HeldCertificate.Builder().certificateAuthority(0).commonName("intermediate CA").signedBy(ca).build()
    val leaf = HeldCertificate.Builder().commonName("phone via intermediate").signedBy(intermediate).build()
    val chain = arrayOf(leaf.certificate, intermediate.certificate)
    val identity = SelectedIdentity("phone", leaf.keyPair.private, chain)
    for (issuer in listOf(ca.certificate, intermediate.certificate)) {
      assertEquals("phone", identity.chooseClientAlias(arrayOf(leaf.keyPair.private.algorithm), arrayOf(issuer.subjectX500Principal), null))
    }
    // Android may omit the root from the returned chain; the intermediate's issuer still matches.
    assertArrayEquals(chain, identity.getCertificateChain("phone"))
    val returned = identity.getCertificateChain("phone")!!
    returned[0] = ca.certificate
    assertEquals(leaf.certificate, identity.getCertificateChain("phone")!![0])
  }

  @Test fun redirectToAnotherHostnameOnTheSameServerDoesNotReceiveTheCertificate() {
    val server = server(false)
    val origin = certificateOrigin(server.url("/").toString())!!
    val client = client(setOf(origin)).newBuilder()
      .dns(object : Dns {
        override fun lookup(hostname: String): List<InetAddress> =
          if (hostname == "t3.test") listOf(InetAddress.getByName("127.0.0.1")) else Dns.SYSTEM.lookup(hostname)
      })
      .build()
    try {
      val destination = server.url("/other-host").newBuilder().host("t3.test").build()
      server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", destination))
      server.enqueue(MockResponse().setBody("anonymous"))
      client.newCall(Request.Builder().url(server.url("/redirect")).build()).execute().use {
        assertEquals("anonymous", it.body!!.string())
      }
      assertEquals(phone.certificate, server.takeRequest(2, TimeUnit.SECONDS)!!.handshake!!.peerCertificates.first())
      assertTrue(server.takeRequest(2, TimeUnit.SECONDS)!!.handshake!!.peerCertificates.isEmpty())
    } finally {
      client.connectionPool.evictAll()
      server.shutdown()
    }
  }

  @Test fun selectedClientIdentityDoesNotTrustAnUnrecognizedServerCa() {
    val untrusted = HeldCertificate.Builder().commonName("localhost").addSubjectAlternativeName("localhost").build()
    val untrustedTls = HandshakeCertificates.Builder().heldCertificate(untrusted).addTrustedCertificate(ca.certificate).build()
    val server = MockWebServer().apply {
      useHttps(untrustedTls.sslSocketFactory(), false)
      requireClientAuth()
      start()
    }
    val client = client(setOf(certificateOrigin(server.url("/").toString())!!))
    try {
      client.newCall(Request.Builder().url(server.url("/")).build()).execute().use {
        fail("Selecting a client certificate must not bypass server trust")
      }
    } catch (_: javax.net.ssl.SSLHandshakeException) {
      // Expected: a client identity cannot grant trust to an unrelated server certificate.
    } finally {
      client.connectionPool.evictAll()
      server.shutdown()
    }
  }

  @Test fun differentOriginsKeepTheirOwnIdentityWhenConnectionsAreReused() {
    val server = server()
    val secondPhone = HeldCertificate.Builder().commonName("second phone").signedBy(ca).build()
    val firstUrl = server.url("/")
    val secondUrl = firstUrl.newBuilder().host("t3.test").build()
    val identities = mapOf(
      certificateOrigin(firstUrl.toString())!! to phone,
      certificateOrigin(secondUrl.toString())!! to secondPhone,
    )
    val socketFactory = OriginSocketFactory(clientTrust.sslSocketFactory(), { origin ->
      val identity = identities.getValue(origin)
      SSLContext.getInstance("TLS").apply {
        init(arrayOf(SelectedIdentity("phone", identity.keyPair.private, arrayOf(identity.certificate, ca.certificate))), arrayOf(clientTrust.trustManager), null)
      }.socketFactory
    }, { _, _ -> })
    val client = OkHttpClient.Builder()
      .sslSocketFactory(socketFactory, clientTrust.trustManager)
      .protocols(listOf(Protocol.HTTP_1_1))
      .dns(object : Dns {
        override fun lookup(hostname: String): List<InetAddress> =
          if (hostname == "t3.test") listOf(InetAddress.getByName("127.0.0.1")) else Dns.SYSTEM.lookup(hostname)
      })
      .callTimeout(5, TimeUnit.SECONDS)
      .build()
    try {
      for ((index, destination) in listOf(firstUrl to phone, secondUrl to secondPhone, firstUrl to phone).withIndex()) {
        val (url, identity) = destination
        server.enqueue(MockResponse().setBody("authenticated"))
        client.newCall(Request.Builder().url(url).build()).execute().use { assertEquals(200, it.code) }
        val received = server.takeRequest(2, TimeUnit.SECONDS)!!
        assertEquals(identity.certificate, received.handshake!!.peerCertificates.first())
        assertEquals(if (index == 2) 1 else 0, received.sequenceNumber)
      }
    } finally {
      client.connectionPool.evictAll()
      server.shutdown()
    }
  }

  @Test fun changingIdentityInvalidatesQueuedWorkOnlyForThatOrigin() {
    val generations = CertificateGenerations()
    val origin = "https://first.test/"
    val otherOrigin = "https://second.test/"
    val pendingFirst = generations.generation(origin)
    val pendingOther = generations.generation(otherOrigin)

    // A transfer queued with certificate A must not register after switching to B.
    generations.invalidate(origin)
    assertNotSame(pendingFirst, generations.generation(origin))
    assertSame(pendingOther, generations.generation(otherOrigin))
    // Requests captured after the switch remain valid until another identity change.
    val pendingAfterSwitch = generations.generation(origin)
    assertSame(pendingAfterSwitch, generations.generation(origin))
  }

  @Test fun removingAndReaddingTheSameAliasCannotReviveQueuedWork() {
    val generations = CertificateGenerations()
    val origin = "https://first.test/"
    val beforeRemoval = generations.generation(origin)
    generations.invalidate(origin)
    val whileRemoved = generations.generation(origin)
    // Re-selecting the same alias (or replacing its underlying key) is still a new identity grant.
    generations.invalidate(origin)
    val afterReadding = generations.generation(origin)
    assertNotSame(beforeRemoval, afterReadding)
    assertNotSame(whileRemoved, afterReadding)
  }

  @Test fun keyChainChangesInvalidateEveryQueuedOrigin() {
    val generations = CertificateGenerations()
    val origins = listOf("https://first.test/", "https://first.test:8443/", "https://second.test/")
    val pending = origins.associateWith { generations.generation(it) }
    generations.invalidateAll()
    for (origin in origins) {
      assertNotSame(pending.getValue(origin), generations.generation(origin))
    }
  }

}
