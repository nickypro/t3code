package expo.modules.t3ssh

import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.schmizz.sshj.userauth.UserAuthException
import java.io.File
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class SshHopRecord : Record {
  @Field val host: String = ""

  @Field val port: Int = 22

  @Field val user: String = ""

  @Field val hostKeyAlias: String? = null
}

/**
 * SSH for the app's SSH environments. The private key never leaves this module: JavaScript
 * sees the public line, fingerprints and session ids.
 */
class T3SshModule : Module() {
  private val sessions = ConcurrentHashMap<String, SshSession>()

  private val store: SshStore by lazy {
    val context = appContext.reactContext ?: throw Exceptions.ReactContextLost()
    SshStore(File(context.noBackupFilesDir, "t3-ssh"), KeystoreSealer)
  }

  override fun definition() = ModuleDefinition {
    Name("T3Ssh")

    OnDestroy {
      for (session in sessions.values) session.close()
      sessions.clear()
    }

    AsyncFunction("getPublicKey") Coroutine { -> io { store.publicKeyLine()?.let(::publicKeyInfo) } }

    AsyncFunction("createKey") Coroutine { comment: String -> io { publicKeyInfo(store.createKey(comment)) } }

    AsyncFunction("deleteKey") Coroutine { -> io { store.deleteKey() } }

    AsyncFunction("readConfig") Coroutine { -> io { store.readConfig() } }

    AsyncFunction("writeConfig") Coroutine { text: String -> io { store.writeConfig(text) } }

    AsyncFunction("listKnownHosts") Coroutine { ->
      io {
        store.knownHosts().map { entry ->
          mapOf(
            "line" to entry.line,
            "names" to entry.names,
            "keyType" to entry.keyType,
            "fingerprint" to sshFingerprint(Base64.getDecoder().decode(entry.keyBase64)),
          )
        }
      }
    }

    AsyncFunction("trustHostKey") Coroutine { line: String -> io { store.trust(line) } }

    AsyncFunction("forgetHostKey") Coroutine { line: String -> io { store.forget(line) } }

    AsyncFunction("connect") Coroutine { hops: List<SshHopRecord> -> io { connect(hops) } }

    AsyncFunction("exec") Coroutine { sessionId: String, command: String, stdin: String, timeoutMs: Double ->
      io {
        val result = session(sessionId).exec(command, stdin, timeoutMs.toLong())
        mapOf("exitCode" to result.exitCode, "stdout" to result.stdout, "stderr" to result.stderr)
      }
    }

    AsyncFunction("forward") Coroutine { sessionId: String, remotePort: Int ->
      io { session(sessionId).forward(remotePort) }
    }

    Function("isOpen") { sessionId: String -> sessions[sessionId]?.isOpen == true }

    AsyncFunction("close") Coroutine { sessionId: String -> io { sessions.remove(sessionId)?.close() } }
  }

  private fun connect(hops: List<SshHopRecord>): Map<String, Any?> {
    val key = store.key() ?: throw CodedException("ERR_SSH_NO_KEY", "Create an SSH key first.", null)
    sessions.entries.removeIf { !it.value.isOpen }
    val result = SshSession.connect(
      hops.map { SshHop(it.host, it.port, it.user, it.hostKeyAlias) },
      key.toKeyPair(),
      store.knownHosts(),
    )
    return when (result) {
      is SshConnectResult.Connected -> {
        val id = UUID.randomUUID().toString()
        sessions[id] = result.session
        mapOf("status" to "connected", "sessionId" to id)
      }
      is SshConnectResult.Rejected -> with(result.rejection) {
        mapOf(
          "status" to "host-key-rejected",
          "host" to hop.host,
          "port" to hop.port,
          "knownHostsName" to hop.knownHostsName,
          "keyType" to keyType,
          "fingerprint" to fingerprint,
          "knownHostsLine" to knownHostsLine,
          "changed" to changed,
        )
      }
    }
  }

  private fun session(id: String): SshSession =
    sessions[id]?.takeIf { it.isOpen }
      ?: throw CodedException("ERR_SSH_SESSION_CLOSED", "The SSH connection closed.", null)

  private fun publicKeyInfo(line: String): Map<String, String> {
    val blob = Base64.getDecoder().decode(line.split(Regex("\\s+"))[1])
    return mapOf("line" to line, "fingerprint" to sshFingerprint(blob))
  }

  private suspend fun <T> io(block: () -> T): T = withContext(Dispatchers.IO) {
    try {
      block()
    } catch (error: CodedException) {
      throw error
    } catch (error: UserAuthException) {
      throw CodedException("ERR_SSH_AUTH", "The server did not accept this device's key.", error)
    } catch (error: Exception) {
      val unreachable = error is UnknownHostException || error is ConnectException ||
        error is NoRouteToHostException || error is SocketTimeoutException
      throw CodedException(
        if (unreachable) "ERR_SSH_UNREACHABLE" else "ERR_SSH",
        error.message ?: error.javaClass.simpleName,
        error,
      )
    }
  }
}
