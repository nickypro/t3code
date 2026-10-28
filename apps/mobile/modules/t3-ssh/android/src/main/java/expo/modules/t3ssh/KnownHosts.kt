package expo.modules.t3ssh

import java.util.Base64

/** One plain `known_hosts` entry: `name[,name...] keytype base64`. */
data class KnownHost(val names: List<String>, val keyType: String, val keyBase64: String) {
  val line: String get() = "${names.joinToString(",")} $keyType $keyBase64"

  fun matches(name: String): Boolean = name in names
}

/**
 * The subset of OpenSSH's known_hosts this app writes and reads: plain names, one key per
 * line. Hashed names and `@cert-authority`/`@revoked` markers are skipped, so they can never
 * make a host trusted.
 */
object KnownHosts {
  /** The name OpenSSH files a host under: `host` on port 22, otherwise `[host]:port`. */
  fun name(host: String, port: Int): String = if (port == 22) host else "[$host]:$port"

  fun parse(text: String): List<KnownHost> = text.lineSequence().mapNotNull(::parseLine).toList()

  fun parseLine(raw: String): KnownHost? {
    val line = raw.trim()
    if (line.isEmpty() || line.startsWith("#") || line.startsWith("@") || line.startsWith("|")) {
      return null
    }
    val fields = line.split(Regex("\\s+"))
    if (fields.size < 3) return null
    val names = fields[0].split(",").filter { it.isNotEmpty() }
    if (names.isEmpty() || names.any { it.startsWith("|") || it.contains('*') || it.contains('?') }) {
      return null
    }
    val blob = try {
      Base64.getDecoder().decode(fields[2])
    } catch (_: IllegalArgumentException) {
      return null
    }
    if (blob.isEmpty()) return null
    return KnownHost(names, fields[1], fields[2])
  }
}
