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
    val fields = raw.trim().split(WHITESPACE)
    if (fields.size < 3 || !isPlainNameList(fields[0])) return null
    val blob = runCatching { Base64.getDecoder().decode(fields[2]) }.getOrNull()
    val entry = KnownHost(fields[0].split(","), fields[1], fields[2])
    return entry.takeIf { blob?.isNotEmpty() == true }
  }

  // Comments, `@` markers, hashed `|1|` names and patterns could match a host other than the
  // one the user trusted, so only plain names count.
  private fun isPlainNameList(field: String): Boolean = field.split(",").all { name ->
    name.isNotEmpty() && name[0] !in "#@|" && name.none { it in "*?!" }
  }

  private val WHITESPACE = Regex("\\s+")
}
