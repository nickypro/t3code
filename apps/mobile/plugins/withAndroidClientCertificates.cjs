const { withMainApplication } = require("expo/config-plugins");

const install = "expo.modules.t3clientcertificates.T3CertificateTransport.install(this)";

function installCertificateTransport(source) {
  // Anchor to the method body, not a comment or another lifecycle method. Fail closed if
  // a future Expo template runs initialization before super.onCreate(). These hooks must
  // precede every eagerly created Expo fetch / Fresco client.
  const marker = /override fun onCreate\(\)\s*\{\s*super\.onCreate\(\)[ \t]*;?/g;
  const matches = [...source.matchAll(marker)];
  if (matches.length !== 1)
    throw new Error("Cannot install client certificates before React Native startup");
  const match = matches[0];
  const offset = match.index + match[0].length;
  if (source.includes(install)) {
    if (!source.slice(offset).trimStart().startsWith(install) || source.split(install).length !== 2)
      throw new Error(
        "Client certificate transport must be installed immediately after super.onCreate()",
      );
    return source;
  }
  const newline = source.includes("\r\n") ? "\r\n" : "\n";
  return source.slice(0, offset) + `${newline}    ${install}` + source.slice(offset);
}

module.exports = (config) =>
  withMainApplication(config, (next) => {
    if (next.modResults.language !== "kt")
      throw new Error("Client certificate startup requires Kotlin MainApplication");
    next.modResults.contents = installCertificateTransport(next.modResults.contents);
    return next;
  });
module.exports.installCertificateTransport = installCertificateTransport;
