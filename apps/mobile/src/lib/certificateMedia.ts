import { selectedClientCertificate, transferWithClientCertificate } from "./clientCertificates";
import { uuidv4 } from "./uuid";

/** Expo Video bypasses React Native's TLS hooks, so protected videos need a private file lease. */
export async function loadCertificateMedia(
  uri: string,
  signal: AbortSignal,
): Promise<{ uri: string; dispose(): void }> {
  if (!selectedClientCertificate(uri)) return { uri, dispose() {} };
  if (signal.aborted) throw new Error("Media download cancelled.");
  const { File, Paths } = await import("expo-file-system");
  const file = new File(Paths.cache, `t3-mtls-media-${uuidv4()}`);
  const dispose = () => {
    if (file.exists) file.delete();
  };
  try {
    const result = await transferWithClientCertificate({ url: uri, fileUri: file.uri, signal });
    if (result === null) throw new Error("Certificate selection changed. Try again.");
    if (signal.aborted) throw new Error("Media download cancelled.");
    return { uri: file.uri, dispose };
  } catch (error) {
    dispose();
    throw error;
  }
}
