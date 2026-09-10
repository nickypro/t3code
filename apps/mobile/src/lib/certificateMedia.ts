import { useEffect, useState } from "react";

import {
  selectedClientCertificate,
  onClientCertificateChange,
  transferWithClientCertificate,
} from "./clientCertificates";
import { uuidv4 } from "./uuid";

/** Lease a private cache file for native media loaders that do not share React Native's TLS hooks. */
export async function loadCertificateMedia(
  uri: string,
  signal: AbortSignal,
): Promise<{ uri: string; dispose(): void }> {
  if (!selectedClientCertificate(uri)) return { uri, dispose() {} };
  signal.throwIfAborted();
  const { File, Paths } = await import("expo-file-system");
  const file = new File(Paths.cache, `t3-mtls-media-${uuidv4()}`);
  const dispose = () => {
    if (file.exists) file.delete();
  };
  try {
    const result = await transferWithClientCertificate({ url: uri, fileUri: file.uri, signal });
    if (result === null) throw new Error("Certificate selection changed. Try again.");
    signal.throwIfAborted();
    return { uri: file.uri, dispose };
  } catch (error) {
    dispose();
    throw error;
  }
}

export function useCertificateMedia(source: string): { uri: string | null; failed: boolean } {
  const [generation, setGeneration] = useState(0);
  const [resolved, setResolved] = useState<{
    source: string;
    generation: number;
    uri: string | null;
    failed: boolean;
  } | null>(null);
  const protectedSource = selectedClientCertificate(source) !== null;
  useEffect(() => {
    const subscription = onClientCertificateChange(() => setGeneration((value) => value + 1));
    return () => subscription.remove();
  }, []);
  useEffect(() => {
    if (!protectedSource) return;
    const controller = new AbortController();
    let release = () => {};
    void loadCertificateMedia(source, controller.signal).then(
      (media) => {
        if (controller.signal.aborted) {
          media.dispose();
          return;
        }
        release = media.dispose;
        setResolved({ source, generation, uri: media.uri, failed: false });
      },
      () => {
        if (!controller.signal.aborted)
          setResolved({ source, generation, uri: null, failed: true });
      },
    );
    return () => {
      controller.abort();
      release();
    };
  }, [source, generation, protectedSource]);
  if (!protectedSource) return { uri: source, failed: false };
  return resolved?.source === source && resolved.generation === generation
    ? resolved
    : { uri: null, failed: false };
}
