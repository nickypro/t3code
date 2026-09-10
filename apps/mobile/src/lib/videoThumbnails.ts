import { loadCertificateMedia } from "./certificateMedia";
import type { VideoThumbnail } from "expo-video";

import type { AttachmentPreviewFile } from "./attachmentDownload";

const thumbnails = new Map<string, VideoThumbnail>();
const MAX_CACHED_THUMBNAILS = 32;
let pending: Promise<unknown> = Promise.resolve();

export function cachedVideoThumbnail(key: string): VideoThumbnail | null {
  return thumbnails.get(key) ?? null;
}

async function extractFrame(uri: string, signal: AbortSignal) {
  const controller = new AbortController();
  let player: ReturnType<typeof import("expo-video").createVideoPlayer> | undefined;
  let media: Awaited<ReturnType<typeof loadCertificateMedia>> | undefined;
  const cancel = () => controller.abort();
  const canceled = new Promise<null>((resolve) => {
    controller.signal.addEventListener("abort", () => resolve(null), { once: true });
  });
  signal.addEventListener("abort", cancel, { once: true });
  // Include the certificate download: it must not block thumbnails for other environments.
  const timeout = setTimeout(cancel, 15_000);
  if (signal.aborted) cancel();
  try {
    const frame = (async () => {
      const { createVideoPlayer } = await import("expo-video");
      if (controller.signal.aborted) return null;
      const loaded = await loadCertificateMedia(uri, controller.signal);
      if (controller.signal.aborted) {
        loaded.dispose();
        return null;
      }
      media = loaded;
      player = createVideoPlayer(null);
      // Never play or change audio settings: leave the shared audio session alone.
      player.bufferOptions = { preferredForwardBufferDuration: 1 };
      await player.replaceAsync({ uri: media.uri, contentType: "progressive" });
      if (controller.signal.aborted) return null;
      const [thumbnail] = await player.generateThumbnailsAsync([0], {
        maxWidth: 480,
        maxHeight: 480,
      });
      return thumbnail ?? null;
    })();
    return await Promise.race([frame, canceled]);
  } finally {
    cancel();
    clearTimeout(timeout);
    signal.removeEventListener("abort", cancel);
    try {
      player?.release();
    } finally {
      media?.dispose();
    }
  }
}

/** Serializes frame extraction and releases each temporary player and local-file lease. */
export function loadVideoThumbnail(
  key: string,
  resolveSource: (
    signal: AbortSignal,
  ) => Promise<Pick<AttachmentPreviewFile, "uri" | "dispose"> | null>,
  signal: AbortSignal,
): Promise<VideoThumbnail | null> {
  if (signal.aborted) return Promise.resolve(null);
  const cached = cachedVideoThumbnail(key);
  if (cached) return Promise.resolve(cached);
  const load = pending
    .then(async () => {
      if (signal.aborted) return null;
      const cached = cachedVideoThumbnail(key);
      if (cached) return cached;

      const source = await resolveSource(signal);
      if (!source) return null;
      try {
        const thumbnail = await extractFrame(source.uri, signal);
        if (!thumbnail || signal.aborted) return null;
        thumbnails.set(key, thumbnail);
        if (thumbnails.size > MAX_CACHED_THUMBNAILS) {
          thumbnails.delete(thumbnails.keys().next().value!);
        }
        return thumbnail;
      } finally {
        source.dispose();
      }
    })
    .catch(() => null);
  pending = load;
  return load;
}
