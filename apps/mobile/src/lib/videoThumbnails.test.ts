import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({ createPlayer: vi.fn(), loadMedia: vi.fn() }));
vi.mock("./certificateMedia", () => ({ loadCertificateMedia: mocks.loadMedia }));
vi.mock("expo-video", () => ({ createVideoPlayer: mocks.createPlayer }));

let thumbnails: typeof import("./videoThumbnails");
const frame = { width: 480, height: 270 };
const player = () => ({
  replaceAsync: vi.fn(async (): Promise<void> => {}),
  generateThumbnailsAsync: vi.fn(async () => [frame]),
  release: vi.fn(),
});
const source = () => ({ uri: "file:///clip.mp4", dispose: vi.fn() });

beforeEach(async () => {
  vi.resetModules();
  mocks.createPlayer.mockReset().mockImplementation(player);
  mocks.loadMedia.mockReset().mockImplementation(async (uri: string) => ({ uri, dispose() {} }));
  thumbnails = await import("./videoThumbnails");
});

afterEach(() => vi.useRealTimers());

describe("video thumbnails", () => {
  it("serializes decoding and skips queued requests that scroll out of view", async () => {
    const started = Promise.withResolvers<void>();
    const generated = Promise.withResolvers<(typeof frame)[]>();
    const first = player();
    first.generateThumbnailsAsync.mockImplementation(() => {
      started.resolve();
      return generated.promise;
    });
    mocks.createPlayer.mockReturnValueOnce(first);
    const firstRequest = thumbnails.loadVideoThumbnail(
      "first",
      async () => source(),
      new AbortController().signal,
    );
    await started.promise;
    const removed = new AbortController();
    const skipped = vi.fn(async () => source());
    const queued = thumbnails.loadVideoThumbnail("removed", skipped, removed.signal);
    const next = vi.fn(async () => source());
    const nextRequest = thumbnails.loadVideoThumbnail("next", next, new AbortController().signal);
    expect(next).not.toHaveBeenCalled();
    removed.abort();
    generated.resolve([frame]);
    expect(await firstRequest).toBe(frame);
    expect(await queued).toBeNull();
    expect(await nextRequest).toBe(frame);
    expect(skipped).not.toHaveBeenCalled();
    expect(first.release).toHaveBeenCalledTimes(1);
  });

  it("releases an active canceled player and ignores late source loading", async () => {
    const started = Promise.withResolvers<void>();
    const replaced = Promise.withResolvers<void>();
    const first = player();
    first.replaceAsync.mockImplementation(() => {
      started.resolve();
      return replaced.promise;
    });
    mocks.createPlayer.mockReturnValueOnce(first);
    const file = source();
    const controller = new AbortController();
    const request = thumbnails.loadVideoThumbnail("canceled", async () => file, controller.signal);
    await started.promise;
    controller.abort();
    expect(await request).toBeNull();
    expect(first.release).toHaveBeenCalledTimes(1);
    expect(file.dispose).toHaveBeenCalledTimes(1);
    replaced.resolve();
    expect(
      await thumbnails.loadVideoThumbnail(
        "next",
        async () => source(),
        new AbortController().signal,
      ),
    ).toBe(frame);
    expect(first.generateThumbnailsAsync).not.toHaveBeenCalled();
    expect(thumbnails.cachedVideoThumbnail("canceled")).toBeNull();
  });

  it("times out a protected download and disposes its late cache file", async () => {
    vi.useFakeTimers();
    const started = Promise.withResolvers<AbortSignal>();
    const downloaded = Promise.withResolvers<{ uri: string; dispose(): void }>();
    mocks.loadMedia.mockImplementationOnce((_uri: string, signal: AbortSignal) => {
      started.resolve(signal);
      return downloaded.promise;
    });
    const request = thumbnails.loadVideoThumbnail(
      "protected",
      async () => source(),
      new AbortController().signal,
    );
    const downloadSignal = await started.promise;
    await vi.advanceTimersByTimeAsync(15_000);
    expect(await request).toBeNull();
    expect(downloadSignal.aborted).toBe(true);
    expect(
      await thumbnails.loadVideoThumbnail(
        "next",
        async () => source(),
        new AbortController().signal,
      ),
    ).toBe(frame);
    const late = source();
    downloaded.resolve(late);
    await vi.advanceTimersByTimeAsync(0);
    expect(late.dispose).toHaveBeenCalledOnce();
    expect(mocks.createPlayer).toHaveBeenCalledOnce();
  });

  it("releases a protected cache file when native player creation fails", async () => {
    const media = source();
    mocks.loadMedia.mockResolvedValueOnce(media);
    mocks.createPlayer.mockImplementationOnce(() => {
      throw new Error("No player");
    });
    expect(
      await thumbnails.loadVideoThumbnail(
        "broken",
        async () => source(),
        new AbortController().signal,
      ),
    ).toBeNull();
    expect(media.dispose).toHaveBeenCalledOnce();
  });
});
