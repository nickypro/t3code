import { beforeEach, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  selected: vi.fn(),
  transfer: vi.fn(),
  remove: vi.fn(),
}));
vi.mock("./clientCertificates", () => ({
  selectedClientCertificate: mocks.selected,
  transferWithClientCertificate: mocks.transfer,
  onClientCertificateChange: () => ({ remove() {} }),
}));
vi.mock("./uuid", () => ({ uuidv4: () => "unique-id" }));
vi.mock("expo-file-system", () => ({
  Paths: { cache: "file:///cache" },
  File: class {
    uri = "file:///cache/t3-mtls-media-unique-id";
    exists = true;
    delete = mocks.remove;
  },
}));
import { loadCertificateMedia } from "./certificateMedia";

beforeEach(() => {
  vi.resetAllMocks();
  mocks.selected.mockReturnValue("phone");
  mocks.transfer.mockResolvedValue({ status: 200 });
});

it("keeps public and local media on their original loader", async () => {
  mocks.selected.mockReturnValue(null);
  for (const uri of ["file:///cache/local.mp4", "https://public.example/image.png"]) {
    const media = await loadCertificateMedia(uri, new AbortController().signal);
    expect(media.uri).toBe(uri);
    media.dispose();
  }
  expect(mocks.transfer).not.toHaveBeenCalled();
  expect(mocks.remove).not.toHaveBeenCalled();
});

it("leases the protected download until its native consumer releases it", async () => {
  const media = await loadCertificateMedia("https://host/video.mp4", new AbortController().signal);
  expect(media.uri).toBe("file:///cache/t3-mtls-media-unique-id");
  expect(mocks.remove).not.toHaveBeenCalled();
  media.dispose();
  expect(mocks.remove).toHaveBeenCalledOnce();
});

it("cleans a partial download on native failure without returning the original URL", async () => {
  mocks.transfer.mockRejectedValue(new Error("HTTP 401"));
  await expect(
    loadCertificateMedia("https://host/video", new AbortController().signal),
  ).rejects.toThrow("401");
  expect(mocks.remove).toHaveBeenCalledOnce();
});

it("does not fall back to an anonymous loader if the choice changes during setup", async () => {
  mocks.transfer.mockResolvedValue(null);
  await expect(
    loadCertificateMedia("https://host/video", new AbortController().signal),
  ).rejects.toThrow("Certificate selection changed");
  expect(mocks.remove).toHaveBeenCalledOnce();
});

it("removes a completed download if cancellation won the race", async () => {
  const controller = new AbortController();
  mocks.transfer.mockImplementation(async () => {
    controller.abort();
    return { status: 200 };
  });
  await expect(loadCertificateMedia("https://host/video", controller.signal)).rejects.toThrow();
  expect(mocks.remove).toHaveBeenCalledOnce();
});

it("does not start a canceled protected download", async () => {
  const controller = new AbortController();
  controller.abort();
  await expect(loadCertificateMedia("https://host/video", controller.signal)).rejects.toThrow();
  expect(mocks.transfer).not.toHaveBeenCalled();
});
