import { beforeEach, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  getAlias: vi.fn(),
  transfer: vi.fn(),
  cancel: vi.fn(),
  removeListener: vi.fn(),
  listener: undefined as
    | undefined
    | ((event: { id: string; bytesSent: number; totalBytes: number }) => void),
}));
vi.mock("react-native", () => ({ Platform: { OS: "android" } }));
vi.mock("expo", () => ({
  requireOptionalNativeModule: () => ({
    getAlias: mocks.getAlias,
    transfer: mocks.transfer,
    cancel: mocks.cancel,
    addListener: (_: string, listener: typeof mocks.listener) => {
      mocks.listener = listener;
      return { remove: mocks.removeListener };
    },
  }),
}));
vi.mock("./uuid", () => ({ uuidv4: () => "transfer-id" }));
import { transferWithClientCertificate } from "./clientCertificates";

const input = { url: "https://server.example/upload", fileUri: "file:///app/file", upload: true };
beforeEach(() => {
  vi.clearAllMocks();
  mocks.getAlias.mockReturnValue("phone");
  mocks.transfer.mockResolvedValue({ status: 204 });
});
it("leaves ordinary destinations on their existing transport", async () => {
  mocks.getAlias.mockReturnValue(null);
  expect(
    await transferWithClientCertificate({ ...input, signal: new AbortController().signal }),
  ).toBeNull();
  expect(mocks.transfer).not.toHaveBeenCalled();
});
it("preserves an HTTP error status instead of treating it as a TLS failure", async () => {
  mocks.transfer.mockResolvedValue({ status: 401 });
  expect(
    await transferWithClientCertificate({ ...input, signal: new AbortController().signal }),
  ).toEqual({ status: 401 });
});
it("does not downgrade native certificate errors to anonymous transfers", async () => {
  mocks.transfer.mockRejectedValue(new Error("KeyChain grant revoked"));
  await expect(
    transferWithClientCertificate({ ...input, signal: new AbortController().signal }),
  ).rejects.toThrow("grant revoked");
});
it("does not start an already aborted transfer", async () => {
  const controller = new AbortController();
  controller.abort();
  await expect(
    transferWithClientCertificate({ ...input, signal: controller.signal }),
  ).rejects.toThrow();
  expect(mocks.transfer).not.toHaveBeenCalled();
});
it("cancels the native operation and releases its progress listener", async () => {
  const controller = new AbortController();
  let finish!: (value: { status: number }) => void;
  mocks.transfer.mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const pending = transferWithClientCertificate({
    ...input,
    signal: controller.signal,
    onProgress: vi.fn(),
  });
  controller.abort();
  expect(mocks.cancel).toHaveBeenCalledWith("transfer-id");
  finish({ status: 204 });
  await expect(pending).rejects.toThrow();
  expect(mocks.removeListener).toHaveBeenCalledOnce();
});
it("reports only this transfer's progress", async () => {
  const progress = vi.fn();
  mocks.transfer.mockImplementation(async () => {
    mocks.listener?.({ id: "other", bytesSent: 9, totalBytes: 10 });
    mocks.listener?.({ id: "transfer-id", bytesSent: 5, totalBytes: 10 });
    return { status: 204 };
  });
  await transferWithClientCertificate({
    ...input,
    signal: new AbortController().signal,
    onProgress: progress,
  });
  expect(progress).toHaveBeenCalledExactlyOnceWith(0.5);
  expect(mocks.removeListener).toHaveBeenCalledOnce();
});
