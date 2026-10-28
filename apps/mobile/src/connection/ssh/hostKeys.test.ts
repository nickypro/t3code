import { describe, expect, it, vi } from "vite-plus/test";

import { reviewHostKeys, SshHostKeyChangedError } from "./hostKeys";
import type { SshConnectResult, SshHop, SshHostKeyRejection, SshNative } from "./native";

const HOPS: ReadonlyArray<SshHop> = [
  { host: "jump.example", port: 22, user: "me", hostKeyAlias: null },
  { host: "127.0.0.1", port: 2222, user: "dev", hostKeyAlias: "box" },
];

function rejection(name: string, changed = false): SshHostKeyRejection {
  return {
    status: "host-key-rejected",
    host: name,
    port: 22,
    knownHostsName: name,
    keyType: "ssh-ed25519",
    fingerprint: `SHA256:${name}`,
    knownHostsLine: `${name} ssh-ed25519 AAAA`,
    changed,
  };
}

function fakeNative(results: ReadonlyArray<SshConnectResult>) {
  const queue = [...results];
  const native = {
    connect: vi.fn(async () => queue.shift() ?? { status: "connected" as const, sessionId: "s" }),
    trustHostKey: vi.fn(async (_line: string) => undefined),
    close: vi.fn(async (_id: string) => undefined),
  };
  return native as typeof native & SshNative;
}

describe("reviewHostKeys", () => {
  it("asks about each new hop in order, then closes the check connection", async () => {
    const native = fakeNative([rejection("jump.example"), rejection("box")]);
    const asked: string[] = [];

    const trusted = await reviewHostKeys(native, HOPS, async (key) => {
      asked.push(key.knownHostsName);
      return true;
    });

    expect(trusted).toBe(true);
    expect(asked).toEqual(["jump.example", "box"]);
    expect(native.trustHostKey.mock.calls).toEqual([
      ["jump.example ssh-ed25519 AAAA"],
      ["box ssh-ed25519 AAAA"],
    ]);
    expect(native.close).toHaveBeenCalledWith("s");
  });

  it("trusts nothing when the user declines", async () => {
    const native = fakeNative([rejection("jump.example")]);

    expect(await reviewHostKeys(native, HOPS, async () => false)).toBe(false);
    expect(native.trustHostKey).not.toHaveBeenCalled();
  });

  it("never offers a changed key for trust", async () => {
    const native = fakeNative([rejection("box", true)]);
    const confirm = vi.fn(async () => true);

    await expect(reviewHostKeys(native, HOPS, confirm)).rejects.toBeInstanceOf(
      SshHostKeyChangedError,
    );
    expect(confirm).not.toHaveBeenCalled();
    expect(native.trustHostKey).not.toHaveBeenCalled();
  });
});
