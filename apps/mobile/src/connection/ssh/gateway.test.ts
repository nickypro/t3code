import { describe, expect, it } from "@effect/vitest";
import {
  AuthStandardClientScopes,
  type DesktopSshEnvironmentTarget,
  EnvironmentId,
} from "@t3tools/contracts";
import { targetConnectionKey } from "@t3tools/ssh/remoteScripts";
import * as Effect from "effect/Effect";
import * as Fiber from "effect/Fiber";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientResponse from "effect/http/HttpClientResponse";
import * as TestClock from "effect/testing/TestClock";
import * as NodeCrypto from "node:crypto";
import { vi } from "vite-plus/test";

const http = vi.hoisted(() => ({
  descriptor: vi.fn(),
  exchange: vi.fn(),
  session: vi.fn(),
}));

vi.mock("expo", () => ({ requireOptionalNativeModule: () => null }));
vi.mock("@t3tools/client-runtime/environment", () => ({
  fetchRemoteEnvironmentDescriptor: (input: unknown) => http.descriptor(input),
}));
vi.mock("@t3tools/client-runtime/authorization", () => ({
  bootstrapRemoteBearerSession: (input: unknown) => http.exchange(input),
  fetchRemoteSessionState: (input: unknown) => http.session(input),
}));

import { makeSshGateway } from "./gateway";
import type { SshConnectResult, SshNative } from "./native";

const CONFIG = `
Host jump
  HostName jump.example
  User me
Host box
  HostName 127.0.0.1
  Port 2222
  User dev
  ProxyJump jump
`;
const TARGET: DesktopSshEnvironmentTarget = {
  alias: "box",
  hostname: "127.0.0.1",
  username: "dev",
  port: 2222,
};
const ENVIRONMENT = EnvironmentId.make("env-box");
const sha256Hex = async (text: string) =>
  NodeCrypto.createHash("sha256").update(text).digest("hex");

function setup(options: { readonly connect?: () => SshConnectResult } = {}) {
  http.descriptor
    .mockReset()
    .mockImplementation(() => Effect.succeed({ environmentId: ENVIRONMENT, label: "box" }));
  http.exchange.mockReset().mockImplementation(() => Effect.succeed({ access_token: "token-new" }));
  http.session
    .mockReset()
    .mockImplementation(() =>
      Effect.succeed({ authenticated: true, scopes: [...AuthStandardClientScopes] }),
    );
  const open = new Set<string>();
  const forward = { answers: true };
  let sessions = 0;
  const native = {
    readConfig: vi.fn(async () => CONFIG),
    connect: vi.fn(async (_hops: unknown): Promise<SshConnectResult> => {
      if (options.connect) return options.connect();
      const sessionId = `session-${++sessions}`;
      open.add(sessionId);
      return { status: "connected", sessionId };
    }),
    exec: vi.fn(async (_id: string, command: string, _stdin: string, _timeoutMs: number) =>
      command.startsWith("sh -l -s")
        ? { exitCode: 0, stdout: 'motd\n{"remotePort":3777,"serverKind":"external"}\n', stderr: "" }
        : { exitCode: 0, stdout: '{"credential":"pairing-1"}\n', stderr: "" },
    ),
    forward: vi.fn(async (_id: string, _remotePort: number) => 41001),
    isOpen: (id: string) => open.has(id),
    close: vi.fn(async (id: string) => {
      open.delete(id);
    }),
    trustHostKey: vi.fn(async () => undefined),
  };
  const gateway = makeSshGateway({
    native: native as typeof native & SshNative,
    // Only the reuse probe goes through the client; the auth helpers are mocked above.
    httpClient: HttpClient.make((request) =>
      Effect.sync(() =>
        HttpClientResponse.fromWeb(request, new Response("", { status: forward.answers ? 200 : 503 })),
      ),
    ),
    clientMetadata: { label: "Phone", os: "Android" },
    sha256Hex,
  });
  return { native, open, forward, gateway };
}

describe("mobile SSH gateway", () => {
  it.effect("starts the server, forwards its port and pairs through the forward", () =>
    Effect.gen(function* () {
      const { native, gateway } = setup();
      const ssh = yield* gateway;

      const provisioned = yield* ssh.provision(TARGET);

      const stateKey = (yield* Effect.promise(() => sha256Hex(targetConnectionKey(TARGET)))).slice(
        0,
        16,
      );
      expect(native.connect.mock.calls[0]?.[0]).toEqual([
        { host: "jump.example", port: 22, user: "me", hostKeyAlias: null },
        { host: "127.0.0.1", port: 2222, user: "dev", hostKeyAlias: null },
      ]);
      expect(native.exec.mock.calls.map((call) => call[1])).toEqual([
        `sh -l -s -- ${stateKey}`,
        "sh -s",
      ]);
      expect(native.forward).toHaveBeenCalledWith("session-1", 3777);
      expect(http.exchange).toHaveBeenCalledWith(
        expect.objectContaining({
          httpBaseUrl: "http://127.0.0.1:41001/",
          credential: "pairing-1",
        }),
      );
      expect(provisioned).toMatchObject({
        environmentId: ENVIRONMENT,
        bearerToken: "token-new",
        bootstrap: {
          wsBaseUrl: "ws://127.0.0.1:41001/",
          remotePort: 3777,
          remoteServerKind: "external",
        },
      });
    }),
  );

  it.effect("reuses the tunnel and a still-granted token without pairing again", () =>
    Effect.gen(function* () {
      const { native, gateway } = setup();
      const ssh = yield* gateway;
      yield* ssh.provision(TARGET);
      native.exec.mockClear();

      const prepared = yield* ssh.prepare({
        connectionId: "ssh:env-box",
        expectedEnvironmentId: ENVIRONMENT,
        target: TARGET,
        bearerToken: "token-saved",
      });

      expect(prepared.bearerToken).toBe("token-saved");
      expect(native.connect).toHaveBeenCalledTimes(1);
      expect(native.exec).not.toHaveBeenCalled();
    }),
  );

  it.effect("pairs again when the saved token lost a standard scope", () =>
    Effect.gen(function* () {
      const { native, gateway } = setup();
      const ssh = yield* gateway;
      http.session.mockImplementation(() => Effect.succeed({ authenticated: true, scopes: [] }));

      const prepared = yield* ssh.prepare({
        connectionId: "ssh:env-box",
        expectedEnvironmentId: ENVIRONMENT,
        target: TARGET,
        bearerToken: "token-old",
      });

      expect(prepared.bearerToken).toBe("token-new");
      expect(native.exec.mock.calls.map((call) => call[1])).toContain("sh -s");
    }),
  );

  it.effect("blocks on an untrusted host key instead of trusting it in the background", () =>
    Effect.gen(function* () {
      const { native, gateway } = setup({
        connect: () => ({
          status: "host-key-rejected",
          host: "jump.example",
          port: 22,
          knownHostsName: "jump.example",
          keyType: "ssh-ed25519",
          fingerprint: "SHA256:x",
          knownHostsLine: "jump.example ssh-ed25519 AAAA",
          changed: true,
        }),
      });
      const ssh = yield* gateway;

      const error = yield* Effect.flip(
        ssh.prepare({
          connectionId: "c",
          expectedEnvironmentId: ENVIRONMENT,
          target: TARGET,
          bearerToken: "t",
        }),
      );

      expect(error).toMatchObject({ _tag: "ConnectionBlockedError", reason: "authentication" });
      expect(native.trustHostKey).not.toHaveBeenCalled();
    }),
  );

  it.effect("starts over after a failure instead of reusing a forward to a dead port", () =>
    Effect.gen(function* () {
      const { native, gateway } = setup();
      const ssh = yield* gateway;
      yield* ssh.provision(TARGET);
      http.descriptor.mockImplementationOnce(() =>
        Effect.fail({ _tag: "RemoteEnvironmentAuthFetchError", message: "connection refused" }),
      );
      const input = {
        connectionId: "c",
        expectedEnvironmentId: ENVIRONMENT,
        target: TARGET,
        bearerToken: "t",
      };

      const error = yield* Effect.flip(ssh.prepare(input));
      expect(error).toMatchObject({ _tag: "ConnectionTransientError", reason: "network" });
      expect(native.close).toHaveBeenCalledWith("session-1");

      yield* ssh.prepare(input);
      expect(native.connect).toHaveBeenCalledTimes(2);
    }),
  );

  it.effect("replaces a session that died between attempts", () =>
    Effect.gen(function* () {
      const { native, open, gateway } = setup();
      const ssh = yield* gateway;
      yield* ssh.provision(TARGET);
      open.clear();

      yield* ssh.prepare({
        connectionId: "c",
        expectedEnvironmentId: ENVIRONMENT,
        target: TARGET,
        bearerToken: "t",
      });

      expect(native.connect).toHaveBeenCalledTimes(2);
      expect(native.forward).toHaveBeenLastCalledWith("session-2", 3777);
    }),
  );

  it.effect("replaces a tunnel whose forward stopped answering", () =>
    Effect.gen(function* () {
      const { native, forward, gateway } = setup();
      const ssh = yield* gateway;
      yield* ssh.provision(TARGET);
      forward.answers = false;

      const preparing = yield* Effect.forkChild(
        ssh.prepare({
          connectionId: "c",
          expectedEnvironmentId: ENVIRONMENT,
          target: TARGET,
          bearerToken: "t",
        }),
      );
      // The reuse probe gives up after its budget, then the gateway reconnects.
      yield* TestClock.adjust("3 seconds");
      yield* Fiber.join(preparing);

      expect(native.close).toHaveBeenCalledWith("session-1");
      expect(native.connect).toHaveBeenCalledTimes(2);
    }),
  );

  it.effect("refuses a host that turns out to be a different environment, before pairing", () =>
    Effect.gen(function* () {
      const { gateway } = setup();
      const ssh = yield* gateway;
      http.descriptor.mockImplementation(() =>
        Effect.succeed({ environmentId: EnvironmentId.make("env-other"), label: "other" }),
      );

      const error = yield* Effect.flip(ssh.provision(TARGET, ENVIRONMENT));

      expect(error).toMatchObject({ _tag: "ConnectionBlockedError", reason: "configuration" });
      expect(http.exchange).not.toHaveBeenCalled();
    }),
  );

  it.effect("explains a key the host does not accept", () =>
    Effect.gen(function* () {
      const { native, gateway } = setup();
      native.connect.mockRejectedValueOnce(
        Object.assign(new Error("auth"), { code: "ERR_SSH_AUTH" }),
      );
      const ssh = yield* gateway;

      const error = yield* Effect.flip(ssh.provision(TARGET));

      expect(error).toMatchObject({ _tag: "ConnectionBlockedError", reason: "authentication" });
    }),
  );

  it.effect("disconnect closes the session", () =>
    Effect.gen(function* () {
      const { native, gateway } = setup();
      const ssh = yield* gateway;
      yield* ssh.provision(TARGET);

      yield* ssh.disconnect(TARGET);

      expect(native.close).toHaveBeenCalledWith("session-1");
    }),
  );
});
