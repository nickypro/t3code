import {
  bootstrapRemoteBearerSession,
  fetchRemoteSessionState,
} from "@t3tools/client-runtime/authorization";
import {
  ConnectionBlockedError,
  ConnectionTransientError,
  mapRemoteEnvironmentError,
  sshTargetKey,
} from "@t3tools/client-runtime/connection";
import { fetchRemoteEnvironmentDescriptor } from "@t3tools/client-runtime/environment";
import { ClientCapabilities } from "@t3tools/client-runtime/platform";
import {
  type AuthClientPresentationMetadata,
  AuthStandardClientScopes,
  type DesktopSshEnvironmentBootstrap,
  type DesktopSshEnvironmentTarget,
  type EnvironmentId,
} from "@t3tools/contracts";
import { waitForHttpReady } from "@t3tools/shared/httpReadiness";
import * as KeyedLock from "@t3tools/shared/KeyedLock";
import {
  buildRemoteLaunchScript,
  buildRemotePairingScript,
  decodeRemoteLaunchOutput,
  decodeRemotePairingOutput,
  REMOTE_ARCHIVE_LAUNCH_TIMEOUT_MS,
  targetConnectionKey,
} from "@t3tools/ssh/remoteScripts";
import * as Effect from "effect/Effect";
import { HttpClient } from "effect/http";

import { type SshNative, sshErrorCode, sshFailureMessage } from "./native";
import { parseSshConfig, resolveSshHost } from "./sshConfig";

/**
 * The t3 release a host is given when it has no server running yet. The desktop passes its
 * own version here; keep this in step with the server version this build is paired with.
 */
export const REMOTE_T3_VERSION = "0.1.2";

export interface SshGatewayDependencies {
  readonly native: SshNative;
  readonly httpClient: HttpClient.HttpClient;
  readonly clientMetadata: AuthClientPresentationMetadata;
  readonly sha256Hex: (text: string) => Promise<string>;
}

interface Tunnel {
  readonly sessionId: string;
  readonly stateKey: string;
  readonly httpBaseUrl: string;
  readonly wsBaseUrl: string;
  readonly remotePort: number;
  readonly remoteServerKind: "external" | "managed" | undefined;
}

const runner = { archiveVersion: REMOTE_T3_VERSION };

// A forward can outlive its server, or a frozen app's connection, and still look open. As on
// the desktop, a reused one must answer within this before it is trusted.
const REUSE_PROBE_TIMEOUT_MS = 2_000;

const answers = (httpBaseUrl: string) =>
  waitForHttpReady({
    baseUrl: httpBaseUrl,
    timeoutMs: REUSE_PROBE_TIMEOUT_MS,
    makeError: () => "unanswered" as const,
  }).pipe(
    Effect.as(true),
    Effect.catch(() => Effect.succeed(false)),
  );

/**
 * The desktop's SSH environment flow, over the app's own SSH connection: run the launch
 * script, forward its port to this device's loopback, and pair through the forward. Host keys
 * are trusted only from Settings or while adding the host, never during a reconnect.
 */
export const makeSshGateway = Effect.fn("mobile.ssh.makeGateway")(function* (
  deps: SshGatewayDependencies,
) {
  const { native } = deps;
  const tunnels = new Map<string, Tunnel>();
  const locks = yield* KeyedLock.make<string>();

  const call = <A>(operation: () => Promise<A>) =>
    Effect.tryPromise({ try: operation, catch: nativeError });

  const dropTunnel = (key: string) =>
    Effect.suspend(() => {
      const tunnel = tunnels.get(key);
      tunnels.delete(key);
      return tunnel === undefined
        ? Effect.void
        : Effect.promise(() => native.close(tunnel.sessionId).catch(() => undefined));
    });

  const openTunnel = Effect.fn("mobile.ssh.openTunnel")(function* (
    target: DesktopSshEnvironmentTarget,
  ) {
    const configText = yield* call(() => native.readConfig());
    const resolved = yield* Effect.try({
      try: () => resolveSshHost(parseSshConfig(configText), target.alias),
      catch: (cause) =>
        new ConnectionBlockedError({
          reason: "configuration",
          detail: cause instanceof Error ? cause.message : String(cause),
        }),
    });
    const connected = yield* call(() => native.connect(resolved.hops));
    if (connected.status === "host-key-rejected") {
      return yield* new ConnectionBlockedError({
        reason: "authentication",
        detail: connected.changed
          ? `The SSH host key for ${connected.knownHostsName} changed. If that is expected, remove the old key in Settings > SSH, then add the environment again.`
          : `${connected.knownHostsName} is not trusted yet. Add the environment again to review its SSH host key.`,
        hop: "tunnel",
      });
    }
    const sessionId = connected.sessionId;
    return yield* Effect.gen(function* () {
      const stateKey = (yield* call(() => deps.sha256Hex(targetConnectionKey(target)))).slice(
        0,
        16,
      );
      const launch = yield* call(() =>
        native.exec(
          sessionId,
          `sh -l -s -- ${stateKey}`,
          buildRemoteLaunchScript(runner),
          REMOTE_ARCHIVE_LAUNCH_TIMEOUT_MS,
        ),
      );
      if (launch.exitCode !== 0) {
        return yield* remoteFailure("start T3 Code on the host", launch.stderr);
      }
      const started = yield* decodeRemoteLaunchOutput(launch.stdout).pipe(
        Effect.mapError(() => remoteFailureError("start T3 Code on the host", launch.stdout)),
      );
      const localPort = yield* call(() => native.forward(sessionId, started.remotePort));
      return {
        sessionId,
        stateKey,
        httpBaseUrl: `http://127.0.0.1:${localPort}/`,
        wsBaseUrl: `ws://127.0.0.1:${localPort}/`,
        remotePort: started.remotePort,
        remoteServerKind: started.serverKind,
      } satisfies Tunnel;
    }).pipe(
      Effect.onError(() => Effect.promise(() => native.close(sessionId).catch(() => undefined))),
    );
  });

  const ensure = (target: DesktopSshEnvironmentTarget, options: { issuePairingToken: boolean }) => {
    const key = sshTargetKey(target);
    return locks.withLock(
      key,
      Effect.gen(function* () {
        let tunnel = tunnels.get(key);
        if (
          tunnel !== undefined &&
          !(native.isOpen(tunnel.sessionId) && (yield* answers(tunnel.httpBaseUrl)))
        ) {
          yield* dropTunnel(key);
          tunnel = undefined;
        }
        if (tunnel === undefined) {
          tunnel = yield* openTunnel(target);
          tunnels.set(key, tunnel);
        }
        let pairingToken: string | null = null;
        if (options.issuePairingToken) {
          const { sessionId, stateKey } = tunnel;
          const pairing = yield* call(() =>
            native.exec(
              sessionId,
              "sh -s",
              buildRemotePairingScript(stateKey, runner),
              REMOTE_ARCHIVE_LAUNCH_TIMEOUT_MS,
            ),
          );
          if (pairing.exitCode !== 0) {
            return yield* remoteFailure("issue a pairing credential", pairing.stderr);
          }
          pairingToken = (yield* decodeRemotePairingOutput(pairing.stdout).pipe(
            Effect.mapError(() => remoteFailureError("issue a pairing credential", pairing.stdout)),
          )).credential;
        }
        return {
          target,
          httpBaseUrl: tunnel.httpBaseUrl,
          wsBaseUrl: tunnel.wsBaseUrl,
          pairingToken,
          remotePort: tunnel.remotePort,
          ...(tunnel.remoteServerKind === undefined
            ? {}
            : { remoteServerKind: tunnel.remoteServerKind }),
        } satisfies DesktopSshEnvironmentBootstrap;
      }),
    );
  };

  const describe = Effect.fn("mobile.ssh.describe")(function* (
    httpBaseUrl: string,
    target: DesktopSshEnvironmentTarget,
    expected?: EnvironmentId,
  ) {
    const descriptor = yield* fetchRemoteEnvironmentDescriptor({ httpBaseUrl }).pipe(
      Effect.mapError((error) => mapRemoteEnvironmentError(error)),
    );
    if (expected !== undefined && descriptor.environmentId !== expected) {
      return yield* new ConnectionBlockedError({
        reason: "configuration",
        detail: `${target.alias} reaches ${descriptor.label}, a different machine. Add it as its own environment instead.`,
      });
    }
    return descriptor;
  });

  const provision = Effect.fn("mobile.ssh.provision")(function* (
    target: DesktopSshEnvironmentTarget,
    expectedEnvironmentId?: EnvironmentId,
  ) {
    const bootstrap = yield* ensure(target, { issuePairingToken: true });
    const credential = bootstrap.pairingToken;
    if (credential === null) {
      return yield* remoteFailure("issue a pairing credential", "");
    }
    const descriptor = yield* describe(bootstrap.httpBaseUrl, target, expectedEnvironmentId);
    const access = yield* bootstrapRemoteBearerSession({
      httpBaseUrl: bootstrap.httpBaseUrl,
      credential,
      clientMetadata: deps.clientMetadata,
    }).pipe(Effect.mapError((error) => mapRemoteEnvironmentError(error)));
    return {
      environmentId: descriptor.environmentId,
      label: descriptor.label,
      bootstrap,
      bearerToken: access.access_token,
    };
  });

  // Every pairing adds a session on the host, so a saved token is kept while the host still
  // grants it every standard scope.
  const prepare = Effect.fn("mobile.ssh.prepare")(function* (input: {
    readonly connectionId: string;
    readonly expectedEnvironmentId: EnvironmentId;
    readonly target: DesktopSshEnvironmentTarget;
    readonly bearerToken?: string;
  }) {
    const bearerToken = input.bearerToken;
    if (bearerToken !== undefined) {
      const bootstrap = yield* ensure(input.target, { issuePairingToken: false });
      yield* describe(bootstrap.httpBaseUrl, input.target, input.expectedEnvironmentId);
      const session = yield* fetchRemoteSessionState({
        httpBaseUrl: bootstrap.httpBaseUrl,
        bearerToken,
      }).pipe(Effect.mapError((error) => mapRemoteEnvironmentError(error)));
      const granted = session.permissions ?? session.scopes ?? [];
      if (
        session.authenticated &&
        AuthStandardClientScopes.every((scope) => granted.includes(scope))
      ) {
        return { bootstrap, bearerToken };
      }
    }
    const provisioned = yield* provision(input.target, input.expectedEnvironmentId);
    return { bootstrap: provisioned.bootstrap, bearerToken: provisioned.bearerToken };
  });

  // A failure after the tunnel opened may mean the host's server moved or stopped, so the next
  // attempt starts over instead of reusing a forward to a dead port.
  const resetOnFailure =
    (target: DesktopSshEnvironmentTarget) =>
    <A, E>(effect: Effect.Effect<A, E, HttpClient.HttpClient>) =>
      effect.pipe(
        Effect.onError(() => dropTunnel(sshTargetKey(target))),
        Effect.provideService(HttpClient.HttpClient, deps.httpClient),
      );

  return ClientCapabilities.SshEnvironmentGateway.of({
    provision: (target, expectedEnvironmentId) =>
      provision(target, expectedEnvironmentId).pipe(resetOnFailure(target)),
    prepare: (input) => prepare(input).pipe(resetOnFailure(input.target)),
    disconnect: (target) => dropTunnel(sshTargetKey(target)),
  });
});

function nativeError(cause: unknown) {
  const message = cause instanceof Error ? cause.message : String(cause);
  switch (sshErrorCode(cause)) {
    case "ERR_SSH_AUTH":
      return new ConnectionBlockedError({
        reason: "authentication",
        detail: sshFailureMessage(cause),
        hop: "tunnel",
      });
    case "ERR_SSH_NO_KEY":
      return new ConnectionBlockedError({
        reason: "configuration",
        detail: sshFailureMessage(cause),
        hop: "device",
      });
    case "ERR_SSH_UNREACHABLE":
      return new ConnectionTransientError({ reason: "network", detail: message, hop: "tunnel" });
    default:
      return new ConnectionTransientError({
        reason: "remote-unavailable",
        detail: `Could not prepare the SSH environment: ${message}`,
        hop: "tunnel",
      });
  }
}

function remoteFailureError(action: string, output: string) {
  const tail = output.trim().split("\n").slice(-3).join("\n");
  return new ConnectionTransientError({
    reason: "remote-unavailable",
    detail: `Could not ${action}${tail === "" ? "." : `: ${tail}`}`,
    hop: "server",
  });
}

const remoteFailure = (action: string, output: string) =>
  Effect.fail(remoteFailureError(action, output));
