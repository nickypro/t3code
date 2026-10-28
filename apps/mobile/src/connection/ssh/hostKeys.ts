import type { SshHop, SshHostKeyRejection, SshNative } from "./native";

export class SshHostKeyChangedError extends Error {
  constructor(readonly rejection: SshHostKeyRejection) {
    super(
      `The SSH host key for ${rejection.knownHostsName} changed. If that is expected, remove the old key in Settings > SSH and try again.`,
    );
  }
}

/**
 * Connects once to check every hop's host key, asking before trusting one it has not seen.
 * A key that differs from the trusted one is never offered for trust here. Resolves false if
 * the user declines; signing in with the device key happens on the same connection, so a key
 * the host does not accept rejects with `ERR_SSH_AUTH`.
 */
export async function reviewHostKeys(
  native: SshNative,
  hops: ReadonlyArray<SshHop>,
  confirmTrust: (rejection: SshHostKeyRejection) => Promise<boolean>,
): Promise<boolean> {
  // Each pass gets one hop further, so this is bounded by the number of hops.
  for (let pass = 0; pass <= hops.length; pass++) {
    const result = await native.connect(hops);
    if (result.status === "connected") {
      await native.close(result.sessionId);
      return true;
    }
    if (result.changed) throw new SshHostKeyChangedError(result);
    if (!(await confirmTrust(result))) return false;
    await native.trustHostKey(result.knownHostsLine);
  }
  throw new Error("The SSH host keys did not settle; try again.");
}
