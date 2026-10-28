import { requireOptionalNativeModule } from "expo";

export interface SshPublicKey {
  readonly line: string;
  readonly fingerprint: string;
}

export interface SshKnownHost {
  readonly line: string;
  readonly names: ReadonlyArray<string>;
  readonly keyType: string;
  readonly fingerprint: string;
}

export interface SshHop {
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly hostKeyAlias: string | null;
}

export interface SshHostKeyRejection {
  readonly status: "host-key-rejected";
  readonly host: string;
  readonly port: number;
  readonly knownHostsName: string;
  readonly keyType: string;
  readonly fingerprint: string;
  readonly knownHostsLine: string;
  /** known_hosts already holds a different key under this name. */
  readonly changed: boolean;
}

export type SshConnectResult =
  | { readonly status: "connected"; readonly sessionId: string }
  | SshHostKeyRejection;

export interface SshExecResult {
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

/** `modules/t3-ssh`. The private key stays native; failures reject with an `ERR_SSH_*` code. */
export interface SshNative {
  getPublicKey(): Promise<SshPublicKey | null>;
  createKey(comment: string): Promise<SshPublicKey>;
  deleteKey(): Promise<void>;
  readConfig(): Promise<string>;
  writeConfig(text: string): Promise<void>;
  listKnownHosts(): Promise<ReadonlyArray<SshKnownHost>>;
  trustHostKey(line: string): Promise<void>;
  forgetHostKey(line: string): Promise<void>;
  connect(hops: ReadonlyArray<SshHop>): Promise<SshConnectResult>;
  exec(
    sessionId: string,
    command: string,
    stdin: string,
    timeoutMs: number,
  ): Promise<SshExecResult>;
  forward(sessionId: string, remotePort: number): Promise<number>;
  isOpen(sessionId: string): boolean;
  close(sessionId: string): Promise<void>;
}

/** Null where the platform has no SSH module (iOS). */
export const sshNative = requireOptionalNativeModule<SshNative>("T3Ssh");

export function sshErrorCode(cause: unknown): string | null {
  return typeof cause === "object" &&
    cause !== null &&
    "code" in cause &&
    typeof cause.code === "string"
    ? cause.code
    : null;
}
