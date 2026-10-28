import type { DesktopSshEnvironmentTarget } from "@t3tools/contracts";

import type { SshHop } from "./native";

/**
 * The part of ssh_config(5) the app understands: literal `Host` blocks with HostName, User,
 * Port, ProxyJump and HostKeyAlias. As in OpenSSH, the first value found for a setting wins.
 * Anything else is ignored, and the settings that would change where a connection goes are
 * reported so the user is not surprised.
 */
export interface SshConfigHost {
  readonly alias: string;
  readonly hostname: string | null;
  readonly user: string | null;
  readonly port: number | null;
  readonly proxyJump: ReadonlyArray<string> | null;
  readonly hostKeyAlias: string | null;
}

export interface SshConfig {
  readonly hosts: ReadonlyArray<SshConfigHost>;
  readonly problems: ReadonlyArray<string>;
}

export interface ResolvedSshHost {
  readonly hops: ReadonlyArray<SshHop>;
  readonly target: DesktopSshEnvironmentTarget;
}

const MAX_HOPS = 8;
const UNSUPPORTED = new Map([
  ["match", "Match blocks are not supported; their settings are ignored."],
  ["include", "Include is not supported."],
  ["proxycommand", "ProxyCommand is not supported; use ProxyJump."],
]);

type MutableHost = { -readonly [K in keyof SshConfigHost]: SshConfigHost[K] };

export function parseSshConfig(text: string): SshConfig {
  const hosts = new Map<string, MutableHost>();
  const problems: string[] = [];
  // null while outside a literal Host block (before the first one, or in `Host *` / Match).
  let current: MutableHost[] | null = null;

  for (const [index, raw] of text.split(/\r?\n/u).entries()) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const match = /^(\S+?)(?:\s*=\s*|\s+)(.*)$/u.exec(line);
    const keyword = (match?.[1] ?? line).toLowerCase();
    const value = (match?.[2] ?? "").trim();
    const where = `Line ${index + 1}`;

    if (keyword === "host") {
      const names = value.split(/\s+/u).filter((name) => name !== "");
      const literal = names.filter((name) => !/[*?!]/u.test(name));
      if (literal.length < names.length) {
        problems.push(`${where}: patterns like "${names.join(" ")}" are ignored; name each host.`);
      }
      current = literal.map((alias) => {
        const existing = hosts.get(alias);
        if (existing) return existing;
        const created: MutableHost = {
          alias,
          hostname: null,
          user: null,
          port: null,
          proxyJump: null,
          hostKeyAlias: null,
        };
        hosts.set(alias, created);
        return created;
      });
      continue;
    }
    const unsupported = UNSUPPORTED.get(keyword);
    if (unsupported !== undefined) {
      problems.push(`${where}: ${unsupported}`);
      if (keyword === "match") current = null;
      continue;
    }
    if (current === null) continue;
    for (const host of current) applySetting(host, keyword, value, where, problems);
  }
  return { hosts: [...hosts.values()], problems };
}

function applySetting(
  host: MutableHost,
  keyword: string,
  value: string,
  where: string,
  problems: string[],
) {
  switch (keyword) {
    case "hostname":
      host.hostname ??= value;
      return;
    case "user":
      host.user ??= value;
      return;
    case "hostkeyalias":
      host.hostKeyAlias ??= value;
      return;
    case "port": {
      const port = Number(value);
      if (!Number.isInteger(port) || port < 1 || port > 65_535) {
        problems.push(`${where}: "${value}" is not a port.`);
        return;
      }
      host.port ??= port;
      return;
    }
    case "proxyjump":
      host.proxyJump ??=
        value.toLowerCase() === "none" ? [] : value.split(",").map((jump) => jump.trim());
      return;
  }
}

/** The hops to reach `alias`, jump hosts first, following each jump host's own ProxyJump. */
export function resolveSshHost(config: SshConfig, alias: string): ResolvedSshHost {
  const byAlias = new Map(config.hosts.map((host) => [host.alias, host]));
  const hops: SshHop[] = [];

  const visit = (name: string, chain: ReadonlyArray<string>) => {
    if (chain.includes(name)) {
      throw new Error(`ProxyJump loops back to ${name}.`);
    }
    const host = byAlias.get(name) ?? literalHost(name);
    for (const jump of host.proxyJump ?? []) visit(jump, [...chain, name]);
    if (hops.length >= MAX_HOPS) throw new Error(`${alias} needs more than ${MAX_HOPS} hops.`);
    if (host.user === null || host.user === "") {
      throw new Error(`Add a User line for ${host.alias}.`);
    }
    hops.push({
      host: host.hostname ?? host.alias,
      port: host.port ?? 22,
      user: host.user,
      hostKeyAlias: host.hostKeyAlias,
    });
  };

  if (!byAlias.has(alias)) throw new Error(`No Host ${alias} in the SSH config.`);
  visit(alias, []);
  const last = hops[hops.length - 1];
  if (last === undefined) throw new Error(`No Host ${alias} in the SSH config.`);
  return {
    hops,
    target: { alias, hostname: last.host, username: last.user, port: last.port },
  };
}

/** A ProxyJump entry that names no Host block: `[user@]host[:port]`, IPv6 in brackets. */
function literalHost(spec: string): SshConfigHost {
  const match = /^(?:([^@]+)@)?(?:\[([^\]]+)\]|([^:]+))(?::(\d+))?$/u.exec(spec);
  if (match === null)
    throw new Error(`"${spec}" is neither a Host in the config nor user@host:port.`);
  const port = match[4] === undefined ? null : Number(match[4]);
  return {
    alias: spec,
    hostname: match[2] ?? match[3] ?? spec,
    user: match[1] ?? null,
    port,
    proxyJump: null,
    hostKeyAlias: null,
  };
}
