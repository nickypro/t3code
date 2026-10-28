import { describe, expect, it } from "vite-plus/test";

import { parseSshConfig, resolveSshHost } from "./sshConfig";

const BOX = `
# The research box: the host's sshd, then the container's on its loopback.
Host slop
  HostName slop.example
  User nicky

Host slop-box
  HostName 127.0.0.1
  Port 2222
  User dev
  HostKeyAlias slop-box
  ProxyJump slop
  ForwardAgent no
`;

describe("parseSshConfig / resolveSshHost", () => {
  it("resolves a ProxyJump chain, jump host first", () => {
    expect(resolveSshHost(parseSshConfig(BOX), "slop-box")).toEqual({
      hops: [
        { host: "slop.example", port: 22, user: "nicky", hostKeyAlias: null },
        { host: "127.0.0.1", port: 2222, user: "dev", hostKeyAlias: "slop-box" },
      ],
      target: { alias: "slop-box", hostname: "127.0.0.1", username: "dev", port: 2222 },
    });
  });

  it("follows a jump host's own ProxyJump and literal user@host:port jumps", () => {
    const config = parseSshConfig(`
Host inner
  User root
  ProxyJump outer,ops@[2001:db8::1]:2200
Host outer
  HostName outer.example
  User me
  ProxyJump gate@gate.example
`);

    expect(resolveSshHost(config, "inner").hops).toEqual([
      { host: "gate.example", port: 22, user: "gate", hostKeyAlias: null },
      { host: "outer.example", port: 22, user: "me", hostKeyAlias: null },
      { host: "2001:db8::1", port: 2200, user: "ops", hostKeyAlias: null },
      { host: "inner", port: 22, user: "root", hostKeyAlias: null },
    ]);
  });

  it("keeps the first value for a setting, as OpenSSH does", () => {
    const config = parseSshConfig(`
Host a b
  User first
Host a
  User second
  Port=2200
`);

    expect(resolveSshHost(config, "a").target).toEqual({
      alias: "a",
      hostname: "a",
      username: "first",
      port: 2200,
    });
    expect(resolveSshHost(config, "b").target.username).toBe("first");
  });

  it("ignores pattern and Match blocks and says so", () => {
    const config = parseSshConfig(`
Host *
  User everyone
Host box
  HostName box.example
Match host box
  User matched
`);

    expect(config.problems).toHaveLength(2);
    expect(() => resolveSshHost(config, "box")).toThrow("Add a User line for box.");
  });

  it("reports unusable configurations", () => {
    const config = parseSshConfig(`
Host loop-a
  User u
  ProxyJump loop-b
Host loop-b
  User u
  ProxyJump loop-a
Host bad-port
  User u
  Port 99999
  ProxyCommand nc %h %p
`);

    expect(() => resolveSshHost(config, "loop-a")).toThrow("ProxyJump loops back to loop-a.");
    expect(() => resolveSshHost(config, "missing")).toThrow("No Host missing in the SSH config.");
    expect(config.problems).toEqual([
      'Line 10: "99999" is not a port.',
      "Line 11: ProxyCommand is not supported; use ProxyJump.",
    ]);
  });

  it("treats ProxyJump none as a direct connection", () => {
    const config = parseSshConfig("Host direct\n  User u\n  ProxyJump none\n");

    expect(resolveSshHost(config, "direct").hops).toHaveLength(1);
  });
});
