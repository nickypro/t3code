// Writes the scripts T3ServerEndToEndTest runs, exactly as the app builds them.
// Usage (from apps/mobile): node modules/t3-ssh/e2e/write-remote-scripts.ts <dir> <t3 version>
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";

import {
  buildRemoteLaunchScript,
  buildRemotePairingScript,
  buildRemoteStopScript,
} from "@t3tools/ssh/remoteScripts";

const [outDir, archiveVersion] = process.argv.slice(2);
if (!outDir || !archiveVersion) {
  console.error("usage: write-remote-scripts.ts <dir> <t3 version>");
  process.exit(2);
}
const stateKey = "0123456789abcdef";
const runner = { archiveVersion };
NodeFS.mkdirSync(outDir, { recursive: true });
NodeFS.writeFileSync(NodePath.join(outDir, "state-key"), stateKey);
NodeFS.writeFileSync(NodePath.join(outDir, "launch.sh"), buildRemoteLaunchScript(runner));
NodeFS.writeFileSync(
  NodePath.join(outDir, "pairing.sh"),
  buildRemotePairingScript(stateKey, runner),
);
NodeFS.writeFileSync(NodePath.join(outDir, "stop.sh"), buildRemoteStopScript(stateKey));
