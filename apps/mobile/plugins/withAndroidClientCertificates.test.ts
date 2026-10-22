import * as NodeModule from "node:module";
import { describe, expect, it } from "vite-plus/test";

const require = NodeModule.createRequire(import.meta.url);
const { installCertificateTransport } = require("./withAndroidClientCertificates.cjs") as {
  installCertificateTransport(source: string): string;
};
const install = "expo.modules.t3clientcertificates.T3CertificateTransport.install(this)";
const template = `class MainApplication : Application(), ReactApplication {
  override fun onCreate() {
    super.onCreate()
    loadReactNative(this)
    ApplicationLifecycleDispatcher.onApplicationCreate(this)
  }
}`;

describe("Android certificate startup prebuild", () => {
  it("installs before React Native and Expo lifecycle initialize their HTTP clients", () => {
    expect(installCertificateTransport(template)).toBe(
      template.replace("super.onCreate()", `super.onCreate()\n    ${install}`),
    );
  });

  it("is idempotent across repeated prebuilds", () => {
    const generated = installCertificateTransport(template);
    expect(installCertificateTransport(generated)).toBe(generated);
  });

  it("preserves Windows line endings", () => {
    const generated = installCertificateTransport(template.replaceAll("\n", "\r\n"));
    expect(generated).toContain(`super.onCreate()\r\n    ${install}\r\n`);
    expect(installCertificateTransport(generated)).toBe(generated);
  });

  it("ignores super.onCreate references outside the lifecycle body", () => {
    const prefix = "// super.onCreate() is required by Android\n";
    expect(installCertificateTransport(prefix + template)).toBe(
      prefix + installCertificateTransport(template),
    );
  });

  it.each([
    "class MainApplication {}",
    template.replace("super.onCreate()", "initializeNetworking()\n    super.onCreate()"),
    template + template,
  ])("rejects an incompatible startup template instead of silently missing hooks", (source) => {
    expect(() => installCertificateTransport(source)).toThrow(
      "Cannot install client certificates before React Native startup",
    );
  });

  it.each([
    template.replace("loadReactNative(this)", `loadReactNative(this)\n    ${install}`),
    template.replace("super.onCreate()", `super.onCreate()\n    ${install}\n    ${install}`),
  ])("rejects a misplaced or duplicated existing install", (source) => {
    expect(() => installCertificateTransport(source)).toThrow(
      "Client certificate transport must be installed immediately after super.onCreate()",
    );
  });
});
