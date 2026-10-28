import * as Clipboard from "expo-clipboard";
import * as Haptics from "expo-haptics";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Share, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { AppText as Text, AppTextInput } from "../../components/ui/AppText";
import * as Dialog from "../../components/ui/Dialog";
import { ListActionRow } from "../../components/ui/ListActionRow";
import { ScreenScrollView as ScrollView } from "../../components/ui/ScreenScrollView";
import {
  type SshKnownHost,
  type SshNative,
  type SshPublicKey,
  sshFailureMessage,
  sshNative,
} from "../../connection/ssh/native";
import { parseSshConfig } from "../../connection/ssh/sshConfig";
import { SettingsSection } from "./components/SettingsSection";
import { SettingsScreen } from "./components/SettingsScreen";

const KEY_COMMENT = "t3code-android";
const CONFIG_PLACEHOLDER = "Host my-server\n  HostName server.example.com\n  User me";

export function SettingsSshRouteScreen() {
  const insets = useSafeAreaInsets();
  return (
    <SettingsScreen title="SSH">
      <ScrollView
        contentInsetAdjustmentBehavior="automatic"
        keyboardShouldPersistTaps="handled"
        showsVerticalScrollIndicator={false}
        className="flex-1"
        contentContainerClassName="gap-6 px-5 pt-4"
        contentContainerStyle={{ paddingBottom: Math.max(insets.bottom, 18) + 18 }}
      >
        {sshNative === null ? (
          <Text className="px-4 text-foreground-muted">SSH environments need the Android app.</Text>
        ) : (
          <SshSettings native={sshNative} />
        )}
      </ScrollView>
    </SettingsScreen>
  );
}

function SshSettings({ native }: { readonly native: SshNative }) {
  const [key, setKey] = useState<SshPublicKey | null>(null);
  const [savedConfig, setSavedConfig] = useState("");
  const [config, setConfig] = useState("");
  const [knownHosts, setKnownHosts] = useState<ReadonlyArray<SshKnownHost>>([]);
  const [busy, setBusy] = useState<"key" | "config" | null>(null);
  const problems = useMemo(() => parseSshConfig(config).problems, [config]);

  const run = useCallback(async (kind: "key" | "config" | null, action: () => Promise<void>) => {
    setBusy(kind);
    try {
      await action();
    } catch (error) {
      Dialog.alert("SSH", sshFailureMessage(error));
    } finally {
      setBusy(null);
    }
  }, []);

  useEffect(() => {
    let live = true;
    Promise.all([native.getPublicKey(), native.readConfig(), native.listKnownHosts()]).then(
      ([nextKey, nextConfig, nextHosts]) => {
        if (!live) return;
        setKey(nextKey);
        setSavedConfig(nextConfig);
        setConfig(nextConfig);
        setKnownHosts(nextHosts);
      },
      (error: unknown) => Dialog.alert("SSH", sshFailureMessage(error)),
    );
    return () => {
      live = false;
    };
  }, [native]);

  const createKey = () =>
    void run("key", async () => {
      setKey(await native.createKey(KEY_COMMENT));
    });

  const copyKey = (line: string) =>
    void run(null, async () => {
      await Clipboard.setStringAsync(line);
      void Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
    });

  const saveConfig = () =>
    void run("config", async () => {
      await native.writeConfig(config);
      setSavedConfig(config);
    });

  const forgetHost = (host: SshKnownHost) =>
    Dialog.confirm({
      title: `Remove ${host.names.join(", ")}?`,
      message: "You will be asked to check its key again on the next connection.",
      confirmText: "Remove",
      destructive: true,
      onConfirm: () =>
        void run(null, async () => {
          await native.forgetHostKey(host.line);
          setKnownHosts(await native.listKnownHosts());
        }),
    });

  return (
    <>
      <SettingsSection
        title="This device's key"
        footer={
          key === null
            ? "An ed25519 key that stays on this device and is never backed up."
            : "Add this line to ~/.ssh/authorized_keys on each host. It is the only key the app uses."
        }
      >
        {key === null ? (
          <ListActionRow
            icon="plus"
            label="Create SSH key"
            loading={busy === "key"}
            onPress={createKey}
          />
        ) : (
          <>
            <View collapsable={false} className="gap-1 px-4 py-3">
              <Text selectable className="font-mono text-xs text-foreground">
                {key.line}
              </Text>
              <Text className="text-xs text-foreground-muted">{key.fingerprint}</Text>
            </View>
            <View className="ml-4 border-t border-border-subtle" />
            <ListActionRow
              icon="doc.on.doc"
              label="Copy public key"
              onPress={() => copyKey(key.line)}
            />
            <ListActionRow
              icon="square.and.arrow.up"
              label="Share public key"
              onPress={() => void Share.share({ message: key.line })}
            />
            <ListActionRow
              icon="arrow.clockwise"
              label="Replace key"
              tone="danger"
              loading={busy === "key"}
              onPress={() =>
                Dialog.confirm({
                  title: "Replace this device's SSH key?",
                  message: "Hosts stop accepting this device until you add the new key to them.",
                  confirmText: "Replace",
                  destructive: true,
                  onConfirm: createKey,
                })
              }
            />
          </>
        )}
      </SettingsSection>

      <SettingsSection
        title="SSH config"
        footer="Uses Host, HostName, User, Port, ProxyJump and HostKeyAlias, as in ~/.ssh/config."
      >
        <AppTextInput
          accessibilityLabel="SSH config"
          multiline
          autoCapitalize="none"
          autoCorrect={false}
          spellCheck={false}
          textAlignVertical="top"
          placeholder={CONFIG_PLACEHOLDER}
          value={config}
          onChangeText={setConfig}
          className="min-h-40 rounded-none border-0 bg-transparent font-mono text-sm"
        />
        {problems.map((problem) => (
          <Text key={problem} className="px-4 pb-2 text-xs text-danger-foreground">
            {problem}
          </Text>
        ))}
        <View className="ml-4 border-t border-border-subtle" />
        <ListActionRow
          icon="checkmark.circle"
          label="Save config"
          disabled={config === savedConfig}
          loading={busy === "config"}
          onPress={saveConfig}
        />
      </SettingsSection>

      <SettingsSection
        title="Trusted host keys"
        footer="A host's key is added when you confirm it while adding an environment."
      >
        {knownHosts.length === 0 ? (
          <ListActionRow label="None yet" disabled onPress={() => undefined} />
        ) : (
          knownHosts.map((host) => (
            <ListActionRow
              key={host.line}
              icon="trash"
              label={host.names.join(", ")}
              description={`${host.keyType} ${host.fingerprint}`}
              onPress={() => forgetHost(host)}
            />
          ))
        )}
      </SettingsSection>
    </>
  );
}
