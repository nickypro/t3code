import { useFocusEffect, useNavigation } from "@react-navigation/native";
import * as Cause from "effect/Cause";
import { AsyncResult } from "effect/reactivity";
import * as Haptics from "expo-haptics";
import { useCallback, useState } from "react";
import { View } from "react-native";

import { AppText as Text } from "../../components/ui/AppText";
import * as Dialog from "../../components/ui/Dialog";
import { ListActionRow } from "../../components/ui/ListActionRow";
import { connectSshEnvironment } from "../../connection/onboarding";
import { reviewHostKeys } from "../../connection/ssh/hostKeys";
import {
  type SshHostKeyRejection,
  type SshNative,
  sshFailureMessage,
  sshNative,
} from "../../connection/ssh/native";
import {
  parseSshConfig,
  resolveSshHost,
  type SshConfig,
  type SshConfigHost,
} from "../../connection/ssh/sshConfig";
import { useAtomCommand } from "../../state/use-atom-command";

/** Hosts from the app's SSH config, on platforms with the SSH module. */
export function SshEnvironmentSection(props: { readonly onConnected: () => void }) {
  return sshNative === null ? null : (
    <SshHosts native={sshNative} onConnected={props.onConnected} />
  );
}

function SshHosts(props: { readonly native: SshNative; readonly onConnected: () => void }) {
  const { native, onConnected } = props;
  const navigation = useNavigation();
  const connectSsh = useAtomCommand(connectSshEnvironment, { reportFailure: false });
  const [config, setConfig] = useState<SshConfig>({ hosts: [], problems: [] });
  const [hasKey, setHasKey] = useState(false);
  const [connecting, setConnecting] = useState<string | null>(null);

  // Settings > SSH may have changed the config or key while this screen was underneath.
  useFocusEffect(
    useCallback(() => {
      let live = true;
      void Promise.all([native.readConfig(), native.getPublicKey()]).then(([text, key]) => {
        if (!live) return;
        setConfig(parseSshConfig(text));
        setHasKey(key !== null);
      });
      return () => {
        live = false;
      };
    }, [native]),
  );

  const openSettings = () => navigation.navigate("SettingsSsh");

  const connect = async (alias: string) => {
    if (!hasKey) {
      Dialog.alert("Create an SSH key first", "Then add its public key to the host.", [
        { text: "Cancel", style: "cancel" },
        { text: "Open SSH settings", onPress: openSettings },
      ]);
      return;
    }
    setConnecting(alias);
    try {
      const resolved = resolveSshHost(config, alias);
      if (!(await reviewHostKeys(native, resolved.hops, confirmHostKey))) return;
      const result = await connectSsh({ target: resolved.target });
      void Haptics.notificationAsync(
        AsyncResult.isSuccess(result)
          ? Haptics.NotificationFeedbackType.Success
          : Haptics.NotificationFeedbackType.Error,
      );
      if (AsyncResult.isSuccess(result)) {
        onConnected();
      } else {
        Dialog.alert("Could not connect", sshFailureMessage(Cause.squash(result.cause)));
      }
    } catch (error) {
      void Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      Dialog.alert("Could not connect", sshFailureMessage(error));
    } finally {
      setConnecting(null);
    }
  };

  return (
    <View collapsable={false} className="gap-2">
      <Text className="px-4 text-sm font-t3-medium text-foreground-muted">Or connect over SSH</Text>
      <View className="overflow-hidden rounded-[26px] border-continuous bg-grouped-card">
        {config.hosts.map((host) => (
          <ListActionRow
            key={host.alias}
            icon="terminal"
            label={host.alias}
            description={describeHost(host)}
            loading={connecting === host.alias}
            disabled={connecting !== null}
            onPress={() => void connect(host.alias)}
          />
        ))}
        <ListActionRow
          icon="slider.horizontal.3"
          label={config.hosts.length === 0 ? "Set up SSH" : "SSH key and hosts"}
          disabled={connecting !== null}
          onPress={openSettings}
        />
      </View>
      <Text className="px-4 text-sm leading-normal text-foreground-muted">
        Starts T3 Code on the host if needed, using this device's own SSH key.
      </Text>
    </View>
  );
}

function describeHost(host: SshConfigHost): string {
  const port = host.port === null ? "" : `:${host.port}`;
  const via = host.proxyJump?.length ? ` via ${host.proxyJump.join(", ")}` : "";
  return `${host.user ?? "?"}@${host.hostname ?? host.alias}${port}${via}`;
}

function confirmHostKey(rejection: SshHostKeyRejection): Promise<boolean> {
  return new Promise((resolve) =>
    Dialog.confirm({
      title: `Trust ${rejection.knownHostsName}?`,
      message: `This is the first connection to this host. Its ${rejection.keyType} key fingerprint is\n\n${rejection.fingerprint}\n\nCheck it against ssh-keygen -lf on the host before trusting it.`,
      confirmText: "Trust",
      onConfirm: () => resolve(true),
      onCancel: () => resolve(false),
    }),
  );
}
