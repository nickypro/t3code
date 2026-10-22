import { useState, useSyncExternalStore } from "react";
import { Pressable, View } from "react-native";

import { SymbolView } from "../../components/ui/AppSymbol";
import { AppText as Text } from "../../components/ui/AppText";
import * as Dialog from "../../components/ui/Dialog";
import {
  chooseClientCertificate,
  clientCertificatesAvailable,
  onClientCertificateChange,
  removeClientCertificate,
  selectedClientCertificate,
} from "../../lib/clientCertificates";
import { buildPairingUrl } from "./pairing";

function subscribe(listener: () => void) {
  const subscription = onClientCertificateChange(listener);
  return () => subscription.remove();
}

export function ClientCertificateField(props: { host: string; disabled?: boolean }) {
  const endpoint = buildPairingUrl(props.host, "certificate-origin");
  const alias = useSyncExternalStore(
    subscribe,
    () => selectedClientCertificate(endpoint),
    () => null,
  );
  const [busy, setBusy] = useState(false);
  const [expanded, setExpanded] = useState(false);
  if (!clientCertificatesAvailable) return null;
  const act = (remove: boolean) => {
    setBusy(true);
    void (remove ? removeClientCertificate(endpoint) : chooseClientCertificate(endpoint))
      .catch((error: unknown) => {
        Dialog.alert(
          "Client certificate",
          error instanceof Error ? error.message : "Could not select certificate.",
        );
      })
      .finally(() => setBusy(false));
  };
  const disabled = busy || props.disabled || !props.host.trim();
  return (
    <View className="rounded-xl bg-foreground/5">
      <Pressable
        accessibilityRole="button"
        accessibilityState={{ expanded }}
        onPress={() => setExpanded((value) => !value)}
        className="flex-row items-center justify-between px-4 py-3"
      >
        <View className="gap-1">
          <Text className="text-sm text-foreground-muted">Advanced settings</Text>
          {alias ? (
            <Text className="text-xs text-foreground-muted">Certificate selected</Text>
          ) : null}
        </View>
        <SymbolView
          name={expanded ? "chevron.up" : "chevron.down"}
          size={16}
          tintColorClassName="accent-icon-muted"
        />
      </Pressable>
      {expanded ? (
        <View className="gap-2 px-4 pb-3">
          <Text className="text-2xs font-t3-bold uppercase text-foreground-muted">
            Client certificate (optional)
          </Text>
          <Text className="text-sm text-foreground-muted">
            {alias ?? "None selected"}. Applies to this HTTPS host and port, including other
            environments using the same address.
          </Text>
          <Pressable
            accessibilityRole="button"
            disabled={disabled}
            onPress={() => act(false)}
            className="rounded-xl bg-input px-4 py-3"
          >
            <Text className="text-foreground">
              {busy ? "Please wait…" : alias ? "Change certificate" : "Select certificate"}
            </Text>
          </Pressable>
          {alias ? (
            <Pressable
              accessibilityRole="button"
              disabled={disabled}
              onPress={() => act(true)}
              className="px-4 py-2"
            >
              <Text className="text-danger-foreground">Remove certificate</Text>
            </Pressable>
          ) : null}
        </View>
      ) : null}
    </View>
  );
}
