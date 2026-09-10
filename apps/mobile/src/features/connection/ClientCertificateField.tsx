import { useEffect, useState } from "react";
import { Alert, Pressable, View } from "react-native";

import { AppText as Text } from "../../components/AppText";
import { SymbolView } from "../../components/AppSymbol";
import {
  chooseClientCertificate,
  clientCertificatesAvailable,
  onClientCertificateChange,
  removeClientCertificate,
  selectedClientCertificate,
} from "../../lib/clientCertificates";
import { buildPairingUrl } from "./pairing";

export function ClientCertificateField(props: { host: string; disabled?: boolean }) {
  const endpoint = buildPairingUrl(props.host, "certificate-origin");
  const [alias, setAlias] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [expanded, setExpanded] = useState(false);
  useEffect(() => {
    const refresh = () => setAlias(selectedClientCertificate(endpoint));
    refresh();
    const subscription = onClientCertificateChange(refresh);
    return () => subscription.remove();
  }, [endpoint]);
  if (!clientCertificatesAvailable) return null;
  const act = async (remove: boolean) => {
    setBusy(true);
    try {
      if (remove) await removeClientCertificate(endpoint);
      else await chooseClientCertificate(endpoint);
      setAlias(selectedClientCertificate(endpoint));
    } catch (error) {
      Alert.alert(
        "Client certificate",
        error instanceof Error ? error.message : "Could not select certificate.",
      );
    } finally {
      setBusy(false);
    }
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
        <SymbolView name={expanded ? "chevron.up" : "chevron.down"} size={16} tintColor="#888888" />
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
            onPress={() => void act(false)}
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
              onPress={() => void act(true)}
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
