export interface ClientCertificateSubscription {
  remove(): void;
}

export interface ClientCertificateTransferInput {
  readonly url: string;
  readonly fileUri: string;
  readonly upload?: boolean;
  readonly contentType?: string;
  readonly signal: AbortSignal;
  readonly onProgress?: (progress: number) => void;
}
