interface DotakonAPI {
  deriveWallet: () => Promise<string>;
}

interface Window {
  dotakon: DotakonAPI;
}
