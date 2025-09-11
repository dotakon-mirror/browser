import { useState } from "react";

import { useAsyncEffect } from "./Utilities";

export const App = () => {
  const [address, setAddress] = useState<string | null>(null);
  useAsyncEffect(async () => {
    if (address === null) {
      setAddress(await window.dotakon.deriveWallet());
    }
  }, [address]);
  return (
    <>
      <h1 className="text-3xl font-bold underline">💖 Hello World!</h1>
      <p>Welcome to your Electron application, {address}.</p>
    </>
  );
};
