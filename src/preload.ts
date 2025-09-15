import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("dotakon", {
  deriveWallet: () => ipcRenderer.invoke("wallet"),
});

contextBridge.exposeInMainWorld("__dirname", __dirname);
