/**
 * Electron Preload Script
 * Securely exposes IPC and some Node APIs to the renderer process
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  getAppVersion: () => ipcRenderer.invoke('get-app-version'),

  getSettings: () => ipcRenderer.invoke('get-settings'),
  updateSettings: (settings) => ipcRenderer.invoke('update-settings', settings),

  restartBackend: (interface_) => ipcRenderer.invoke('restart-backend', interface_),

  showNotification: (title, body) => ipcRenderer.invoke('show-notification', { title, body }),

  checkForUpdates: () => ipcRenderer.invoke('check-for-updates'),

  getBackendStatus: () => ipcRenderer.invoke('get-backend-status'),

  sendSecurityAlert: (alert) => ipcRenderer.send('security-alert', alert),

  onNavigate: (callback) => ipcRenderer.on('navigate', (event, path) => callback(path)),
  onDeepNavigate: (callback) => ipcRenderer.on('deep-navigate', (event, data) => callback(data)),
  onExportReport: (callback) => ipcRenderer.on('export-report', (event, format) => callback(format)),
  onStartMonitoring: (callback) => ipcRenderer.on('start-monitoring', () => callback()),
  onStopMonitoring: (callback) => ipcRenderer.on('stop-monitoring', () => callback()),
  onScanNetwork: (callback) => ipcRenderer.on('scan-network', () => callback()),
  onClearAlerts: (callback) => ipcRenderer.on('clear-alerts', () => callback()),

  removeNavigateListener: () => ipcRenderer.removeAllListeners('navigate'),
  removeDeepNavigateListener: () => ipcRenderer.removeAllListeners('deep-navigate'),
});

contextBridge.exposeInMainWorld('nodeAPI', {
  platform: process.platform,
  isDev: process.env.NODE_ENV === 'development',
  env: {
    VITE_BACKEND_URL: process.env.VITE_BACKEND_URL || 'http://localhost:5000'
  }
});
