/**
 * Electron Preload Script
 * Securely exposes IPC and some Node APIs to the renderer process
 */

const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // App information
  getAppVersion: () => ipcRenderer.invoke('get-app-version'),
  
  // Settings
  getSettings: () => ipcRenderer.invoke('get-settings'),
  updateSettings: (settings) => ipcRenderer.invoke('update-settings', settings),
  
  // Backend control
  restartBackend: (interface_) => ipcRenderer.invoke('restart-backend', interface_),
  
  // Notifications
  showNotification: (title, body) => ipcRenderer.invoke('show-notification', { title, body }),
  
  // Listen for navigation from main process
  onNavigate: (callback) => ipcRenderer.on('navigate', (event, path) => callback(path)),
  onExportReport: (callback) => ipcRenderer.on('export-report', (event, format) => callback(format)),
  onStartMonitoring: (callback) => ipcRenderer.on('start-monitoring', () => callback()),
  onStopMonitoring: (callback) => ipcRenderer.on('stop-monitoring', () => callback()),
  onScanNetwork: (callback) => ipcRenderer.on('scan-network', () => callback()),
  
  // Remove listeners
  removeNavigateListener: () => ipcRenderer.removeAllListeners('navigate'),
});

// Expose some Node APIs safely
contextBridge.exposeInMainWorld('nodeAPI', {
  platform: process.platform,
  isDev: process.env.NODE_ENV === 'development',
  env: {
    VITE_BACKEND_URL: process.env.VITE_BACKEND_URL || 'http://localhost:5000'
  }
});
