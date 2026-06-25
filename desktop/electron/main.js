/**
 * Packet Peeper - Electron Main Process
 * Handles window management, Python backend spawning, and system integration
 */

const { app, BrowserWindow, Menu, Tray, ipcMain, shell, dialog, nativeImage } = require('electron');
const { spawn, exec } = require('child_process');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const Store = require('electron-store');

// Configuration store for user preferences
const store = new Store({
  defaults: {
    windowBounds: { width: 1400, height: 900 },
    startMinimized: false,
    launchOnStartup: false,
    selectedInterface: 'auto',
    backendPort: 5000,
    frontendPort: 5173
  }
});

// Check if running in development
const isDev = !app.isPackaged;

// Global references
let mainWindow = null;
let tray = null;
let pythonProcess = null;
let isQuitting = false;

// Backend configuration
const BACKEND_PORT = store.get('backendPort');
const FRONTEND_PORT = store.get('frontendPort');

// Paths
const getBackendPath = () => {
  if (isDev) {
    return path.join(__dirname, '..', '..', 'backend');
  }
  return path.join(process.resourcesPath, 'backend');
};

const getBackendBinaryName = () => {
  return process.platform === 'win32' ? 'packet_peeper_backend.exe' : 'packet_peeper_backend';
};

const getBackendBinaryPath = () => {
  return path.join(getBackendPath(), getBackendBinaryName());
};

const getPythonPath = () => {
  return process.env.PACKET_PEEPER_PYTHON_PATH || (process.platform === 'win32' ? 'python' : 'python3');
};

const getJwtSecret = () => {
  let secret = store.get('jwtSecret');
  if (!secret) {
    secret = crypto.randomBytes(32).toString('hex');
    store.set('jwtSecret', secret);
  }
  return secret;
};

const buildBackendEnv = () => {
  const dataDir = app.getPath('userData');
  const baseEnv = {
    ...process.env,
    FLASK_PORT: BACKEND_PORT.toString(),
    PYTHONUNBUFFERED: '1',
    PACKET_PEEPER_DESKTOP: 'True',
    PACKET_PEEPER_DATA_DIR: dataDir,
    FEATURE_ELECTRON_DESKTOP: 'True',
    DB_ENGINE: 'sqlite',
    ENABLE_AUTH: 'True',
    JWT_SECRET: getJwtSecret(),
  };

  if (!isDev) {
    baseEnv.FLASK_ENV = 'production';
    baseEnv.FLASK_DEBUG = 'False';
  }

  return baseEnv;
};

const resolveBackendCommand = (interface_) => {
  const overridePath = process.env.PACKET_PEEPER_BACKEND_PATH;
  if (overridePath && fs.existsSync(overridePath)) {
    try { fs.chmodSync(overridePath, 0o755); } catch (e) { /* ignore */ }
    return { command: overridePath, args: [interface_], usesPython: false };
  }

  const binaryPath = getBackendBinaryPath();
  if (fs.existsSync(binaryPath)) {
    return { command: binaryPath, args: [interface_], usesPython: false };
  }

  return { command: getPythonPath(), args: ['app.py', interface_], usesPython: true };
};

const isElevated = () => {
  if (process.platform === 'win32') {
    return true;
  }
  if (typeof process.getuid !== 'function') {
    return false;
  }
  return process.getuid() === 0;
};

const getFrontendPath = () => {
  if (isDev) {
    return `http://localhost:${FRONTEND_PORT}`;
  }
  return path.join(process.resourcesPath, 'frontend', 'index.html');
};

const getAssetPath = (asset) => {
  return path.join(__dirname, 'assets', asset);
};

/**
 * Create the main application window
 */
function createWindow() {
  const { width, height } = store.get('windowBounds');
  
  mainWindow = new BrowserWindow({
    width,
    height,
    minWidth: 1024,
    minHeight: 700,
    show: false,
    backgroundColor: '#0f172a', // Match app background
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#0f172a',
      symbolColor: '#ffffff',
      height: 40
    },
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      webSecurity: true
    },
    icon: getAssetPath('icon.png')
  });

  // Load the app
  // In both dev and production, load via the Flask backend URL.
  // The Flask server serves the SPA at all non-API routes, which
  // prevents 404 flashes that happen when loading a static file.
  if (isDev) {
    mainWindow.loadURL(`http://localhost:${FRONTEND_PORT}`);
    mainWindow.webContents.openDevTools();
  } else {
    // Load from Flask backend which serves the SPA correctly
    mainWindow.loadURL(`http://localhost:${BACKEND_PORT}`);
  }

  // Show window when ready
  mainWindow.once('ready-to-show', () => {
    if (!store.get('startMinimized')) {
      mainWindow.show();
    }
  });

  // Save window size on resize
  mainWindow.on('resize', () => {
    const { width, height } = mainWindow.getBounds();
    store.set('windowBounds', { width, height });
  });

  // Handle window close
  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
      
      // Show notification that app is still running
      if (tray) {
        tray.displayBalloon({
          title: 'Packet Peeper',
          content: 'App minimized to system tray. Network monitoring continues.',
          iconType: 'info'
        });
      }
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Handle external links
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  return mainWindow;
}

/**
 * Start the Python backend process
 */
function startBackend() {
  return new Promise((resolve, reject) => {
    const backendPath = getBackendPath();
    const interface_ = store.get('selectedInterface');
    const backendCommand = resolveBackendCommand(interface_);
    
    console.log(`Starting Python backend at: ${backendPath}`);
    console.log(`Interface: ${interface_}`);
    console.log(`Backend command: ${backendCommand.command}`);

    if (!isElevated()) {
      dialog.showMessageBox({
        type: 'warning',
        title: 'Administrator Permissions Required',
        message: 'Packet capture requires elevated permissions or netcap capabilities.',
        detail: 'Run Packet Peeper as Administrator/root or grant packet-capture capabilities to the backend binary.'
      });
    }
    
    const launchBackend = () => {
      pythonProcess = spawn(backendCommand.command, backendCommand.args, {
        cwd: backendPath,
        env: buildBackendEnv(),
        stdio: ['ignore', 'pipe', 'pipe']
      });
      
      pythonProcess.stdout.on('data', (data) => {
        console.log(`[Backend] ${data.toString().trim()}`);
        
        // Check if backend is ready
        if (data.toString().includes('Running on')) {
          resolve();
        }
      });
      
      pythonProcess.stderr.on('data', (data) => {
        console.error(`[Backend Error] ${data.toString().trim()}`);
      });
      
      pythonProcess.on('error', (error) => {
        console.error('Failed to start backend:', error);
        reject(error);
      });
      
      pythonProcess.on('close', (code) => {
        console.log(`Backend process exited with code ${code}`);
        pythonProcess = null;
        
        if (!isQuitting && code !== 0) {
          // Attempt to restart
          setTimeout(() => {
            startBackend().catch(console.error);
          }, 5000);
        }
      });
      
      // Timeout for backend startup
      setTimeout(() => {
        resolve(); // Resolve anyway after timeout
      }, 10000);
    };

    if (backendCommand.usesPython) {
      // Check if Python is available
      exec(`${backendCommand.command} --version`, (error) => {
        if (error) {
          dialog.showErrorBox(
            'Python Not Found',
            'Python is required to run Packet Peeper in development mode. Please install Python 3.8 or higher.'
          );
          reject(new Error('Python not found'));
          return;
        }
        launchBackend();
      });
      return;
    }

    launchBackend();
  });
}

/**
 * Stop the Python backend process
 */
function stopBackend() {
  return new Promise((resolve) => {
    if (pythonProcess) {
      console.log('Stopping Python backend...');
      
      if (process.platform === 'win32') {
        spawn('taskkill', ['/pid', pythonProcess.pid.toString(), '/f', '/t']);
      } else {
        pythonProcess.kill('SIGTERM');
      }
      
      setTimeout(() => {
        if (pythonProcess) {
          pythonProcess.kill('SIGKILL');
        }
        resolve();
      }, 3000);
    } else {
      resolve();
    }
  });
}

/**
 * Create system tray icon and menu
 */
function createTray() {
  const iconPath = getAssetPath(process.platform === 'win32' ? 'icon.ico' : 'icon.png');
  
  // Create tray icon
  let trayIcon;
  try {
    trayIcon = nativeImage.createFromPath(iconPath);
    if (trayIcon.isEmpty()) {
      // Create a simple colored icon if file not found
      trayIcon = nativeImage.createEmpty();
    }
  } catch (e) {
    trayIcon = nativeImage.createEmpty();
  }
  
  tray = new Tray(trayIcon);
  tray.setToolTip('Packet Peeper - Network Security Monitor');
  
  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Open Packet Peeper',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        }
      }
    },
    { type: 'separator' },
    {
      label: 'Network Status',
      enabled: false
    },
    {
      label: '  🟢 Monitoring Active',
      enabled: false
    },
    { type: 'separator' },
    {
      label: 'Settings',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.webContents.send('navigate', '/settings');
        }
      }
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        isQuitting = true;
        app.quit();
      }
    }
  ]);
  
  tray.setContextMenu(contextMenu);
  
  tray.on('click', () => {
    if (mainWindow) {
      if (mainWindow.isVisible()) {
        mainWindow.hide();
      } else {
        mainWindow.show();
        mainWindow.focus();
      }
    }
  });
}

/**
 * Create application menu
 */
function createMenu() {
  const template = [
    {
      label: 'File',
      submenu: [
        {
          label: 'Settings',
          accelerator: 'CmdOrCtrl+,',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.send('navigate', '/settings');
            }
          }
        },
        { type: 'separator' },
        {
          label: 'Export Report',
          submenu: [
            {
              label: 'Export as PDF',
              click: () => {
                if (mainWindow) {
                  mainWindow.webContents.send('export-report', 'pdf');
                }
              }
            },
            {
              label: 'Export as CSV',
              click: () => {
                if (mainWindow) {
                  mainWindow.webContents.send('export-report', 'csv');
                }
              }
            }
          ]
        },
        { type: 'separator' },
        { role: 'quit' }
      ]
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    },
    {
      label: 'Network',
      submenu: [
        {
          label: 'Start Monitoring',
          accelerator: 'CmdOrCtrl+M',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.send('start-monitoring');
            }
          }
        },
        {
          label: 'Stop Monitoring',
          accelerator: 'CmdOrCtrl+Shift+M',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.send('stop-monitoring');
            }
          }
        },
        { type: 'separator' },
        {
          label: 'Scan Network',
          accelerator: 'CmdOrCtrl+S',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.send('scan-network');
            }
          }
        }
      ]
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'Documentation',
          click: () => {
            shell.openExternal('https://github.com/yourusername/packet-peeper#readme');
          }
        },
        {
          label: 'Report Issue',
          click: () => {
            shell.openExternal('https://github.com/yourusername/packet-peeper/issues');
          }
        },
        { type: 'separator' },
        {
          label: 'About Packet Peeper',
          click: () => {
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'About Packet Peeper',
              message: 'Packet Peeper',
              detail: `Version: ${app.getVersion()}\n\nAI-Powered Network Security Monitor\n\nReal-time threat detection and remediation for home networks.`
            });
          }
        }
      ]
    }
  ];
  
  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

// ==================== IPC Handlers ====================

ipcMain.handle('get-app-version', () => {
  return app.getVersion();
});

ipcMain.handle('get-settings', () => {
  return {
    selectedInterface: store.get('selectedInterface'),
    startMinimized: store.get('startMinimized'),
    launchOnStartup: store.get('launchOnStartup')
  };
});

ipcMain.handle('update-settings', (event, settings) => {
  Object.entries(settings).forEach(([key, value]) => {
    store.set(key, value);
  });
  return true;
});

ipcMain.handle('restart-backend', async (event, interface_) => {
  store.set('selectedInterface', interface_);
  await stopBackend();
  await startBackend();
  return true;
});

ipcMain.handle('show-notification', (event, { title, body }) => {
  if (tray) {
    tray.displayBalloon({
      title,
      content: body,
      iconType: 'info'
    });
  }
});

// ==================== App Lifecycle ====================

app.whenReady().then(async () => {
  console.log('Packet Peeper starting...');
  
  // Create menu and tray
  createMenu();
  createTray();
  
  // Start Python backend
  try {
    await startBackend();
    console.log('Backend started successfully');
  } catch (error) {
    console.error('Failed to start backend:', error);
  }
  
  // Create main window
  createWindow();
  
  // Handle macOS dock click
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    } else if (mainWindow) {
      mainWindow.show();
    }
  });
});

app.on('before-quit', async () => {
  isQuitting = true;
  await stopBackend();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    // On Windows/Linux, don't quit, just hide to tray
    // app.quit();
  }
});

// Handle certificate errors in development
app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  if (isDev) {
    event.preventDefault();
    callback(true);
  } else {
    callback(false);
  }
});

// Single instance lock
const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

console.log('Packet Peeper Electron app initialized');
