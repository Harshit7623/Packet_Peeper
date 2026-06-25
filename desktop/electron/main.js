/**
 * Packet Peeper - Electron Main Process
 * Handles window management, Python backend spawning, and system integration
 */

const { app, BrowserWindow, Menu, Tray, ipcMain, shell, dialog, nativeImage, Notification, net } = require('electron');
const { spawn, exec } = require('child_process');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const Store = require('electron-store');

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

const isDev = !app.isPackaged;

let mainWindow = null;
let splashWindow = null;
let tray = null;
let pythonProcess = null;
let isQuitting = false;
let backendHealthy = false;
let healthCheckInterval = null;
let backendRestartCount = 0;
const MAX_BACKEND_RESTARTS = 5;

const BACKEND_PORT = store.get('backendPort');
const FRONTEND_PORT = store.get('frontendPort');

const GITHUB_REPO = 'Harshit7623/Packet_Peeper';

// ==================== Paths ====================

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

const getAssetPath = (asset) => {
  return path.join(__dirname, 'assets', asset);
};

// ==================== Backend Config ====================

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

// ==================== Splash Screen ====================

function createSplashScreen() {
  splashWindow = new BrowserWindow({
    width: 500,
    height: 350,
    transparent: true,
    frame: false,
    resizable: false,
    alwaysOnTop: true,
    skipTaskbar: true,
    show: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    }
  });

  const splashHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          width: 500px; height: 350px;
          background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
          border-radius: 16px;
          display: flex; flex-direction: column;
          align-items: center; justify-content: center;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          color: #f1f5f9;
          overflow: hidden;
          border: 1px solid rgba(99, 102, 241, 0.3);
        }
        .logo { font-size: 36px; font-weight: 700; margin-bottom: 8px; }
        .logo span { color: #6366f1; }
        .subtitle { font-size: 13px; color: #94a3b8; margin-bottom: 24px; }
        .status { font-size: 12px; color: #64748b; margin-top: 24px; }
        .spinner {
          width: 40px; height: 40px;
          border: 3px solid rgba(99, 102, 241, 0.2);
          border-top-color: #6366f1;
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .progress-bar {
          width: 200px; height: 3px; background: #1e293b;
          border-radius: 2px; margin-top: 16px; overflow: hidden;
        }
        .progress-fill {
          height: 100%; width: 0%; background: #6366f1;
          border-radius: 2px; transition: width 0.3s ease;
        }
      </style>
    </head>
    <body>
      <div class="logo">Packet<span>Peeper</span></div>
      <div class="subtitle">Network Security Monitor</div>
      <div class="spinner"></div>
      <div class="progress-bar"><div class="progress-fill" id="progress"></div></div>
      <div class="status" id="status">Starting backend...</div>
      <script>
        let progress = 0;
        function updateProgress(pct, msg) {
          progress = pct;
          document.getElementById('progress').style.width = pct + '%';
          if (msg) document.getElementById('status').textContent = msg;
        }
      </script>
    </body>
    </html>
  `;

  splashWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(splashHtml)}`);
  splashWindow.once('ready-to-show', () => {
    splashWindow.show();
  });

  return splashWindow;
}

function updateSplashProgress(pct, message) {
  if (splashWindow && !splashWindow.isDestroyed()) {
    splashWindow.webContents.executeJavaScript(
      `updateProgress(${pct}, '${message.replace(/'/g, "\\'")}')`
    ).catch(() => {});
  }
}

function closeSplashScreen() {
  if (splashWindow && !splashWindow.isDestroyed()) {
    splashWindow.close();
    splashWindow = null;
  }
}

// ==================== Main Window ====================

function createWindow() {
  const { width, height } = store.get('windowBounds');

  mainWindow = new BrowserWindow({
    width,
    height,
    minWidth: 1024,
    minHeight: 700,
    show: false,
    backgroundColor: '#0f172a',
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

  if (isDev) {
    mainWindow.loadURL(`http://localhost:${FRONTEND_PORT}`);
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadURL(`http://localhost:${BACKEND_PORT}`);
  }

  mainWindow.once('ready-to-show', () => {
    closeSplashScreen();
    if (!store.get('startMinimized')) {
      mainWindow.show();
    }
  });

  mainWindow.on('resize', () => {
    const { width, height } = mainWindow.getBounds();
    store.set('windowBounds', { width, height });
  });

  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
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

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  return mainWindow;
}

// ==================== Backend Process ====================

function startBackend() {
  return new Promise((resolve, reject) => {
    const backendPath = getBackendPath();
    const interface_ = store.get('selectedInterface');
    const backendCommand = resolveBackendCommand(interface_);

    console.log(`Starting Python backend at: ${backendPath}`);
    console.log(`Interface: ${interface_}`);
    console.log(`Backend command: ${backendCommand.command}`);
    updateSplashProgress(20, 'Initializing backend...');

    if (!isElevated()) {
      dialog.showMessageBox({
        type: 'warning',
        title: 'Administrator Permissions Required',
        message: 'Packet capture requires elevated permissions or netcap capabilities.',
        detail: 'Run Packet Peeper as Administrator/root or grant packet-capture capabilities to the backend binary.'
      });
    }

    const launchBackend = () => {
      updateSplashProgress(40, 'Spawning backend process...');

      pythonProcess = spawn(backendCommand.command, backendCommand.args, {
        cwd: backendPath,
        env: buildBackendEnv(),
        stdio: ['ignore', 'pipe', 'pipe']
      });

      updateSplashProgress(60, 'Waiting for backend to accept connections...');

      pythonProcess.stdout.on('data', (data) => {
        const output = data.toString().trim();
        console.log(`[Backend] ${output}`);
        if (output.includes('Running on')) {
          updateSplashProgress(80, 'Backend is running, loading UI...');
          backendHealthy = true;
          updateTrayStatus(backendHealthy);
          resolve();
        }
      });

      pythonProcess.stderr.on('data', (data) => {
        console.error(`[Backend Error] ${data.toString().trim()}`);
      });

      pythonProcess.on('error', (error) => {
        console.error('Failed to start backend:', error);
        updateSplashProgress(80, 'Backend error, loading UI anyway...');
        reject(error);
      });

      pythonProcess.on('close', (code) => {
        console.log(`Backend process exited with code ${code}`);
        pythonProcess = null;
        backendHealthy = false;
        updateTrayStatus(false);

        if (!isQuitting && code !== 0 && backendRestartCount < MAX_BACKEND_RESTARTS) {
          backendRestartCount++;
          console.log(`Restarting backend (attempt ${backendRestartCount}/${MAX_BACKEND_RESTARTS})...`);
          updateSplashProgress(40, `Restarting backend (attempt ${backendRestartCount})...`);
          setTimeout(() => {
            startBackend().catch(console.error);
          }, 5000);
        } else if (backendRestartCount >= MAX_BACKEND_RESTARTS) {
          dialog.showErrorBox(
            'Backend Failed',
            'The backend process has crashed too many times. Please restart Packet Peeper manually.'
          );
        }
      });

      setTimeout(() => {
        updateSplashProgress(80, 'Backend startup timeout, loading UI...');
        resolve();
      }, 15000);
    };

    if (backendCommand.usesPython) {
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

// ==================== Backend Health Check ====================

function startHealthCheck() {
  if (healthCheckInterval) return;

  healthCheckInterval = setInterval(() => {
    if (!pythonProcess) {
      if (backendHealthy) {
        backendHealthy = false;
        updateTrayStatus(false);
      }
      return;
    }

    const req = net.request({
      url: `http://localhost:${BACKEND_PORT}/api/health`,
      method: 'GET',
    });

    req.setTimeout(3000, () => {
      req.abort();
      if (backendHealthy) {
        backendHealthy = false;
        updateTrayStatus(false);
      }
    });

    req.on('response', (response) => {
      if (response.statusCode === 200) {
        if (!backendHealthy) {
          backendHealthy = true;
          updateTrayStatus(true);
        }
      } else {
        if (backendHealthy) {
          backendHealthy = false;
          updateTrayStatus(false);
        }
      }
      response.on('data', () => {});
      response.on('end', () => {});
    });

    req.on('error', () => {
      if (backendHealthy) {
        backendHealthy = false;
        updateTrayStatus(false);
      }
    });

    req.end();
  }, 15000);
}

function stopHealthCheck() {
  if (healthCheckInterval) {
    clearInterval(healthCheckInterval);
    healthCheckInterval = null;
  }
}

// ==================== Tray ====================

function updateTrayStatus(healthy) {
  if (!tray) return;

  const statusLabel = healthy ? '  Monitoring Active' : '  Backend Offline';
  const statusIcon = healthy ? '  * Running' : '  ! Stopped';

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
      label: 'Backend Status',
      enabled: false
    },
    {
      label: statusIcon,
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
    {
      label: 'Check for Updates',
      click: () => {
        checkForUpdates(true);
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
  tray.setToolTip(healthy
    ? 'Packet Peeper - Network Security Monitor'
    : 'Packet Peeper - Backend Offline');
}

function createTray() {
  const iconPath = getAssetPath(process.platform === 'win32' ? 'icon.ico' : 'icon.png');

  let trayIcon;
  try {
    trayIcon = nativeImage.createFromPath(iconPath);
    if (trayIcon.isEmpty()) {
      trayIcon = nativeImage.createEmpty();
    }
  } catch (e) {
    trayIcon = nativeImage.createEmpty();
  }

  tray = new Tray(trayIcon);
  tray.setToolTip('Packet Peeper - Network Security Monitor');
  updateTrayStatus(false);

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

// ==================== Application Menu ====================

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
        {
          label: 'Clear All Alerts',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.send('clear-alerts');
            }
          }
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
            shell.openExternal(`https://github.com/${GITHUB_REPO}#readme`);
          }
        },
        {
          label: 'Report Issue',
          click: () => {
            shell.openExternal(`https://github.com/${GITHUB_REPO}/issues`);
          }
        },
        { type: 'separator' },
        {
          label: 'Check for Updates',
          click: () => {
            checkForUpdates(true);
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

// ==================== Auto-Updater ====================

function checkForUpdates(userInitiated = false) {
  if (isDev) {
    if (userInitiated) {
      dialog.showMessageBox({
        type: 'info',
        title: 'Updates',
        message: 'Auto-update is not available in development mode.',
        detail: 'Pull the latest changes from the repository to update.'
      });
    }
    return;
  }

  try {
    const { autoUpdater } = require('electron-updater');

    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = true;

    autoUpdater.on('update-available', (info) => {
      dialog.showMessageBox(mainWindow, {
        type: 'info',
        title: 'Update Available',
        message: `A new version (${info.version}) is available!`,
        detail: 'Click OK to download and install. The app will restart after download.',
        buttons: ['Download Update', 'Later'],
        defaultId: 0,
      }).then(({ response }) => {
        if (response === 0) {
          autoUpdater.downloadUpdate();
        }
      });
    });

    autoUpdater.on('update-downloaded', (info) => {
      dialog.showMessageBox(mainWindow, {
        type: 'info',
        title: 'Update Ready',
        message: `Version ${info.version} has been downloaded.`,
        detail: 'Restart the application to apply the update.',
        buttons: ['Restart Now', 'Later'],
        defaultId: 0,
      }).then(({ response }) => {
        if (response === 0) {
          isQuitting = true;
          autoUpdater.quitAndInstall();
        }
      });
    });

    autoUpdater.on('error', (err) => {
      console.error('Auto-updater error:', err);
      if (userInitiated) {
        dialog.showMessageBox(mainWindow, {
          type: 'error',
          title: 'Update Error',
          message: 'Could not check for updates.',
          detail: err.message || 'Unknown error occurred.'
        });
      }
    });

    autoUpdater.on('update-not-available', () => {
      if (userInitiated) {
        dialog.showMessageBox(mainWindow, {
          type: 'info',
          title: 'No Updates',
          message: 'You are running the latest version of Packet Peeper.',
          detail: `Current version: ${app.getVersion()}`
        });
      }
    });

    autoUpdater.checkForUpdates().catch((err) => {
      console.error('Update check failed:', err);
    });
  } catch (e) {
    console.log('electron-updater not available, skipping auto-update check');
    if (userInitiated) {
      dialog.showMessageBox(mainWindow, {
        type: 'info',
        title: 'Updates',
        message: 'Auto-update is not available in this build.',
        detail: 'Please download the latest version from the GitHub releases page.'
      });
    }
  }
}

// ==================== Deep Link / Protocol Handler ====================

function setupDeepLink() {
  const PROTOCOL = 'packet-peeper';

  if (process.platform === 'linux') {
    app.setAsDefaultProtocolClient(PROTOCOL, process.execPath, [path.join(__dirname, 'main.js')]);
  } else {
    app.setAsDefaultProtocolClient(PROTOCOL);
  }

  app.on('open-url', (event, url) => {
    event.preventDefault();
    handleDeepLink(url);
  });

  app.on('second-instance', (event, argv) => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
    const deepLinkArg = argv.find(arg => arg.startsWith('packet-peeper://'));
    if (deepLinkArg) {
      handleDeepLink(deepLinkArg);
    }
  });
}

function handleDeepLink(url) {
  try {
    const parsedUrl = new URL(url);
    const route = parsedUrl.pathname.replace(/^\/+/, '');
    const params = Object.fromEntries(parsedUrl.searchParams.entries());

    if (!route) return;

    const validRoutes = ['alerts', 'settings', 'devices', 'analytics', 'packets', 'reports'];

    if (validRoutes.includes(route)) {
      if (mainWindow) {
        if (!mainWindow.isVisible()) mainWindow.show();
        mainWindow.focus();
        mainWindow.webContents.send('deep-navigate', { route, params });
      }
    }
  } catch (e) {
    console.error('Failed to handle deep link:', e);
  }
}

// ==================== Desktop Notifications ====================

function showSecurityNotification(alert) {
  if (!Notification.isSupported()) return;
  if (!store.get('desktopNotifications', true)) return;

  const severity = alert.severity || alert.type || 'medium';
  const urgency = severity === 'critical' || severity === 'high' ? 'critical' : 'normal';

  const notification = new Notification({
    title: `Security Alert: ${alert.title || alert.type || 'Alert'}`,
    body: alert.description || alert.message || 'Security event detected',
    icon: getAssetPath('icon.png'),
    urgency,
    silent: severity === 'low',
  });

  notification.on('click', () => {
    if (mainWindow) {
      if (!mainWindow.isVisible()) mainWindow.show();
      mainWindow.focus();
      mainWindow.webContents.send('navigate', '/alerts');
    }
  });

  notification.show();
}

// ==================== IPC Handlers ====================

ipcMain.handle('get-app-version', () => {
  return app.getVersion();
});

ipcMain.handle('get-settings', () => {
  return {
    selectedInterface: store.get('selectedInterface'),
    startMinimized: store.get('startMinimized'),
    launchOnStartup: store.get('launchOnStartup'),
    desktopNotifications: store.get('desktopNotifications', true),
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
  backendRestartCount = 0;
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

ipcMain.handle('check-for-updates', () => {
  checkForUpdates(true);
  return true;
});

ipcMain.handle('get-backend-status', () => {
  return {
    healthy: backendHealthy,
    pid: pythonProcess ? pythonProcess.pid : null,
    restartCount: backendRestartCount,
  };
});

// Receive security alerts from renderer (which gets them from WebSocket)
ipcMain.on('security-alert', (event, alert) => {
  showSecurityNotification(alert);
});

// ==================== App Lifecycle ====================

setupDeepLink();

app.whenReady().then(async () => {
  console.log('Packet Peeper starting...');

  createSplashScreen();
  updateSplashProgress(10, 'Initializing...');

  createMenu();
  createTray();

  updateSplashProgress(20, 'Starting backend...');

  try {
    await startBackend();
    console.log('Backend started successfully');
  } catch (error) {
    console.error('Failed to start backend:', error);
    updateSplashProgress(80, 'Backend failed, loading UI...');
  }

  createWindow();
  startHealthCheck();

  if (!isDev) {
    setTimeout(() => {
      checkForUpdates(false);
    }, 30000);
  }

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
  stopHealthCheck();
  await stopBackend();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    // On Windows/Linux, keep running in tray
  }
});

app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  if (isDev) {
    event.preventDefault();
    callback(true);
  } else {
    callback(false);
  }
});

const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', (event, argv) => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
    const deepLinkArg = argv.find(arg => arg.startsWith('packet-peeper://'));
    if (deepLinkArg) {
      handleDeepLink(deepLinkArg);
    }
  });
}

console.log('Packet Peeper Electron app initialized');
