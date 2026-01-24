# Packet Peeper - Build & Distribution

## Windows

### Prerequisites
- Windows 10 or later
- Git
- Node.js 16+
- Python 3.8+

### Building the Installer

```bash
# Clone the repository
git clone https://github.com/yourusername/packet-peeper.git
cd packet-peeper/desktop/electron

# Install Electron dependencies
npm install

# Build the Windows installer
npm run build:win
```

The installer will be created in `dist/` directory as `Packet Peeper Setup 1.0.0.exe`

### Installation

1. Download `Packet Peeper Setup 1.0.0.exe`
2. Right-click and select "Run as Administrator" (required for network capture)
3. Follow the installation wizard
4. The app will create a Desktop shortcut
5. Launch Packet Peeper from your Desktop or Start Menu

## macOS

### Prerequisites
- macOS 10.13+
- Xcode Command Line Tools
- Node.js 16+
- Python 3.8+

### Building

```bash
npm run build:mac
```

## Linux

### Prerequisites
- Node.js 16+
- Python 3.8+

### Building

```bash
npm run build:linux
```

## Development

### Running in Development Mode

```bash
# Terminal 1: Start the backend
cd ..
python app.py Wi-Fi

# Terminal 2: Start the frontend dev server
cd frontend
npm run dev

# Terminal 3: Start Electron (from desktop/electron directory)
npm start
```

Or use the combined command:
```bash
npm run dev
```

## Distribution

### GitHub Releases

1. Create a GitHub release with version tag (e.g., `v1.0.0`)
2. Upload the installer files:
   - Windows: `Packet Peeper Setup 1.0.0.exe`
   - macOS: `Packet Peeper 1.0.0.dmg`
   - Linux: `packet-peeper-1.0.0.AppImage`

### Automatic Updates

The app is configured with `electron-updater` for automatic updates:
- Windows: NSIS installer with auto-update support
- macOS: DMG file download
- Linux: AppImage download

Updates check on app startup and can be manually triggered.

## Troubleshooting

### Backend won't start
- Ensure Python 3.8+ is installed and in your PATH
- Check Windows Defender or antivirus isn't blocking Python
- Try running as Administrator

### No network interfaces detected
- On Windows, you may need to run as Administrator
- Check Network settings for available interfaces
- Try restarting the app

### Port 5000 already in use
- Change `FLASK_PORT` in app configuration
- Or stop the application using port 5000

## Support

For issues or feature requests, please visit:
https://github.com/yourusername/packet-peeper/issues
