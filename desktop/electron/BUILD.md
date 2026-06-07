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
git clone https://github.com/Harshit7623/Packet_Peeper.git
cd Packet_Peeper/desktop/electron

# Prerequisites: Ensure your .env file is set up before building the backend
# cp ../../.env.example ../../.env

# Build the backend binary (one-time per release)
cd ../../backend/packaging
pip install -r requirements-build.txt
./build_backend.bat
cd ../../desktop/electron

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
npm run build:frontend
cd ../../backend/packaging
pip install -r requirements-build.txt
./build_backend.sh
cd ../../desktop/electron
npm run build:mac
```

## Linux

### Prerequisites
- Node.js 16+
- Python 3.8+

### Building

```bash
npm run build:frontend
cd ../../backend/packaging
pip install -r requirements-build.txt
./build_backend.sh
cd ../../desktop/electron
npm run build:linux
```

### Running the Linux AppImage

```bash
chmod +x "dist/Packet Peeper-1.0.0.AppImage"
sudo -E ./"dist/Packet Peeper-1.0.0.AppImage" --no-sandbox
```
*(Note: `sudo -E` preserves your environment variables so the display works properly. `--no-sandbox` may be required on some distributions).*

## Development

### Running in Development Mode

```bash
# Terminal 1: Start the backend
cd ../..
python backend/app.py auto

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

### Packet capture permission errors (Linux/macOS)
- Run the app with elevated permissions, or grant capabilities to the backend binary:
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip "backend/packet_peeper_backend"
   ```

### No network interfaces detected
- On Windows, you may need to run as Administrator
- Check Network settings for available interfaces
- Try restarting the app

### Port 5000 already in use
- Change `FLASK_PORT` in app configuration
- Or stop the application using port 5000

### Configuration Overrides & Persistence
- **Backend Path:** You can override the embedded backend executable path using the `PACKET_PEEPER_BACKEND_PATH` environment variable.
- **Persistence:** Application state is stored using `electron-store`. The configuration file is typically located at:
  - Linux: `~/.config/Packet Peeper/config.json`
  - Windows: `%APPDATA%\Packet Peeper\config.json`
  - macOS: `~/Library/Application Support/Packet Peeper/config.json`

## Support

For issues or feature requests, please visit:
https://github.com/Harshit7623/Packet_Peeper/issues
