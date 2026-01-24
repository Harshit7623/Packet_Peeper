# Packet Peeper Backend Startup Guide

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Administrator/root privileges (for packet capture)
- Network interface available (Wi-Fi, Ethernet, etc.)

## Installation Steps

### 1. Install Dependencies

```bash
# Upgrade pip
pip install --upgrade pip

# Install all required packages
pip install -r requirements.txt
```

### 2. Verify Installation

Run the backend verification script to ensure everything is configured correctly:

```bash
python verify_backend.py
```

Expected output:
```
🔍 PACKET PEEPER BACKEND VERIFICATION
==================================================

📋 Python Version:
✅ Python 3.10.11

📋 Required Files:
✅ app.py
✅ packet_sniffer.py
✅ network_security_monitor.py
✅ requirements.txt
✅ .env
✅ config/config.py
...

📊 VERIFICATION SUMMARY
==================================================
✅ PASS: Python Version
✅ PASS: Required Files
✅ PASS: Dependencies
✅ PASS: Configuration
✅ PASS: Directories
✅ PASS: Services
✅ PASS: Flask Routes
==================================================

✅ ALL CHECKS PASSED - Backend is ready to launch!
```

## Configuration

The `.env` file contains all configuration options. Key settings:

### Network Capture
```
CAPTURE_INTERFACE=Wi-Fi          # Your network interface
PACKET_BUFFER_SIZE=10000         # Max packets in memory
```

### Database
```
DB_ENGINE=sqlite                 # Use sqlite for development
# For PostgreSQL, change to:
# DB_ENGINE=postgresql
# DB_HOST=localhost
# DB_PORT=5432
# DB_USER=packet_peeper_user
# DB_PASSWORD=your_password
# DB_NAME=packet_peeper_db
```

### Security
```
ENABLE_AUTH=False                # Auth disabled for development
FEATURE_THREAT_DETECTION=True    # Enable attack detection
FEATURE_PERSISTENT_STORAGE=True  # Save to database
```

### Logging
```
LOG_LEVEL=INFO                   # DEBUG, INFO, WARNING, ERROR
FLASK_DEBUG=True                 # Development mode
```

## Finding Your Network Interface

### Windows
```bash
python -c "from scapy.all import conf; print(conf.ifaces)"
```

Or use:
```bash
ipconfig
```

Common interface names: `Wi-Fi`, `Ethernet`, `eth0`

### Linux/macOS
```bash
ip link show
# or
ifconfig
```

## Starting the Backend

### Basic Startup

```bash
python app.py Wi-Fi
```

Replace `Wi-Fi` with your actual network interface name.

### With Explicit Configuration

```bash
# Override interface from .env
CAPTURE_INTERFACE=eth0 python app.py eth0

# Enable debug logging
LOG_LEVEL=DEBUG python app.py Wi-Fi

# Use production mode
FLASK_ENV=production FLASK_DEBUG=False python app.py Wi-Fi
```

### Expected Output

```
Server initialized for threading.
2025-12-31 02:00:00,123 - INFO - ✅ Database service initialized
2025-12-31 02:00:00,456 - INFO - ✅ Packet processor initialized
2025-12-31 02:00:00,789 - INFO - Starting packet sniffing on Wi-Fi...
2025-12-31 02:00:01,012 - INFO - Discovered 3 network interfaces
2025-12-31 02:00:01,234 - INFO - Local network detected: 192.168.1.0/24
2025-12-31 02:00:01,456 - INFO - Starting Flask application
 * Serving Flask app 'packet_peeper'
 * Environment: development
 * Running on http://0.0.0.0:5000
```

## Connecting the Frontend

In a separate terminal:

```bash
cd my-app
npm start
```

Frontend will be available at: `http://localhost:3000`

## Verify Backend is Running

Check Flask is listening:

```bash
# Windows
netstat -an | findstr :5000

# Linux/macOS
lsof -i :5000
# or
netstat -an | grep 5000
```

Should show: `LISTENING` on port 5000

## Testing the Connection

Open another terminal and run:

```bash
python verify_alerts.py
```

or use the web interface to test WebSocket connection.

## Common Issues & Solutions

### Issue: "No module named 'scapy'"

**Solution:**
```bash
pip install scapy
pip install -r requirements.txt
```

### Issue: "Permission denied" (Linux/macOS)

**Solution:**
```bash
# Run with sudo
sudo python app.py Wi-Fi
```

Or add capabilities:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3
```

### Issue: "Interface not found"

**Solution:**
1. Verify interface name:
   ```bash
   # Windows
   python -c "from scapy.all import conf; print(conf.ifaces)"
   ```

2. Check interface is active:
   ```bash
   ipconfig (Windows)
   ifconfig (Linux/macOS)
   ```

3. Try common names: `Wi-Fi`, `Ethernet`, `eth0`, `en0`

### Issue: "Port 5000 already in use"

**Solution:**
```bash
# Find process using port 5000
# Windows
netstat -ano | findstr :5000

# Linux/macOS
lsof -i :5000

# Kill process (Windows)
taskkill /PID <PID> /F

# Kill process (Linux/macOS)
kill -9 <PID>
```

Or use different port:
```bash
FLASK_PORT=5001 python app.py Wi-Fi
```

### Issue: "WebSocket connection refused"

**Solution:**
1. Verify backend is running on port 5000
2. Check firewall allows port 5000
3. Verify frontend is connecting to `http://localhost:5000`
4. Check browser console for detailed error messages

### Issue: "No packets captured"

**Solution:**
1. Ensure you have network activity (browse a website)
2. Check interface is correct
3. Verify you have required privileges
4. Check BPF filter isn't too restrictive

### Issue: "Database connection failed"

**Solution:**
1. SQLite doesn't require setup; just works
2. For PostgreSQL:
   - Ensure database is running
   - Verify credentials in .env
   - Check host/port are correct

## Monitoring the Backend

### View Real-time Logs

```bash
# Watch log file for updates
tail -f logs/packet_peeper.log

# Windows PowerShell
Get-Content logs/packet_peeper.log -Wait
```

### Database Status

```bash
python -c "from services.database_services import get_database_service; db = get_database_service(); print(db.get_stats())"
```

### Packet Processor Status

```bash
python -c "from services.packet_processor import get_packet_processor; pp = get_packet_processor(); print(pp.get_stats())"
```

## Performance Tuning

### Increase Packet Buffer

Edit `.env`:
```
PACKET_BUFFER_SIZE=50000      # For high-traffic networks
WORKER_THREADS=8              # For multi-core systems
```

### Enable Persistent Storage

Edit `.env`:
```
DB_ENGINE=postgresql          # Better for large datasets
FEATURE_PERSISTENT_STORAGE=True
```

### Optimize for Production

Edit `.env`:
```
FLASK_ENV=production
FLASK_DEBUG=False
LOG_LEVEL=WARNING
ASYNC_PROCESSING=True
WORKER_THREADS=8
```

## Security Considerations

### Development Mode

Current setup is for development only. To make it production-ready:

1. **Change Secret Key**
   ```
   SECRET_KEY=<generate-secure-random-string>
   ```

2. **Enable HTTPS**
   ```
   USE_HTTPS=True
   TLS_CERT_PATH=/path/to/cert.pem
   TLS_KEY_PATH=/path/to/key.pem
   ```

3. **Enable Authentication**
   ```
   ENABLE_AUTH=True
   JWT_SECRET=<secure-random-string>
   ```

4. **Restrict CORS**
   ```
   # Modify app.py CORS configuration
   CORS(app, resources={r"/*": {"origins": ["https://yourdomain.com"]}})
   ```

5. **Use PostgreSQL**
   ```
   DB_ENGINE=postgresql
   # Set secure credentials
   ```

## Docker Deployment

To run in Docker:

```dockerfile
FROM python:3.10
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "app.py", "eth0"]
```

Build and run:
```bash
docker build -t packet-peeper .
docker run --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN packet-peeper
```

## Troubleshooting

### Enable Debug Logging

Edit `.env`:
```
LOG_LEVEL=DEBUG
FLASK_DEBUG=True
```

Then restart:
```bash
python app.py Wi-Fi
```

### Check System Resources

```bash
# Python memory usage
python -c "import psutil; print(psutil.Process().memory_info())"

# CPU usage
python -c "import psutil; print(f'CPU: {psutil.cpu_percent()}%')"
```

### Validate Configuration

```bash
python config/config.py
```

### Test Each Service

```bash
# Test database
python -c "from services.database_services import get_database_service; db = get_database_service(); print('DB OK')"

# Test packet processor
python -c "from services.packet_processor import init_packet_processor; pp = init_packet_processor(); print('Processor OK')"

# Test report generator
python -c "from services.report_generator import get_report_generator; rg = get_report_generator(); print('Reports OK')"
```

## Getting Help

1. Check logs: `logs/packet_peeper.log`
2. Run verification: `python verify_backend.py`
3. Enable debug logging for more details
4. Check GitHub issues for similar problems
5. Review README.md for detailed documentation

## Next Steps

Once backend is running:

1. Start frontend: `cd my-app && npm start`
2. Open browser: `http://localhost:3000`
3. Test packet capture with network activity
4. Run attack simulation: `python test_attacks.py`
5. View alerts in the dashboard

Happy monitoring! 🎉
