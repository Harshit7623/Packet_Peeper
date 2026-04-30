# Backend Tuning & Testing Guide

## Quick Start

### 1. Enable Detailed Logging
Set environment variables before starting the backend:

```bash
export DETECTION_DEBUG=True      # See detailed attack detection logs
export CAPTURE_DEBUG=True        # See detailed packet capture logs  
export AI_DEBUG=True             # See detailed AI operation logs
```

### 2. Start with Test Profile (For Development)
```bash
export DETECTION_PROFILE=test    # Very low thresholds - easier to trigger alerts
python3 backend/app.py
```

## Detection Profiles Explained

### Profile Thresholds

| Profile | Use Case | Characteristics |
|---------|----------|-----------------|
| **strict** | Production/Enterprise | High bar for alerts, few false positives, may miss subtle attacks |
| **balanced** | DEFAULT | Balanced sensitivity, recommended for most environments |
| **sensitive** | Security Labs | Low bar for alerts, catches more attacks, more false positives |
| **test** | Development/Testing | Very low bar - expects many alerts, for testing detection logic |

### Profile Details

#### STRICT
- Port scan detection: 15+ ports in 90s (high bar)
- Flood detection: 100 SYN/s (very high threshold)
- DNS tunneling: 80+ char queries, 8+ subdomains
- Brute force: 12+ attempts in 180s
- **Use when:** False positives are expensive, you have heavy normal traffic

#### BALANCED (Default)
- Port scan detection: 10+ ports in 60s
- Flood detection: 50 SYN/s
- DNS tunneling: 70+ char queries, 7+ subdomains
- Brute force: 7+ attempts in 120s
- **Use when:** You want reasonable coverage without too much noise

#### SENSITIVE
- Port scan detection: 6+ ports in 30s (low bar)
- Flood detection: 20 SYN/s (sensitive)
- DNS tunneling: 60+ char queries, 6+ subdomains
- Brute force: 5+ attempts in 60s
- **Use when:** You want to catch subtle attacks, can tolerate more false positives

#### TEST
- Port scan detection: 5+ ports in 30s (very low)
- Flood detection: 10 SYN/s (very low)
- DNS tunneling: 50+ char queries, 5+ subdomains
- Brute force: 4+ attempts in 60s
- **Use when:** Testing detection logic, simulating attacks

## Testing Workflow

### Step 1: Check Current Status
```bash
curl http://localhost:5000/api/detection/profile
# Returns current profile and available thresholds

curl http://localhost:5000/api/ai/status
# Returns AI provider (openai, anthropic, ollama, or fallback)
```

### Step 2: Switch to Test Profile
```bash
curl -X POST http://localhost:5000/api/detection/profile \
  -H "Content-Type: application/json" \
  -d '{"profile": "test"}'
```

**Expected Response:**
```json
{
  "message": "Profile changed to test",
  "current_profile": "test",
  "current_thresholds": {
    "port_scan_count": 5,
    "syn_flood_rate": 10,
    ...
  }
}
```

### Step 3: Generate Test Alerts

Use the attack testing scripts from `attack_tests/`:

```bash
# Terminal 1: Start monitoring
cd backend
export DETECTION_PROFILE=test
export DETECTION_DEBUG=True
python3 app.py

# Terminal 2: Run port scan attack
cd attack_tests
python3 port_scanner.py --target localhost --ports 8000-8010 --speed fast

# Terminal 3: Monitor alerts
curl -s http://localhost:5000/api/alerts | jq '.[] | {type, severity, timestamp}'
```

### Step 4: Monitor Both Alerts and Profiles

**Check alerts:**
```bash
curl http://localhost:5000/api/alerts | jq length
# Should show increasing count if attacks are detected
```

**Check current profile:**
```bash
curl http://localhost:5000/api/detection/profile | jq '.current_profile'
# Verify you're still on "test"
```

**View detection logs:**
```bash
tail -f backend/logs/packet_peeper.log | grep DETECTION
```

## Frontend Testing

### 1. Visit Alerts Page
- Navigate to http://localhost:3000/alerts
- You should see **System Status Bar** at the top showing:
  - ✅ **AI Assistant** section with provider status
  - ✅ **Detection Profile** section showing current profile

### 2. Test Profile Switching from Frontend
- Click "Change" button next to Detection Profile
- Select a different profile (e.g., "sensitive")
- Should see toast notification confirming change

### 3. Check AI Provider Status
- If OPENAI_API_KEY is set → Shows "Connected to openai"
- If no API key → Shows "Using Fallback Responses" in yellow
- All fallback responses work for 20+ attack types

### 4. Monitor Real Alerts
- As packets flow in, alerts should appear in the list
- Alert severity matches detection logic
- Click AI Helper button → Gets remediation from provider

## Troubleshooting

### No Alerts Appearing?
1. **Check profile:** `curl http://localhost:5000/api/detection/profile`
2. **Check logs:** `tail backend/logs/packet_peeper.log | grep -i "detect\|alert"`
3. **Verify traffic:** Ensure packets are being captured
4. **Try test profile:** Switch to "test" profile for lower thresholds

### Profile Change Not Taking Effect?
1. **Check if sniffer is running:** `curl http://localhost:5000/api/sniffing/status`
2. **Verify profile was set:** `curl http://localhost:5000/api/detection/profile`
3. **Check logs:** Look for "Detection profile changed" messages

### AI Not Responding?
1. **Check AI status:** `curl http://localhost:5000/api/ai/status`
2. **If fallback:** Responses are built-in, should always work
3. **If provider shows error:** Check API keys and network connectivity
4. **Check logs:** `tail backend/logs/packet_peeper.log | grep AI`

## Production Readiness Checklist

### Detection Accuracy ✅
- [ ] Run attacks on your network
- [ ] Verify alerts are generated at expected times
- [ ] Tune profile based on your normal traffic patterns
- [ ] Document chosen profile and reasoning

### AI Functionality ✅
- [ ] Check `/api/ai/status` shows desired provider
- [ ] Test remediation by clicking "Get AI Help" on alerts
- [ ] Verify responses are helpful and non-technical
- [ ] If using API provider, verify API key is working

### Action Center ✅
- [ ] Can scan network (check for new devices)
- [ ] Can pause/resume monitoring
- [ ] Can export report (JSON/CSV)
- [ ] Toast notifications appear on success/failure

### Logging ✅
- [ ] Backend logs are clean (no print statements)
- [ ] Debug flags work as expected
- [ ] Profile changes are logged
- [ ] Alerts are timestamped and structured

## Next Steps

Once packet accuracy and AI are satisfactory, proceed to:
1. **Docker containerization** - Build containers for consistent deployment
2. **Database setup** - Configure PostgreSQL or SQLite
3. **SSL/TLS certificates** - Secure all connections
4. **Production deployment** - Deploy to cloud or on-premises server
