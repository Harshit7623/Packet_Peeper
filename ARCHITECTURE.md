# Packet Peeper - System Architecture

This document provides a deep dive into the underlying architecture, data flow, and threat detection mechanisms of Packet Peeper.

## System Architecture

Packet Peeper is built on a decoupled architecture, separating the high-performance packet capture backend from the dynamic React frontend. They communicate in real-time via Socket.IO.

```mermaid
graph TD
    %% Core Components
    subgraph Network Layer
        NIC[Network Interface Card]
        PCAP[Packet Capture / scapy / pcap]
    end

    subgraph Backend Core Python
        PS[Packet Sniffer Engine]
        NSM[Network Security Monitor]
        DB[(SQLite Database)]
        AUTH[Auth Service]
        FLASK[Flask Web Server]
        SIO[Socket.IO Server]
    end

    subgraph Desktop Application Electron
        REACT[React Frontend Vite]
        CHART[Chart.js Visualizations]
        MAIN[Electron Main Process]
    end

    %% Flow
    NIC -->|Raw Packets| PCAP
    PCAP -->|Parsed Packets| PS
    PS -->|Extracted Metadata| NSM
    PS -->|Live Stats| SIO
    NSM -->|Threats & Alerts| SIO
    NSM <-->|Cooldown State| DB
    AUTH <-->|User Credentials| DB
    FLASK <-->|Auth Tokens| AUTH

    SIO == WebSocket 200ms ==> REACT
    FLASK -- REST API --> REACT
    REACT --> CHART
    MAIN -->|Spawns Backend Binary| FLASK
    MAIN -->|Serves Static Files| REACT
```

## Packet Processing Pipeline

The following sequence details how a single raw packet is ingested, parsed, classified, and analyzed for security threats in under a millisecond.

```mermaid
sequenceDiagram
    participant NIC as Network Interface
    participant Scapy as Packet Sniffer (Scapy)
    participant Classifier as Service Classifier
    participant NSM as Security Monitor
    participant SIO as Socket.IO
    participant Client as Frontend Dashboard

    NIC->>Scapy: Receive raw packet bytes
    Scapy->>Scapy: Decode L2/L3 (Ethernet/IP)
    Scapy->>Scapy: Decode L4 (TCP/UDP/ICMP)
    
    rect rgb(30, 41, 59)
        Note right of Scapy: Classification Phase
        Scapy->>Classifier: Extract IP/Port/Payload
        alt is DNS Packet
            Classifier->>Classifier: Cache DNS A/AAAA Records
        else is HTTPS (TLS)
            Classifier->>Classifier: Extract SNI Hostname
        else is Standard Traffic
            Classifier->>Classifier: Check IP against known CIDR blocks
        end
    end
    
    rect rgb(49, 14, 24)
        Note right of Classifier: Security Analysis Phase
        Classifier->>NSM: Send packet metadata
        NSM->>NSM: Update stateful connection tracking
        NSM->>NSM: Check Port Scan thresholds (5+ ports/60s)
        NSM->>NSM: Check DDoS thresholds (100+ pkts/s)
        NSM->>NSM: Check Brute Force (SSH/RDP/Telnet)
    end
    
    alt Threat Detected
        NSM->>NSM: Verify Cooldown Period
        NSM->>SIO: Generate Alert (High/Critical)
        SIO-->>Client: Emit `new_alert` event
    end

    Scapy->>SIO: Aggregate packet stats
    SIO-->>Client: Emit `new_packet` & `traffic_update` (batched 200ms)
```

## Authentication Workflow

With the introduction of the Local Authentication system, the desktop application now requires users to authenticate before viewing sensitive network traffic.

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant AuthAPI as Flask Auth API
    participant DB as SQLite DB
    
    User->>Frontend: Enters Username & Password
    Frontend->>AuthAPI: POST /api/auth/login
    
    AuthAPI->>DB: Query User by Username
    DB-->>AuthAPI: Return Password Hash & Salt
    
    AuthAPI->>AuthAPI: bcrypt.checkpw(password, hash)
    
    alt Invalid Credentials
        AuthAPI-->>Frontend: 401 Unauthorized
        Frontend-->>User: Show Error Message
    else Valid Credentials
        AuthAPI->>AuthAPI: Generate JWT (Expires 24h)
        AuthAPI-->>Frontend: 200 OK + { token, user_id }
        Frontend->>Frontend: Store JWT in localStorage
        Frontend->>Frontend: Redirect to Dashboard
        
        loop Real-time Traffic
            Frontend->>AuthAPI: WS Connect (Auth Header)
            AuthAPI-->>Frontend: Upgrade to WebSocket
        end
    end
```
