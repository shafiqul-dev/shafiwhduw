# Android RAT Lab - Pentesting Education Platform

A comprehensive educational lab for understanding Android Remote Access Trojan (RAT) attacks, detection, and mitigation strategies. Built with Flask backend and modern dark-theme web frontend.

## Features

### 🔴 ATTACKER VIEW (Red Team)
- **APK Payload Generator**: Generate Android RAT payloads with msfvenom
- **Generated Payloads**: View history of all generated APK payloads
- **Active Sessions**: Monitor active meterpreter sessions from infected devices
- **Download Payloads**: Download generated APK files for deployment

### 🔵 DETECT VIEW (Blue Team)
- **Device Scanner**: Scan connected Android devices for vulnerabilities
- **Scanned Devices**: View all scanned devices and their status
- **RAT Indicators**: Educational guide on RAT detection indicators
- **Real-time Status**: Check device connectivity and security status

### 🟢 DELETE VIEW (Defensive)
- **Remove RAT**: Eliminate RAT payloads using various methods
- **Device Cleanup**: Perform forensic cleanup of infected devices
- **Manual Steps**: Step-by-step guide for manual RAT removal
- **Defensive Best Practices**: Security hardening recommendations

## Technology Stack

### Backend
- **Framework**: Flask 2.3.2
- **Database**: SQLite with SQLAlchemy ORM
- **CORS**: Flask-CORS for cross-origin requests
- **Python 3.11+**

### Frontend
- **HTML5 + CSS3**: Dark theme cybersecurity dashboard
- **JavaScript (Vanilla)**: No external framework dependencies
- **Responsive Design**: Works on desktop and mobile

### Integration
- **Metasploit Framework**: msfvenom for APK payload generation
- **REST API**: JSON-based communication
- **Mock APK Support**: Fallback for testing without msfvenom

## Installation & Setup

### Prerequisites
```bash
python3 --version  # Should be 3.11 or higher
```

### Quick Start

1. **Clone the repository**:
```bash
cd /home/user/shafiwhduw
```

2. **Create virtual environment and install dependencies**:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
```

3. **Start the backend**:
```bash
source venv/bin/activate
nohup python3 backend/app.py > backend.log 2>&1 &
```

4. **Start the frontend** (in another terminal):
```bash
cd frontend
python3 -m http.server 8080
```

5. **Open in browser**:
```
http://localhost:8080
```

## API Endpoints

### Attacker API
- `POST /api/attacker/generate-apk` - Generate APK payload
- `GET /api/attacker/apk-history` - Get all generated payloads
- `GET /api/attacker/download/<id>` - Download APK file
- `GET /api/attacker/sessions` - Get active meterpreter sessions

### Detect API
- `POST /api/detect/scan` - Scan Android device
- `GET /api/detect/devices` - Get all scanned devices

### Delete API
- `POST /api/delete/remove-rat` - Remove RAT from device
- `POST /api/delete/cleanup` - Cleanup infected device

### Health Check
- `GET /api/health` - API health status

## Database Models

### APKPayload
- `id`: Unique identifier
- `lhost`: Attacker IP address
- `lport`: Listener port
- `payload_name`: Unique payload identifier
- `file_path`: Path to generated APK
- `status`: 'pending', 'completed', 'failed'
- `created_at`: Timestamp

### MeterpreterSession
- `id`: Unique identifier
- `session_id`: Metasploit session ID
- `device_id`: Target device identifier
- `payload_name`: Associated payload
- `status`: 'active', 'terminated'
- `created_at`: Timestamp

### AndroidDevice
- `id`: Unique identifier
- `device_id`: Device serial/UUID
- `device_name`: Human-readable name
- `status`: 'online', 'offline'
- `rat_detected`: Boolean indicator
- `rat_indicators`: JSON field with detection data
- `scanned_at`: Last scan timestamp

## Educational Purpose

This lab is designed for:
- **Security Education**: Understanding RAT attack vectors
- **Penetration Testing**: Learning attack methodology
- **Incident Response**: Detection and removal techniques
- **Defensive Security**: Implementing protective measures

## Important Notes

- **Ethical Use Only**: This lab is for authorized testing only
- **Authorization Required**: Only use with proper authorization
- **Educational Context**: Intended for learning and security research
- **CTF Challenges**: Compatible with cybersecurity competitions

## Troubleshooting

### Backend Connection Error
- Ensure backend is running: `ps aux | grep python3`
- Check if port 5000 is available: `lsof -i :5000`
- Verify CORS headers in browser console

### Frontend Not Loading
- Ensure frontend server is running on port 8080
- Clear browser cache (Ctrl+Shift+Delete)
- Check console for JavaScript errors

### Metasploit Not Found
- Lab uses mock APKs if msfvenom unavailable
- For real payloads, install: `apt-get install metasploit-framework`

## License

Educational Use Only

## Support

For issues or questions about the lab functionality, review the code structure:
- Backend logic: `backend/app.py`
- Frontend UI: `frontend/index.html`
- Dependencies: `backend/requirements.txt`
