# Security Event Monitoring System

A real-time intrusion detection and security event monitoring system built with Flask and WebSocket for live event tracking.

## Features

- **Real-time Event Monitoring**
  - Live event notifications
  - Customizable time-based filters (15min, 30min, 1hr, 24hr)
  - Severity-based filtering (High, Medium, Low)

- **Comprehensive Dashboard**
  - Attack statistics and trends
  - System health monitoring
  - Top threats identification
  - Geographic attack visualization

- **Advanced Event Analysis**
  - Detailed event inspection
  - Source IP reputation checking
  - Attack pattern recognition
  - Impact assessment

- **Security Features**
  - File modification tracking
  - Port scan detection 
  - DoS attack monitoring
  - Authentication failure tracking
  - Malware detection alerts

## Tech Stack

- Backend: Flask, SQLAlchemy, SocketIO
- Frontend: JavaScript, WebSocket
- Database: SQLite
- UI: CSS3, FontAwesome

## Quick Start

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python web_app.py
```

3. Access the dashboard:
```
http://localhost:5000
```
