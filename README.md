# Brute-Force Attempt Detector

## Project Overview
This project is a lightweight cybersecurity prototype designed to detect possible brute-force login attacks. It provides an interactive dashboard for simulated login attempts and also supports CSV log analysis.

The system identifies suspicious patterns such as:
- too many failed login attempts in a short time
- repeated failed attempts from the same IP address
- repeated attacks on the same account

## Features
- Simulated login dashboard
- Login success/failure tracking
- Brute-force detection alerts
- Login attempt history
- Failed login history
- Summary statistics
- Charts for failed attempts by IP and username
- CSV log upload and analysis
- Docker support

## Technologies Used
- Python
- Streamlit
- pandas
- Docker

## Detection Rules
1. **Burst Failure**
   - 5 failed attempts within 60 seconds

2. **Suspicious IP**
   - 8 failed attempts from the same IP
   - or 3 different usernames targeted by the same IP

3. **Targeted Account**
   - 5 failed attempts on the same account within 5 minutes

## Project Structure
```text
Cyber-BruteForce/
├── sample_logs/
│   ├── normal_log.csv
│   ├── burst_attack_log.csv
│   ├── suspicious_ip_log.csv
│   ├── targeted_account_log.csv
│   └── mixed_attack_log.csv
├── app.py
├── detector.py
├── Dockerfile
├── requirements.txt
├── README.md
└── .gitignore
```

## How It Works
The project has two main modes:

### 1. Simulated Login
The user enters:
- username
- password
- source IP

The system checks the login against a small predefined user list:
- if correct, it shows **SUCCESS**
- if incorrect, it records a **FAIL**

Each attempt is stored with:
- timestamp
- username
- IP address
- status

Then the system analyzes the failed attempts and generates alerts if brute-force patterns are detected.

### 2. CSV Log Analysis
The dashboard also allows CSV file upload for testing prepared login logs.

The CSV file must contain these columns:
- `timestamp`
- `username`
- `ip`
- `status`

The uploaded log is analyzed using the same detection rules, and the dashboard shows:
- summary metrics
- alerts
- log table

## How to Run Locally

### 1. Create and activate virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install dependencies
```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Run the app
```bash
python -m streamlit run app.py
```

Then open:
```text
http://localhost:8501
```

## How to Run with Docker

### Build image
```bash
docker build -t bruteforce-detector .
```

### Run container
```bash
docker run -p 8501:8501 bruteforce-detector
```

Then open:
```text
http://localhost:8501
```

## Sample Test Files
The `sample_logs/` folder contains example CSV files for testing:

- `normal_log.csv`
  - normal user activity
  - little or no alert expected

- `burst_attack_log.csv`
  - many failed attempts in a short time
  - should trigger burst failure detection

- `suspicious_ip_log.csv`
  - one IP targeting multiple usernames
  - should trigger suspicious IP detection

- `targeted_account_log.csv`
  - repeated failed attempts on one account
  - should trigger targeted account detection

- `mixed_attack_log.csv`
  - combination of suspicious patterns
  - may trigger multiple alerts

## Expected Output
The system displays:
- login result
- alert messages
- login attempt history
- failed login history
- summary metrics
- charts
- CSV analysis results

## Example Use Cases
- Simulate repeated failed login attempts from the same IP
- Simulate attacks on a specific account
- Upload prepared CSV log files for testing
- Demonstrate brute-force detection in a simple dashboard

## Limitations
- uses fixed rule-based thresholds
- simulated login only
- no real backend database
- no real-time production monitoring
- may produce false positives in some cases

## Future Improvements
- real-time log monitoring
- email/SMS alerting
- automatic IP blocking
- database integration
- more advanced anomaly detection using machine learning

## Authors
- Mr. Aung Htet Lwin
- Mr. Prasiddha Kansakar