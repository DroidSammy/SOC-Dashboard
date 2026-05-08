# Cybersecurity SOC Dashboard

Mini Security Operations Center dashboard for a college minor project. The current MVP includes:

- Central analytics dashboard with live stats, charts, threat map, activity log, and incidents
- Phishing URL detector connected to the Python ML service
- Email phishing detector connected to the Python ML service
- Password strength and breach analyzer
- Web vulnerability scanner
- Simulated network anomaly detector
- CVE intelligence search with NVD fallback data
- Incident ticket workflow

## Project Structure

```text
backend/       Node.js + Express API, Socket.io, JSON demo database
frontend/      React + Vite + Tailwind dashboard
ml_service/    Flask analysis service and ML training scripts
```

## Backend Setup

PowerShell blocks `npm.ps1` on this PC, so use `npm.cmd`.

```powershell
cd backend
npm.cmd install
npm.cmd run dev
```

The backend runs on:

```text
http://localhost:4000
```

It stores demo incidents in:

```text
backend/data/db.json
```

The backend can work without Python by using built-in fallback rules. When the Python ML service is running, the backend automatically proxies ML requests to `http://localhost:5001`.

Demo login:

```text
Email: analyst@soc.local
Password: admin123
```

## Frontend Setup

PowerShell blocks `npm.ps1` on this PC, so use `npm.cmd`.

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```

Open the URL Vite prints, usually:

```text
http://localhost:5173
```

Build check:

```powershell
npm.cmd run build
```

## Python ML Service Setup

Install Python 3.11 or 3.12 first if `python --version` does not work.

```powershell
cd ml_service
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python train_models.py
python app.py
```

The service runs on:

```text
http://localhost:5001
```

The React app uses this automatically. To override it:

```powershell
$env:VITE_API_URL="http://localhost:4000"
npm.cmd run dev
```

## Demo Flow

1. Open Overview and show charts, live map, incidents, and activity log.
2. Run URL Scan with `http://paypal-verify-account.tk/login.php`.
3. Run Email Scan with the prefilled urgent account suspension email.
4. Open Tickets and show the auto-created incident.
5. Run Password Analyzer with `password123`, then try a stronger password.
6. Run Network -> Simulate Attack and show the incident creation.
7. Search CVE Intel for `Apache`.
8. Run Web Scan and export the PDF vulnerability report.

## Safe Scanning Note

Use the vulnerability scanner only on your own sites, local labs, or legal test targets such as intentionally vulnerable demo apps.
