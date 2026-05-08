# Cybersecurity SOC Dashboard

A completely functional Security Operations Center dashboard built with React, Node.js, Python, and PostgreSQL. Features real-time packet sniffing, live threat maps, AI-based phishing detection, and vulnerability scanning.

## 🚀 How to Run the Project (From Scratch)

Whenever you open VS Code to work on or demo this project, you need to start 3 separate terminals. Open VS Code, click **Terminal -> New Terminal** at the top, and follow these steps:

### Terminal 1: Start the Database & Backend
*This connects to your PostgreSQL database and starts the API server.*
```powershell
cd backend
npm run dev
```

### Terminal 2: Start the Python AI & Sniffer
*This runs the Scikit-Learn models and connects to your Wi-Fi card using Npcap.*
*(Click the `+` icon or split button in your terminal panel to open a new one)*
```powershell
cd ml_service
.\.venv\Scripts\python.exe app.py
```

### Terminal 3: Start the React Frontend
*This launches the actual User Interface.*
*(Open one last terminal)*
```powershell
cd frontend
npm run dev
```

Once all three are running, open your browser and go to:
**http://localhost:5173**

---

## 🔑 Login Credentials

You can log in with the default demo account:
*   **Email:** `analyst@soc.local`
*   **Password:** `admin123`

*(You can also use the "Sign Up" button on the login screen to securely create a new account in the PostgreSQL database).*

## 🌟 Demo Checklist
When presenting this project to your evaluators, show these things in order:
1.  **Overview Dashboard:** Show the live metrics, interactive threat map, and real-time activity log.
2.  **Live Network Sniffer:** Go to the Network tab, toggle "Live Sniffing", and show actual packets from your Wi-Fi being analyzed in real-time.
3.  **URL Phishing:** Type `www.goggle.com` to show the AI catching a Typosquatting attack.
4.  **Web Scan:** Scan a test website to generate an instant vulnerability report.
5.  **Password Analyzer:** Type a weak password and watch it instantly query the HaveIBeenPwned API to show how many data breaches it appeared in.
6.  **Incident Tickets:** Show how the system automatically generated an Incident Ticket for the threats you just detected.
