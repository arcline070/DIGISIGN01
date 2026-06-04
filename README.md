# DigiSign 🔏

DigiSign is an Enterprise Cryptographic Document Signing and Observability platform. It uses Zero-Trust immutability with RSA-SHA256 and ECDSA-P256-SHA256 asymmetric cryptography.

## Features
- **Cryptographic Engine:** Fast document signing and tamper detection.
- **Mission Control SOC Dashboard:** Live observability of your cryptographic ledger, active algorithm usage, and system telemetry.
- **Maker-Checker Security:** Support for enterprise document quarantine and admin authorization flow.
- **Live Audit Ledger:** Immutable logs of every sign, verify, and admin action.

## Prerequisites
- Node.js (v18+)
- Angular CLI
- Python 3.10+
- Django

## Setup Instructions

### 1. Backend (Django API)
1. Open a terminal and navigate to the `backend` folder.
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Mac/Linux:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run migrations and start the server:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   python manage.py runserver
   ```
   *The backend will run on `http://localhost:8000`.*

### 2. Frontend (Angular App)
1. Open a new terminal and navigate to the `frontend` folder.
2. Install Node modules:
   ```bash
   npm install
   ```
3. Start the Angular development server:
   ```bash
   npx ng serve
   ```
   *The frontend will run on `http://localhost:4200`.*

## Logging Bug Fix
The `backend/logs` directory is now correctly tracked in Git using a `.gitkeep` file so the Django application will not crash when you first clone the repository!
