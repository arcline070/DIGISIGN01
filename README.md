# College Major - Cryptographic Document Signing System

This repository contains a full-stack cryptographic document signing and verification system. It features a Django/Python backend that securely hashes and signs payloads (using RSA/ECDSA) and an Angular frontend that manages the cryptographic workflows, benchmarking, and exporting verifiable documents to PDF.

## 🚀 Getting Started

To get this project running locally, you will need to start both the **Backend** and the **Frontend**.

---

### 1. Backend Setup (Django)

The backend is built with Python and Django. It handles cryptographic signatures, database records, and verification APIs.

**Prerequisites:** Python 3.8+

1. **Navigate to the backend directory:**
   ```bash
   cd backend
   ```

2. **Create and activate a virtual environment:**
   - **Windows:**
     ```bash
     python -m venv venv
     venv\Scripts\activate
     ```
   - **Mac/Linux:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Variables:**
   - Copy the example environment file to `.env`:
     - **Windows:**
       ```bash
       copy .env.example .env
       ```
     - **Mac/Linux:**
       ```bash
       cp .env.example .env
       ```
   - *Note: Ensure your `.env` contains any required keys mentioned in the `.env.example`. (If prompted to overwrite, you can safely skip this step if a `.env` already exists).*

5. **Run Migrations:**
   ```bash
   python manage.py migrate
   ```

6. **Start the Django Development Server:**
   ```bash
   python manage.py runserver
   ```
   *The backend will now be running on `http://127.0.0.1:8000`*

---

### 2. Frontend Setup (Angular)

The frontend is an Angular 19+ application.

**Prerequisites:** Node.js (v18+) and npm.

1. **Open a new terminal and navigate to the frontend directory:**
   ```bash
   cd frontend
   ```

2. **Install Node modules:**
   ```bash
   npm install
   ```

3. **Start the Angular Development Server:**
   ```bash
   npx ng serve
   ```
   *The frontend will now be running on `http://localhost:4200`*

---

### 🌟 Usage

1. Go to `http://localhost:4200` in your browser.
2. The Angular UI will automatically communicate with the Django backend at `localhost:8000`.
3. You can explore the Cryptographic Signing tools, the Diff Engine, the Benchmark tabs, and the PDF QR-Verification systems.
