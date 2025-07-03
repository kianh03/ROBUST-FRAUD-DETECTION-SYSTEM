# ROBUST-FRAUD-DETECTION-SYSTEM

A robust, AI-powered web application for detecting fraudulent URLs using advanced machine learning and rule-based analysis. This project combines deep learning, domain intelligence, and real-time web analysis to provide accurate risk assessments for suspicious links.

## Features

- **Deep Learning Model**: Uses a trained neural network to predict URL fraud risk.
- **Rule-Based Fallback**: Intelligent heuristics for risk scoring when the model is unavailable.
- **Comprehensive Feature Extraction**: Analyzes URL structure, domain info, HTML content, SSL, and more.
- **Firebase Authentication**: Secure user management and history tracking.
- **Modern Web Dashboard**: User-friendly interface for submitting URLs and viewing results.
- **API Endpoints**: RESTful endpoints for integration and automation.
- **Security Best Practices**: HTTPS, input validation, and safe model loading.

## Tech Stack

- **Backend**: Python, Flask, TensorFlow, Scikit-learn
- **Frontend**: Next.js (React), CSS
- **Database**: Firebase Firestore (for user history)
- **Model**: Keras `.h5` model, Scikit-learn scaler
- **Other**: BeautifulSoup, python-whois, requests

## Project Structure

```
frontend/
  app.py                # Main Flask backend
  model_service.py      # Model/scaler loading and prediction logic
  models/               # Trained ML models and scaler
  components/           # React/Next.js components
  pages/                # Next.js pages (login, dashboard, etc.)
  static/               # Static assets (CSS, JS, images)
  templates/            # HTML templates for Flask
  firebase/             # Firebase config and context
  key/                  # Firebase admin key (DO NOT COMMIT PUBLICLY)
  requirements.txt      # Python dependencies
  package.json          # Node.js dependencies
```

## Prerequisites

Before running the project, ensure you have the following tools installed:

- **Python** (Recommended: 3.8 or higher)  
  [Download Python](https://www.python.org/downloads/)  
  Check version:  
  ```bash
  python --version
  ```

- **Node.js** (Recommended: 16.x or higher)  
  [Download Node.js](https://nodejs.org/en/download/)  
  This will also install **npm** (Node Package Manager).  
  Check versions:  
  ```bash
  node --version
  npm --version
  ```

- **Git** (for cloning the repository)  
  [Download Git](https://git-scm.com/downloads)  
  Check version:  
  ```bash
  git --version
  ```

All required Python libraries will be installed via `requirements.txt` and Node.js libraries via `package.json` in the next steps.

## Quickstart

### 1. Clone the Repo

```bash
git clone https://github.com/kianh03/ROBUST-FRAUD-DETECTION-SYSTEM.git
cd ROBUST-FRAUD-DETECTION-SYSTEM/frontend
```

### 2. Install Python Dependencies

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Install Node.js Dependencies

```bash
npm install
```

### 4. Set Up Environment Variables

Create a `.env` file in `frontend/` with:

```
FLASK_SECRET_KEY=your-secret-key
FIREBASE_CREDENTIALS_PATH=key/fraudtest-23c54-firebase-adminsdk-fbsvc-6e8c35326e.json
BACKEND_URL=http://localhost:5001
MODEL_FILE=models/fraud_model.h5
```

### 5. Run the Backend

```bash
python app.py
```

## API Endpoints

- `POST /predict` — Predict fraud risk for a URL (JSON: `{ "url": "..." }`)
- `POST /analyze` — Full analysis report (JSON or PDF)
- `GET /health-check` — Service health status
- `POST /api/analyze-url` — Dashboard quick analyzer


---

## Model & Security

- **Model**: `models/fraud_model.h5` (Keras), `scaler.pkl` (Scikit-learn)
- **Security**: Uses HTTPS, input validation, and Firebase authentication.
- **Note**: Do not commit sensitive keys or model files to public repos.

---
