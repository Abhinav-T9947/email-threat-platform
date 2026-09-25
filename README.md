# AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

An AI-powered cybersecurity platform for analyzing suspicious emails, detecting phishing indicators, performing email forensics, assessing threat intelligence, and preserving forensic evidence integrity using SHA-256 hashing and blockchain.

## Overview

The platform analyzes `.eml` email files from multiple forensic perspectives:

* Machine-learning-based phishing detection
* SPF, DKIM, and DMARC analysis
* Sender and domain analysis
* Email relay / `Received` header analysis
* URL and domain threat analysis
* IP intelligence and geolocation
* Attachment security analysis
* Explainable threat scoring
* SHA-256 evidence integrity
* SHA-256 forensic report integrity
* Blockchain-based evidence registration
* Blockchain integrity verification
* Persistent forensic case storage
* Web-based investigation dashboard

The system is designed around the principle that **original email content and forensic reports should remain off-chain**, while cryptographic hashes are recorded on the blockchain to provide tamper-evident integrity verification.

---

## Architecture

```text
                         EMAIL INPUT
                             |
              +--------------+--------------+
              |              |              |
           Headers         Body           Attachments
              |              |              |
              v              v              v
       Authentication       ML         Attachment
       SPF/DKIM/DMARC     Detection       Analysis
              |              |              |
              +--------------+--------------+
                             |
                    +--------v--------+
                    | Forensic Engine |
                    +--------+--------+
                             |
              +--------------+--------------+
              |              |              |
          URL Analysis   IP Intelligence  Relay Analysis
              |              |              |
              +--------------+--------------+
                             |
                    Threat Assessment
                             |
                +------------+------------+
                |                         |
          Evidence SHA-256          Report SHA-256
                |                         |
                +------------+------------+
                             |
                    Blockchain Layer
                             |
                    Integrity Verification
                             |
                    Forensic Dashboard
```

---

## Main Features

### 1. Machine Learning Phishing Detection

The platform uses a TF-IDF text representation with Logistic Regression to classify email content as:

* Phishing
* Legitimate

The model also produces a phishing probability that contributes to the overall threat assessment.

The trained model artifacts are stored in:

```text
ml/models/
├── phishing_model.joblib
└── tfidf_vectorizer.joblib
```

The original training dataset is intentionally excluded from the GitHub repository because of its size.

---

### 2. Email Authentication Analysis

The forensic engine analyzes:

* SPF
* DKIM
* DMARC
* Authentication domains
* Return-Path alignment
* Domain relationships

Authentication results are treated as forensic indicators rather than standalone proof that an email is malicious.

---

### 3. Sender Analysis

The system compares:

* Visible `From` address
* `Return-Path`
* `Reply-To`

Domain mismatches are reported as suspicious indicators.

---

### 4. Email Relay Analysis

The platform parses `Received` headers and reconstructs the relay path.

It can identify:

* Relay hops
* Source servers
* Destination servers
* Source IP addresses
* Protocol information
* Timestamp ordering anomalies
* Missing or malformed relay information

---

### 5. URL and Domain Intelligence

URLs are extracted from email content and checked for indicators such as:

* HTTP instead of HTTPS
* IP-address-based URLs
* URL encoding
* Punycode domains
* Long domains
* Many subdomains
* Suspicious characters

These indicators contribute to the explainable threat score.

---

### 6. IP Intelligence & Geolocation

Extracted IP addresses are classified into categories such as:

* Private
* Loopback
* Link-local
* Documentation/test networks
* Reserved
* Multicast
* Public

Public IP addresses can also be enriched with geolocation and network information during development.

---

### 7. Attachment Analysis

Attachments are inspected using static metadata such as:

* Filename
* Extension
* MIME type
* File size
* Suspicious extensions
* Double extensions

Examples of potentially dangerous extensions include:

```text
.exe
.scr
.bat
.cmd
.js
.vbs
.ps1
.msi
.jar
```

The platform does **not execute attachments**.

---

### 8. Explainable Threat Scoring

The system combines forensic indicators into an explainable threat score from 0–100.

Example indicators include:

* Authentication failures
* Sender mismatches
* Phishing probability
* Suspicious URLs
* Public IP addresses
* Suspicious attachments
* Relay anomalies

The score is categorized as:

```text
0–39     Low
40–69    Medium
70–100   High
```

The score is an application-specific risk indicator, **not a calibrated probability of maliciousness**.

---

# Blockchain Evidence Integrity

Blockchain is used specifically for **forensic integrity**, not for storing the contents of emails.

For each analyzed case, the platform calculates:

```text
SHA-256(original email)
SHA-256(forensic report)
```

The blockchain record stores information such as:

```text
Case ID
Evidence SHA-256
Report SHA-256
Timestamp
```

This allows investigators to later compare the current evidence and report hashes against the blockchain record.

### Verification

A successful verification produces matching evidence and report hashes.

If the email or forensic report is modified after registration, the resulting hash changes and the integrity check can detect the mismatch.

The project uses a local Ganache blockchain during development.

---

## Persistent Blockchain Storage

The development blockchain uses Ganache with a persistent database directory.

Local blockchain data is intentionally excluded from GitHub:

```text
ganache-data/
ganache-data-old/
```

This prevents local blockchain state and development artifacts from being committed to the repository.

---

## Forensic Case Storage

Case metadata is stored locally using SQLite through SQLAlchemy.

Stored information includes:

* Case ID
* Evidence hash
* Report hash
* Blockchain transaction hash
* Block number
* Creation timestamp

Local database files are excluded from GitHub.

---

# Project Structure

```text
email-threat-platform/
│
├── backend/
│   ├── blockchain/
│   │   └── blockchain_ledger.py
│   ├── database.py
│   ├── evidence_hash.py
│   └── main.py
│
├── email_forensics/
│   ├── __init__.py
│   ├── attachment_analyzer.py
│   ├── authentication_analyzer.py
│   ├── eml_parser.py
│   ├── forensic_integrity.py
│   ├── forensic_result.py
│   ├── relay_analyzer.py
│   ├── sender_analysis.py
│   ├── url_analyzer.py
│   └── test_*.eml
│
├── frontend/
│   └── index.html
│
├── ml/
│   ├── models/
│   │   ├── phishing_model.joblib
│   │   └── tfidf_vectorizer.joblib
│   ├── email_ml_detector.py
│   ├── inspect_dataset.py
│   ├── predict_email.py
│   └── train_model.py
│
├── threat_intelligence/
│   ├── domain_intelligence.py
│   ├── ip_geolocation.py
│   ├── ip_intelligence.py
│   └── threat_scoring.py
│
├── .env
├── .gitignore
├── hardhat.config.ts
├── package.json
├── package-lock.json
├── tsconfig.json
└── README.md
```

> `.env`, local databases, blockchain data, and the large training dataset are intentionally excluded from version control.

---

# Technology Stack

## Backend

* Python
* FastAPI
* SQLAlchemy
* SQLite
* Web3.py

## Machine Learning

* scikit-learn
* TF-IDF
* Logistic Regression
* Joblib

## Email Forensics

* Python email parsing
* Header analysis
* URL analysis
* Attachment metadata analysis
* IP intelligence

## Blockchain

* Ethereum-compatible local blockchain
* Ganache
* Solidity / Hardhat tooling
* Web3.py

## Frontend

* HTML
* CSS
* JavaScript

---

# Running the Project Locally

## 1. Clone the repository

```powershell
git clone https://github.com/Abhinav-T9947/email-threat-platform.git
cd email-threat-platform
```

## 2. Create and activate the Python environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

## 3. Install Python dependencies

Install the Python packages required by the backend and machine-learning components.

For a reproducible project, these dependencies should be documented in a requirements file or equivalent environment configuration.

## 4. Configure environment variables

Create a `.env` file in the project root:

```env
GANACHE_RPC_URL=http://127.0.0.1:8546
```

**Never commit `.env` to GitHub.**

The repository intentionally does not contain the development private key.

## 5. Start Ganache

Example:

```powershell
ganache --server.port 8546 --database.dbPath C:\path\to\ganache-data --wallet.deterministic
```

The blockchain configuration must match the environment variables used by the backend.

## 6. Start the FastAPI backend

```powershell
uvicorn backend.main:app --reload
```

The backend exposes the API used by the investigation dashboard.

## 7. Start the frontend

From the project root:

```powershell
python -m http.server 5500 --directory frontend
```

Then open:

```text
http://127.0.0.1:5500/index.html
```

---

# Example Investigation Workflow

```text
1. Upload .eml
       |
2. Parse email
       |
3. Analyze headers
       |
4. Analyze body with ML
       |
5. Analyze URLs
       |
6. Analyze IP addresses
       |
7. Analyze attachments
       |
8. Calculate threat score
       |
9. Generate forensic report
       |
10. Hash evidence
       |
11. Hash report
       |
12. Register hashes on blockchain
       |
13. Store case metadata
       |
14. Verify integrity
```

---

# API Overview

The FastAPI backend provides endpoints for email analysis and forensic integrity verification.

### Analyze an email

```text
POST /analyze-email
```

Accepts an `.eml` file and performs the complete forensic analysis workflow.

### Verify integrity

```text
POST /verify-integrity
```

Verifies evidence and forensic report hashes against the blockchain record.

### Verify uploaded evidence

```text
POST /verify-evidence
```

Calculates the hash of currently supplied evidence and compares it with the blockchain record.

### Retrieve a case

```text
GET /cases/{case_id}
```

Retrieves stored forensic case metadata.

---

# Testing

The project contains synthetic `.eml` files for testing different forensic scenarios, including:

* Standard suspicious email
* Authentication failures
* Authentication pass scenario
* Suspicious attachment
* URL threats
* Public IP / geolocation
* Tampered email evidence

The test emails are synthetic development artifacts and should not be interpreted as real-world threat intelligence.

---

# Security Considerations

The project follows several security practices:

* Private credentials are stored in environment variables.
* `.env` is excluded from Git.
* Local blockchain data is excluded from Git.
* Local databases are excluded from Git.
* Large training data is excluded from Git.
* Email attachments are analyzed statically and are not executed.
* Email contents are not stored on the blockchain.
* Only cryptographic integrity information is registered on-chain.

For production deployment, additional controls would be required, including:

* Secure secret management
* Authentication and authorization
* HTTPS
* Rate limiting
* Hardened blockchain infrastructure
* Secure file storage
* Malware sandboxing
* Security logging
* Privacy controls
* Input validation
* Access control

---

# Limitations

This is a cybersecurity research and development platform and should not be treated as a complete production email security gateway.

Important limitations include:

* ML performance on the training/test dataset may not represent real-world performance.
* The threat score is a heuristic risk score, not a probability.
* SPF/DKIM/DMARC parsing from email headers does not replace authoritative mail-server verification.
* IP geolocation data can be approximate and may become outdated.
* URL indicators are heuristic and do not by themselves prove malicious intent.
* Attachment analysis is static and does not perform sandbox execution.
* Local Ganache is intended for development/testing, not production blockchain infrastructure.
* Threat-intelligence enrichment may depend on external services and their availability, rate limits, and terms of use.

---

# Future Improvements

Potential extensions include:

* Gmail integration
* Microsoft 365 integration
* Mail-server/webhook ingestion
* Real-time threat-intelligence feeds
* URL reputation services
* Attachment sandboxing
* User authentication
* Case-management workflows
* Production database
* Production blockchain infrastructure
* Dashboard analytics and visualization
* Automated alerting
* Improved ML training and evaluation on diverse real-world datasets

---

# Project Status

Core development is functional and includes:

* Email forensic analysis
* ML phishing detection
* Threat scoring
* Evidence hashing
* Report hashing
* Blockchain registration
* Blockchain verification
* Persistent local blockchain storage
* Forensic case storage
* Investigation dashboard
* Tamper-detection testing

The project is currently in the **testing, documentation, and presentation-polish phase**.

---

# Disclaimer

This project is intended for cybersecurity education, research, development, and controlled testing.

Do not use the platform to analyze email data that you are not authorized to access.

Do not execute suspicious attachments or links during testing.

The ML predictions, threat scores, IP intelligence, and URL indicators should be treated as investigative aids rather than definitive security verdicts.




