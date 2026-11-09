# 🛡️ TRINEX Shield

> **TRINEX Shield** is an intelligent, multi-layered threat detection engine that verifies malicious links in real-time, analyzes social engineering scam messages, and anchors verifiable audit reports on-chain.
## 2. Problem

Modern cyber threats exploit user blind spots using advanced deceptive techniques:
- **Homograph & Typo-squatting Attacks:** Deceptive look-alike domains (e.g., Punycode scripts) bypass visual inspection and traditional blocklists.
- **Social Engineering in Direct Messaging:** Urgent, coercive messages across SMS, WhatsApp, and email push users into clicking fraudulent links before threat intelligence feeds can index them
- **Malleable & Untrusted Audit Logs:** Centralized security audit logs can be forged, manipulated, or altered after an incident occurs, making verifiable post-mortem forensic analysis difficult

## 3. Solution

TRINEX Shield provides an end-to-end protective pipeline combining automated heuristic analysis, active threat feeds, and cryptographic anchoring:
- **Heuristic URL & TLS Scanner:** Decomposes URL anatomy, detects brand look-alikes/typosquatting, audits TLS certificate chains, and grades security header hardening in real time.
- **Scam Message Diagnostics:** Employs NLP and pattern recognition to flag social engineering coercion, false urgency, and payment extortion vectors in message texts.
- **Tamper-Evident On-Chain Anchoring:** Generates cryptographic SHA-256 fingerprints of every scan payload and anchors them on-chain, ensuring audit trail integrity that cannot be modified after an incident.
- **Unified Threat Dashboard:** Aggregates live feeds from OpenPhish, Certificate Transparency logs, and local threat datasets with linked campaign correlation
## 4. Demo links

- **Live Application:** [https://trinex-shield.vercel.app](https://trinex-shield.vercel.app)
- **Demo Video Walkthrough:** [https://youtu.be/-483BJbmRDU](https://youtu.be/-483BJbmRDU)
## 5. Tech stack

- **Frontend & UI:** HTML5, CSS3, Modern JavaScript (ES6+), responsive cyber-defense dashboard design
- **Backend & Detection Engine:** Python (FastAPI / HTTP server runtime)
- **Security & Threat Intelligence:** Lexical URL parser, OpenPhish feeds, Certificate Transparency (crt.sh) logs, SSL/TLS handshake validators
- **Cryptography & Web3 Anchoring:** SHA-256 payload hashing, simulated distributed ledger state verification, tamper-evident registry
- **Hosting & Deployment:** Vercel (Edge deployment)
## 6. Architecture

- **Ingestion Layer:** Captures target inputs via URL inspector or scam message interface.
- **Lexical & Parsing Engine:** Decomposes target anatomy into protocol schemes, subdomains, registered domains, and TLDs.
- **Multi-Vector Threat Analysis:**
  - *Heuristic URL Scanner:* Analyzes typosquatting, homographs, brand look-alikes, SSL/TLS certificate chains, and HTTP header hardening.
  - *Message Parser:* Extracts psychological manipulation, coercive urgency triggers, and suspicious financial vectors.
- **Cryptographic & Ledger Pipeline:** Computes a unique SHA-256 fingerprint for every investigation report and anchors the hash on-chain.
- **Verification & Telemetry Layer:** Provides instant cryptographic tampering validation alongside a unified real-time dashboard aggregating OpenPhish, crt.sh, and linked attack campaigns
## 7. Setup and run steps

Prerequisites:
- Python 3.9+ installed
- Git installed
- Modern web browser

Local Installation and Execution:
1. Clone the repository:
   git clone https://github.com/swayamshoubinsahoo/TRINEX-Shield.git
   cd TRINEX-Shield

2. Set up virtual environment:
   python -m venv venv
   venv\Scripts\activate

3. Install dependencies:
   pip install -r requirements.txt

4. Run the local backend:
   python -m http.server 8000

5. Open in browser:
   http://localhost:8000 (or access the live production deployment at https://trinex-shield.vercel.app)
## 8. Disclosures (libraries, templates, AI tools)

- **Third-Party Libraries & Frameworks:**
  - Modern HTML5/CSS3 custom glassmorphic UI system (no external heavy frontend frameworks).
  - Python standard library (`http.server`, `urllib`, `hashlib`, `json`) for backend routing and lightweight execution.
  - Integration with OpenPhish public threat feeds and crt.sh Certificate Transparency API.

- **Templates & Boilerplates:**
  - Custom UI/UX layout crafted and styled from scratch specifically for TRINEX Shield.
  - Zero pre-built website templates used.

- **AI Tools Usage:**
  - LLMs (Google Gemini) were used for ideation brainstorming, syntactic code review, test case generation, and structuring documentation.
## 9. Track

- **Primary Track:** Cybersecurity / Threat Intelligence & Defense
- **Secondary Track:** Web3 & Trustless Auditing / AI & Automation
