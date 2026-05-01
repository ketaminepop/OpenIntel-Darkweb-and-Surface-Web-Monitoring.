<div align="center">

# 🕵️ OPEN INTEL

### Full-Spectrum OSINT Intelligence Platform

*Surface Web · Dark Web · Threat Intelligence · AI-Powered Analysis*

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40+-FF4B4B?style=flat&logo=streamlit&logoColor=white)](https://streamlit.io)
[![Tor](https://img.shields.io/badge/Tor-Integrated-7D4698?style=flat&logo=tor-project&logoColor=white)](https://torproject.org)
[![AI](https://img.shields.io/badge/AI-LLaMA_3.3_70B-00A67E?style=flat&logo=meta&logoColor=white)](https://groq.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Educational](https://img.shields.io/badge/Purpose-Educational_Research-blue?style=flat)](#disclaimer)

<img src="https://img.shields.io/badge/Dark%20Web%20Search-17%20Engines-7D4698?style=for-the-badge" />
<img src="https://img.shields.io/badge/OSINT%20Modules-12+-00b4ff?style=for-the-badge" />
<img src="https://img.shields.io/badge/Concurrent%20Scanning-✓-22c55e?style=for-the-badge" />

</div>

---

## 📌 What is OPEN INTEL?

**OPEN INTEL** is a comprehensive, open-source OSINT (Open Source Intelligence) platform built for security researchers and threat analysts. It combines **dark web monitoring via Tor**, **surface web intelligence gathering**, and **AI-powered threat analysis** into a single unified Streamlit dashboard.

Built as a cybersecurity research project to demonstrate real-world threat intelligence workflows aligned with **SOC analyst operations**.

---

## ✨ Features

| Module | Description |
|--------|-------------|
| 🧅 **Dark Web Scan** | Queries 17 Tor search engines concurrently for target intelligence |
| 📋 **Paste Monitor** | Monitors Pastebin, GitHub, and IntelX for exposed data |
| 🔐 **Breach Validator** | Multi-source email breach checking (HIBP, LeakLookup, local DB) |
| 📡 **Real-Time Monitor** | Continuous background scanning with live alerts |
| 🌐 **Surface Web OSINT** | WHOIS, DNS recon, subdomain enumeration, tech fingerprinting |
| 🔍 **Domain & IP Intel** | IP intelligence, ASN reputation, zone transfer checks |
| 👤 **Identity OSINT** | Username hunting across 50+ platforms, email/phone analysis |
| 🦠 **Threat Intel** | IOC enrichment via AlienVault OTX, URLhaus, MalwareBazaar, ThreatFox |
| 🤖 **AI Analysis** | LLaMA-3.3-70B threat analysis via Groq (free tier) |
| 📄 **Report Export** | Download full intelligence reports as Markdown or JSON |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Tor installed and running
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/namanvaishnav/openintel.git
cd openintel
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Set Up Environment Variables

```bash
# Copy the example env file
cp .env.example .env

# Edit .env and add your API keys
nano .env
```

Your `.env` file should look like:

```env
GROQ_API_KEY=your_groq_api_key_here
```

> **Get a free Groq API key** at [console.groq.com](https://console.groq.com) — Free tier gives 14,400 requests/day.
>
> **Alternatively**, you can enter your API key directly in the sidebar of the app — no .env file needed.

### 4. Start Tor

```bash
# Linux / WSL
sudo service tor start

# macOS (Homebrew)
brew services start tor

# Verify Tor is running
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

### 5. Run the App

```bash
streamlit run app.py
```

Open your browser at `http://localhost:8501`

---

## 🔑 API Key Configuration

OPEN INTEL supports two ways to provide your Groq API key:

### Option A — Sidebar UI (No setup needed)
Just paste your key into the **🤖 AI Configuration** section in the sidebar when the app loads. Key is never stored.

### Option B — .env File (Recommended for regular use)
```bash
cp .env.example .env
# Add your key to .env
GROQ_API_KEY=gsk_your_key_here
```

> **Priority:** Sidebar input overrides .env file. Both are secure — key is never committed to GitHub.

---

## 📁 Project Structure

```
openintel/
├── app.py              # Main Streamlit application & UI
├── search.py           # Dark web search engine queries via Tor
├── scrape.py           # Web scraping, paste monitoring, breach check
├── surface_web.py      # Surface web OSINT modules (12 functions)
├── requirements.txt    # Python dependencies
├── .env.example        # Environment variable template
├── .gitignore          # Git ignore rules (protects .env)
└── README.md           # This file
```

---

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| **Streamlit** | Web UI framework |
| **Tor / SOCKS5** | Dark web anonymization & routing |
| **BeautifulSoup4** | HTML parsing & scraping |
| **Requests + PySocks** | HTTP requests via Tor proxy |
| **Stem** | Tor control protocol (identity rotation) |
| **Groq API + LLaMA 3.3 70B** | AI-powered threat analysis |
| **Agno** | AI agent framework |
| **ThreadPoolExecutor** | Concurrent scanning |
| **python-dotenv** | Environment variable management |

---

## 🔒 Security & Privacy

- All dark web queries route through **Tor** (`socks5h://127.0.0.1:9050`)
- Supports **Tor identity rotation** (new circuit on demand)
- API keys are **never logged, stored, or transmitted** beyond the API call
- `.env` is in `.gitignore` — your keys never reach GitHub
- Built for **authorized security research only**

---

## ⚙️ Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| Scrape Threads | 20 | Concurrent scraping workers |
| Max Links | 15 | Maximum links to scrape per scan |
| Search Workers | 12 | Concurrent search engine queries |
| Paste Monitoring | ✅ | Enable paste site scanning |
| AI Analysis | ✅ | Enable LLaMA threat analysis |
| Filter Duplicates | ✅ | Deduplicate onion domains |
| Generate Report | ✅ | Auto-generate downloadable report |

---

## 📖 Module Details

### 🧅 Dark Web Scan
Queries **17 Tor-based search engines** concurrently including Ahmia, Tor66, DarkSearch, and others. Results are scraped, deduplicated, and analyzed for keyword relevance. Relevant findings are fed into the AI analysis pipeline.

### 📋 Paste Monitor
Multi-source paste monitoring using:
- **Psbdmp** — Pastebin index search
- **GitHub Code Search** — Public repository scanning
- **IntelX Phonebook** — Intelligence X public search

### 🔐 Breach Validator
Three-layer breach detection:
1. HIBP unofficial unified search
2. LeakLookup free public API
3. Local domain-based breach database (offline fallback)

### 🌐 Surface Web OSINT (12 Modules)
WHOIS/RDAP · DNS Recon · Subdomain Enumeration · IP Intelligence · Username Hunt (50+ platforms) · Google Dorking · Wayback Machine · Email OSINT · Phone Intelligence · Certificate Transparency · Tech Fingerprinting · Security Audit

### 🦠 Threat Intel — IOC Enrichment
Supports: **IP · Domain · URL · Hash (MD5/SHA1/SHA256)**
Sources: AlienVault OTX · URLhaus · MalwareBazaar · ThreatFox

---

## ⚠️ Disclaimer

> **This tool is built strictly for educational purposes and authorized security research.**
>
> - Only use on systems and networks you have **explicit written permission** to test
> - Dark web access is legal in most countries for research — but **what you do with findings** may not be
> - The author is **not responsible** for any misuse of this tool
> - Comply with your country's laws and your organization's policies
> - This is a **student research project** — not a commercial product

---

## 👤 Author

**Naman Vaishnav**
Cybersecurity Researcher | CEH Certified | TryHackMe Top 3% | B.Tech IT — CHARUSAT University

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat&logo=linkedin)](https://linkedin.com/in/ketaminepop)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-Top_3%25-212C42?style=flat&logo=tryhackme)](https://tryhackme.com/p/ketaminepop)
[![Email](https://img.shields.io/badge/Email-vaishnavnaman150@gmail.com-EA4335?style=flat&logo=gmail)](mailto:vaishnavnaman150@gmail.com)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
<sub>Built with 🔐 for cybersecurity research · Star ⭐ if this helped you</sub>
</div>
