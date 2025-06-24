# Forensic Network Control System

This project implements a Django-based network control framework designed to provide **secure, selective Internet access for seized mobile devices** during forensic investigations. It integrates with the **OPNsense firewall** to enable fine-grained, case-specific rule management while minimising the risk of remote wipes or unintended data modification.

## 🧭 Purpose

Modern mobile devices require online access to retrieve cloud-based evidence (e.g., iCloud photos, WhatsApp chats, Binance transactions). However, uncontrolled network access poses a risk of data loss due to:
- Remote wipe commands
- Background sync
- Tracking or alert signals

This system allows forensic examiners to **safely bring devices online** in a controlled, monitored environment using:
- DNS-level filtering
- ISP-based rule grouping
- Enriched IP metadata
- Dynamic, per-device firewall rule enforcement

## 🔧 Features

- 🔐 Selective firewall rule control (via the OPNsense API)
- 📄 DNS and IP logging per device
- 🌍 IP enrichment using third-party services (e.g., `ip-api.com`)
- 🧠 Automated rule creation based on observed DNS/IP activity
- 🖥️ Web interface for investigators to monitor and control network access
- 🔎 Log views showing allowed/blocked connections with metadata
- 🧱 Alias support for high-performance rule handling (via OPNsense)

## 📦 Tech Stack

- Python 3.10+
- Django 4.x
- PostgreSQL (or any Django-supported DB)
- OPNsense Firewall (Tested on version 25.1 "Ultimate Unicorn")
- Bootstrap/Tailwind CSS (for frontend)
- Optional: `ip-api.com` for IP enrichment

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

### 2. Set Up a Virtual Environment
python3 -m venv venv
source venv/bin/activate

### 3. Install Dependencies
pip install -r requirements.txt

### 4. Configure Environment Variables
Create a .env file or set these manually:
API_KEY=
API_SECRET=
OPNSENSE_IP=

### 5. Apply Migrations and Create a Superuser
python manage.py migrate
python manage.py createsuperuser

### 6. Start the Development Server
python manage.py runserver 0.0.0.0:8000