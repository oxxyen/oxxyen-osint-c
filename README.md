# 🇷🇺✨ **OXXYEN STORAGE** — **Enterprise Russian OSINT Platform** (v5.0)  
> *Aggressive, scalable, and ethically-aware intelligence gathering for Russian digital ecosystems — built in pure C for maximum performance and minimal footprint.*  

---

### 🔍 Overview  
`enterprise_osint.c` is a high-performance, multithreaded OSINT (Open-Source Intelligence) engine specialized in Russian-language digital footprints. Designed for red teams, threat analysts, and privacy researchers, it combines deep integration with Russian platforms (**VK, Yandex, Avito, CIAN, Gosuslugi**, etc.) with enterprise-grade reliability, structured output, and advanced evasion techniques.

> **This is not a toy script** — it’s a battle-tested reconnaissance framework engineered to operate in restrictive, geo-fenced, and anti-bot environments typical of Russian web services.

---

### ✨ Key Features  

#### 🇷🇺 Russia-First Intelligence  
- Full support for **+7 E.164 phone numbers** with region/operator lookup  
- Deep scanning of **VKontakte, Yandex Mail/Disk/Music/Maps, Avito, CIAN, Youla, Sberbank, Tinkoff, MVD, FTS**, and more  
- Built-in **Russian area code database** with mobile/fixed-line classification and coverage metrics  

#### ⚙️ Enterprise Architecture  
- Thread-safe global state with **mutex-protected result aggregation**  
- **Dynamic memory management** with hard limits (**10MB/response**) to prevent OOM  
- **Connection pooling** via `curl_share` for DNS/SSL/cookie reuse  
- Structured **JSON/CSV output** with **SHA256 integrity hashes**  
- Comprehensive error handling, **signal safety** (`SIGINT`, `SIGTERM`, `SIGSEGV`), and graceful shutdown  

#### 🛡️ Anti-Detection & Bypass Toolkit  
- Rotating **user-agent spoofing** (including `YandexBot`)  
- **SSL/TLS verification bypass** for restrictive Russian CDNs  
- **GeoIP spoofing simulation** and residential proxy rotation logic  
- **Request throttling**, timing jitter, and referer spoofing  
- Built-in **metadata tagging** for auditability  

#### 📊 Professional Output  
- Color-coded terminal results with **risk/confidence indicators**  
- Progress bar, real-time stats, and executive summary  
- Automatic file export:  
  `russian_osint_enterprise_<target>_<timestamp>.{json,csv}`  

---

### 🧰 Requirements  

- **OS**: Linux (tested on **Arch**, Ubuntu)  
- **Compiler**: GCC ≥ 9 or Clang ≥ 12 (with `-std=gnu11`)  

#### Libraries:  
- `libcurl` (≥ 7.68)  
- `json-c` (≥ 0.15)  
- `openssl` (for SHA256)  
- `pthread` (POSIX threads)  

#### Install Dependencies (Arch Linux):  
```bash
sudo pacman -S gcc curl json-c openssl
```
#### Install Dependencies (Debian/Ubuntu)
```bash
sudo apt install libcurl4-openssl-dev libjson-c-dev libssl-dev build-essential
```

### 🛠️ Build & Run
#### Compile
```bash
gcc -O2 -Wall -Wextra -pthread \
    -lcurl -ljson-c -lssl -lcrypto \
    -o enterprise_osint enterprise_osint.c
```
#### Usage
```bash
# Phone intelligence (Russian format)
./enterprise_osint phone +79123456789

# Username reconnaissance
./enterprise_osint username ivan_ivanov
```

✅ **Valid formats:**

- **Phone**: `+7XXXXXXXXXX` (12 digits total)  
- **Username**: 2–256 chars, alphanumeric + `_ . -`

---

### 📁 Output Examples  

**JSON** (`russian_osint_enterprise_+79123456789_1729600000.json`):

```json
{
  "scan_info": {
    "scan_type": "russian_phone_intelligence",
    "target": "+79123456789",
    "timestamp": 1729600000,
    "version": "5.0-ENTERPRISE",
    "russian_focus": true
  },
  "statistics": {
    "total_results": 14,
    "total_requests": 22,
    "successful_requests": 19
  },
  "results": [
    {
      "platform": "VKontakte",
      "category": "Social Media",
      "url": "https://vk.com/rest/phone.html?phone=+79123456789",
      "details": "Profile exists - Russia's largest social network with 70M+ users",
      "confidence": 0.85,
      "risk_level": 2,
      "timestamp": 1729600001,
      "metadata": "Response: 0.82s | Status: 200",
      "data_hash": "a1b2c3d4..."
    }
  ]
}
```

### 🧪 Design Philosophy

- **Zero external dependencies** beyond standard C + `curl`/`json-c`  
- **No Python, no Node, no bloat** — just lean, auditable C  
- **Ethical by default**: all output includes disclaimers; no automated exploitation  
- **Extensible**: add new sources by implementing a single function + registering it in `tasks[]`

---

### ⚠️ Legal & Ethical Notice

This tool is for **authorized security research**, **penetration testing**, and **digital forensics only**.  
Use against systems you do **not own** or lack **explicit permission** to test is **illegal**.  
Russian government and financial platforms may **log or block your IP**. Use responsibly.

---

### 📬 Author & Support

- **Author**: OXXYEN STORAGE  
- **Telegram**: [@oxxyen](https://t.me/oxxyen)  
- **Project Tagline**: *"Privacy is a feature. Intelligence is a discipline."*

---

### 🚀 Future Roadmap

- Proxy integration (SOCKS5/HTTP)  
- Telegram bot auto-alerting  
- SQLite result persistence  
- CLI flags for output format, concurrency, timeout  

---

🔐 **Built for those who demand speed, precision, and discretion.**  
**OXXYEN AI — Where code meets conscience.**
