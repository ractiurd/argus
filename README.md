## 🕊️ We Stand With Palestine

We stand in solidarity with the Palestinian people against Israel's ongoing genocide and military occupation. We condemn the systematic violence that has claimed thousands of innocent lives, including countless children, and destroyed homes, hospitals, and schools.

We affirm Palestine's right to exist, resist, and achieve liberation. From the river to the sea, Palestine will be free.



# Argus - Advanced Shodan Reconnaissance Tool
Argus is a powerful, fully-featured reconnaissance tool built in Go, designed for cybersecurity researchers, penetration testers, and bug bounty hunters who rely on **Shodan OSINT intelligence** for mapping attack surfaces.

This tool automates domain reconnaissance, enumerates subdomains, discovers exposed IP addresses, queries ASNs and organizations, supports advanced Shodan dorks, and provides clean export-ready outputs.

---

## 📌 Purpose of Argus
Argus is built to streamline reconnaissance during cybersecurity assessments by leveraging the Shodan API. Instead of manually crafting Shodan queries, switching between endpoints, or parsing results, Argus automates the entire reconnaissance pipeline.

### ✔ What Argus Solves
- Automatically discovers subdomains for a target domain from multiple Shodan endpoints.
- Extracts IPs associated with domains, organizations, and ASNs.
- Performs complex Shodan dorking with predefined queries.
- Filters results based on HTTP status codes.
- Stores and manages your Shodan API key securely.
- Provides clean, deduplicated output (subdomains, IPs, etc.).
- Exports results to files in one command.

### ✔ Who Is This Tool For?
- Penetration testers
- Bug bounty hunters
- OSINT investigators
- Red teamers
- Cybersecurity engineers
- Students learning Shodan API

---

## 🚀 Key Features
### 🔍 **1. Domain Reconnaissance**
Extract:
- Subdomains
- DNS entries
- IP addresses associated with the domain
- Hostnames found in Shodan’s host search
- Subdomain records from `dns/domain` and `host/search`

Argus performs:
- Regex filtering
- JSON parsing
- Shodan DNS enumeration
- Shodan host search scraping

### 🛰 **2. ASN Enumeration**
Search using:
```
asn:"AS12345"
```
Results include:
- All IPs in that ASN
- Hostnames attached to those IPs
- Optional subdomain extraction
- Optional HTTP status filtering

### 🏢 **3. Organization Recon**
Search using:
```
org:"Cloudflare"
```
Extract:
- All IPs associated with an organization
- Hostnames / subdomains
- HTTP status-specific assets (e.g., only 200/404)

### 🔐 **4. API Key Management**
Argus automatically:
- Reads your API key from:  
  `~/go/pkg/shodanapikey.txt`
- Prompts you if no key exists
- Allows updating using:
  ```
  -capi NEW_KEY
  ```

Securely stored with `0600` permissions.

### 🎯 **5. Predefined Dork Selector**
Argus includes common Shodan dorks such as:
- Certificate CN search  
  `ssl.cert.subject.CN:"%s"`
- Hostname dork  
  `hostname:"%s"`
- SSL match  
  `ssl:"%s"`

You may also append HTTP status filters.

### 📊 **6. Output Control**
Flags allow showing:
- **Subdomains only** (`-s`)
- **IPs only** (`-i`)
- **Both** (default)

### 💾 **7. File Export**
You can export results to a file while keeping all output **unique and deduplicated**:
```
-o results.txt
```

---

## 📦 Installation
```
go install github.com/ractiurd/argus@latest
```

---

## 🧪 Usage Examples

### ▶ Basic domain scan
```
argus -t example.com
```

### ▶ Export only subdomains to a file
```
argus -t example.com -s -o subs.txt
```

### ▶ Scan an ASN for open hosts
```
argus -asn AS15169
```

### ▶ Scan an organization (Cloudflare)
```
argus -org "Cloudflare"
```

### ▶ Filter results by HTTP status code
```
argus -t example.com -r 200,403
```

### ▶ Use predefined dorks
```
argus -t example.com -c
```

### ▶ Replace stored API key
```
argus -capi NEW_API_KEY
```

---

## 📚 Command-Line Flags

| Flag | Purpose |
|------|---------|
| `-t` | Target domain |
| `-asn` | Search by ASN number |
| `-org` | Search by organization name |
| `-s` | Print only subdomains |
| `-i` | Print only IP addresses |
| `-c` | Choose predefined Shodan dork |
| `-r` | Filter by HTTP status codes |
| `-o` | Save results to file |
| `-api` | Provide API key directly |
| `-capi` | Update stored API key |
| `-h` | Show help |

---

## 🔧 How It Works (High-Level Overview)

### 1. **Shodan Host Search**
Argus queries:
```
https://api.shodan.io/shodan/host/search
```
This returns:
- IPs
- Hostnames
- Additional metadata (filtered)

### 2. **Shodan DNS Enumeration**
Queries:
```
https://api.shodan.io/dns/domain/{target}
```
This returns:
- Subdomains (JSON: `subdomains`)
- DNS records
- Last-seen timestamps

### 3. **Data Filtering & Deduplication**
Everything stored via:
```
map[string]bool
```
Ensures clean results.

### 4. **Regex Subdomain Extraction**
Matches:
```
*.target.com
```

### 5. **API Key Handling**
Securely saves or loads depending on user options.

---

## 🧑‍💻 Developer Notes
- Written in **Go**
- Uses Shodan’s REST API
- Regex-based filtering
- Supports custom dorks
- Easy to modify for future expansions

---

## 🏁 Conclusion
Argus is a robust, multi-feature Shodan reconnaissance toolkit intended to automate and accelerate the information-gathering phase of security research. Whether you're scanning domains, mapping infrastructure, or discovering exposed assets, Argus provides an efficient, automated workflow for Shodan-based intelligence.


---

## 👤 Author
**Ractiurd**  
Twitter: twitter.com/ractiurd  
Facebook: facebook.com/Ractiurd  


