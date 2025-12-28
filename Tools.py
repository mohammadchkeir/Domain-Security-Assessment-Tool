"""
Flask-based Domain Security Scanner with Web UI + Hunter.io & DeHashed Integration
Requirements:
  - Python 3.8+
  - pip install flask requests dnspython

Usage:
  - Set environment variables before running (optional for Shodan/MXToolbox):
      export FLASK_APP=flask_security_scanner.py
      export FLASK_ENV=development
      export SHODAN_API_KEY="your_shodan_key"
      export MXTOOLBOX_API_KEY="your_mxtoolbox_key"
  - Run: python flask_security_scanner.py
"""

from flask import Flask, request, jsonify
import os, time, requests, dns.resolver

# --------------------
# API Keys
# --------------------
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
MXTOOLBOX_API_KEY = os.getenv('MXTOOLBOX_API_KEY')

# Hunter.io API key
HUNTER_API_KEY = ""

# DeHashed API key & account email
DEHASHED_API_KEY = ""
DEHASHED_EMAIL = "your_dehashed_account_email_here"  # Replace with your DeHashed login email

# --------------------
# Flask App
# --------------------
app = Flask(__name__)

# --------------------
# DNS & Security Checks
# --------------------
def get_txt_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        return [''.join(p.decode() if isinstance(p, bytes) else str(p) for p in r.strings) for r in answers]
    except Exception:
        return []

def get_spf_record(domain):
    return next((t for t in get_txt_records(domain) if t.lower().startswith('v=spf1')), None)

def get_dmarc_record(domain):
    txts = get_txt_records(f'_dmarc.{domain}')
    return txts[0] if txts else None

def get_dkim_record(selector, domain):
    txts = get_txt_records(f"{selector}._domainkey.{domain}")
    return txts[0] if txts else None

def resolve_ipv4_all(domain):
    ips = set()
    try:
        answers = dns.resolver.resolve(domain, 'A', lifetime=5)
        for rdata in answers:
            ips.add(rdata.address)
    except Exception:
        pass
    return list(ips)

def measure_http_latency(domain):
    for scheme in ['https', 'http']:
        try:
            start = time.time()
            r = requests.get(f"{scheme}://{domain}", timeout=5)
            return int((time.time() - start) * 1000), r.status_code
        except Exception:
            continue
    return None, None

def shodan_host_lookup(ip):
    if not ip or not SHODAN_API_KEY:
        return None
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        r = requests.get(url, timeout=10)
        return r.json() if r.status_code == 200 else {"error": r.text}
    except Exception as e:
        return {"error": str(e)}

def score_from_checks(spf, dkim, dmarc, shodan_info_list, latency):
    score, breakdown = 0, {}
    breakdown['spf'] = 25 if spf and '-all' in spf else (15 if spf else 0)
    breakdown['dkim'] = 25 if dkim else 0
    breakdown['dmarc'] = 25 if dmarc and 'p=reject' in dmarc.lower() else (15 if dmarc else 0)
    ports_penalty = 0
    open_ports_set = set()
    vulns_set = set()
    for shodan_info in shodan_info_list:
        if not shodan_info or 'error' in shodan_info:
            continue
        for p in shodan_info.get('ports', []):
            open_ports_set.add(p)
            if p in [21, 22, 23, 445, 3389]:
                ports_penalty += 5
        vulns_data = shodan_info.get('vulns')
        if vulns_data:
            if isinstance(vulns_data, dict):
                for v in vulns_data.keys():
                    vulns_set.add(v)
                    ports_penalty += 3
            elif isinstance(vulns_data, list):
                for v in vulns_data:
                    vulns_set.add(v)
                    ports_penalty += 3
    breakdown['ports'] = max(0, 20 - ports_penalty)
    breakdown['reach'] = 5 if latency and latency < 200 else 2 if latency else 0
    score = sum(breakdown.values())
    return min(100, score), breakdown, sorted(open_ports_set), sorted(vulns_set)

# --------------------
# Hunter.io Integration
# --------------------
def get_company_emails(domain):
    """Get emails from Hunter.io for the given domain."""
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={HUNTER_API_KEY}"
    try:
        r = requests.get(url, timeout=10)
        data = r.json()
        emails = [item.get("value") for item in data.get("data", {}).get("emails", [])]
        return emails
    except Exception as e:
        print(f"[DEBUG] Hunter.io error for {domain}: {e}")
        return []

# --------------------
# DeHashed Integration
# --------------------
def check_email_dehashed(email):
    """Check an email in DeHashed for breaches."""
    try:
        r = requests.get(
            f"https://api.dehashed.com/search?query=email:{email}",
            auth=(DEHASHED_EMAIL, DEHASHED_API_KEY),
            timeout=10
        )
        return r.json()
    except Exception as e:
        print(f"[DEBUG] DeHashed error for {email}: {e}")
        return {}

# --------------------
# Web Routes
# --------------------
@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Scanner</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f7fa; color: #333; text-align: center; padding: 30px; }
            h1 { color: #222; }
            form { background: #fff; padding: 20px; border-radius: 8px; display: inline-block; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            input { padding: 10px; width: 250px; border: 1px solid #ccc; border-radius: 4px; }
            button { padding: 10px 20px; border: none; background: #28a745; color: #fff; border-radius: 4px; cursor: pointer; }
            button:hover { background: #218838; }
            pre { text-align: left; background: #272822; color: #f8f8f2; padding: 15px; border-radius: 8px; max-width: 800px; margin: 20px auto; overflow-x: auto; }
        </style>
    </head>
    <body>
        <h1>Security Scanner</h1>
        <form id="scanForm">
            <input type="text" id="domain" placeholder="Enter domain" required>
            <button type="submit">Scan</button>
        </form>
        <pre id="result">Enter a domain and click Scan...</pre>
        <script>
            document.getElementById('scanForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                const domain = document.getElementById('domain').value;
                document.getElementById('result').textContent = 'Scanning...';
                const res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: domain })
                });
                const data = await res.json();
                document.getElementById('result').textContent = JSON.stringify(data, null, 2);
            });
        </script>
    </body>
    </html>
    '''

@app.route('/api/scan', methods=['POST'])
def api_scan():
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    # SPF / DKIM / DMARC
    spf = get_spf_record(domain)
    dmarc = get_dmarc_record(domain)
    dkim = None
    for sel in ['default', 'google', 'mail', 'selector1']:
        rec = get_dkim_record(sel, domain)
        if rec:
            dkim = rec
            break

    # IP & Latency
    ips = resolve_ipv4_all(domain)
    latency, status = measure_http_latency(domain)

    # Shodan Info
    shodan_info_list = []
    for ip in ips:
        shodan_info_list.append(shodan_host_lookup(ip))

    # Score
    score, breakdown, open_ports, vulnerabilities = score_from_checks(spf, dkim, dmarc, shodan_info_list, latency)

    # Hunter.io emails
    emails = get_company_emails(domain)

    # DeHashed breach check
    breached_emails = {}
    for email in emails:
        breached_emails[email] = check_email_dehashed(email)

    return jsonify({
        "domain": domain,
        "public_ips": ips,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "open_ports": open_ports,
        "vulnerabilities": vulnerabilities,
        "score": score,
        "company_emails": emails,
        "breach_check": breached_emails
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
