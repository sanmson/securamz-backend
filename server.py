from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
import ssl
import socket
import dns.resolver
from datetime import datetime
import OpenSSL

app = Flask(__name__)
CORS(app)

def check_headers(url):
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                          headers={'User-Agent': 'SecuraMZ-Scanner/2.0'})
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "hsts": "strict-transport-security" in headers,
            "hsts_value": headers.get("strict-transport-security", ""),
            "csp": "content-security-policy" in headers,
            "csp_value": headers.get("content-security-policy", ""),
            "xframe": "x-frame-options" in headers,
            "xframe_value": headers.get("x-frame-options", ""),
            "xcto": "x-content-type-options" in headers,
            "xcto_value": headers.get("x-content-type-options", ""),
            "xss": "x-xss-protection" in headers,
            "referrer": "referrer-policy" in headers,
            "permissions": "permissions-policy" in headers,
            "server": headers.get("server", ""),
            "powered_by": headers.get("x-powered-by", ""),
        }
    except Exception as e:
        return {"error": str(e)}

def check_ssl(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(10)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            expires_str = cert['notAfter']
            expires = datetime.strptime(expires_str, '%b %d %H:%M:%S %Y %Z')
            days_left = (expires - datetime.utcnow()).days
            tls_version = s.version()
            cipher = s.cipher()

        cert_openssl = ssl.get_server_certificate((hostname, 443))
        x509 = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert_openssl
        )
        issuer = x509.get_issuer().CN or ""
        subject = x509.get_subject().CN or ""

        return {
            "valid": True,
            "expires": expires.strftime('%Y-%m-%d'),
            "days_left": days_left,
            "expiring_soon": days_left < 30,
            "tls_version": tls_version,
            "cipher": cipher[0] if cipher else "",
            "issuer": issuer,
            "subject": subject,
            "forward_secrecy": "ECDHE" in (cipher[0] if cipher else "") or "DHE" in (cipher[0] if cipher else ""),
        }
    except ssl.SSLError as e:
        return {"valid": False, "error": str(e)}
    except Exception as e:
        return {"valid": False, "error": str(e)}

def check_dns(hostname):
    result = {"spf": False, "dmarc": False, "spf_value": "", "dmarc_value": ""}
    try:
        answers = dns.resolver.resolve(hostname, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith('v=spf1'):
                result["spf"] = True
                result["spf_value"] = txt
    except:
        pass
    try:
        answers = dns.resolver.resolve(f'_dmarc.{hostname}', 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if 'v=DMARC1' in txt:
                result["dmarc"] = True
                result["dmarc_value"] = txt
    except:
        pass
    return result

def check_tls_versions(hostname):
    versions = {}
    tls_map = {
        "TLS 1.3": ssl.TLSVersion.TLSv1_3,
        "TLS 1.2": ssl.TLSVersion.TLSv1_2,
    }
    for name, version in tls_map.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = version
            ctx.maximum_version = version
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, 443))
                versions[name] = True
        except:
            versions[name] = False
    return versions

@app.route('/scan', methods=['GET'])
def scan():
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({"error": "URL em falta"}), 400
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path
    except:
        return jsonify({"error": "URL inválido"}), 400

    headers = check_headers(url)
    ssl_info = check_ssl(hostname)
    dns_info = check_dns(hostname)
    tls_versions = check_tls_versions(hostname)

    return jsonify({
        "hostname": hostname,
        "is_https": url.startswith('https://'),
        "headers": headers,
        "ssl": ssl_info,
        "dns": dns_info,
        "tls_versions": tls_versions,
    })

if __name__ == '__main__':
    app.run(port=5000, debug=True)