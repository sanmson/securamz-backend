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

@app.route('/health')
def health():
    return jsonify({"status": "ok"}), 200

@app.route('/scan', methods=['GET'])
def scan():
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({"error": "URL em falta"}), 400
    if not url.startswith('http'):
        url = 'https://' + url
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path
    return jsonify({
        "hostname": hostname,
        "is_https": url.startswith('https://'),
        "headers": {},
        "ssl": {},
        "dns": {},
        "tls_versions": {},
    })

if __name__ == '__main__':
    app.run(port=5000, debug=True)
