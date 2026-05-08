# File: ml-service/utils/vuln_scanner.py
import requests
import ssl
import socket
import re
from datetime import datetime
from urllib.parse import urlparse


def check_headers(target_url):
    """Check HTTP security headers."""
    findings = []
    try:
        resp = requests.get(target_url, timeout=10, allow_redirects=True,
                           headers={'User-Agent': 'SOC-Scanner/1.0'})
        headers = {k.lower(): v for k, v in resp.headers.items()}

        security_headers = {
            'x-frame-options': {
                'name': 'X-Frame-Options Missing',
                'severity': 'medium',
                'description': 'Site may be vulnerable to Clickjacking attacks.',
                'fix': 'Add header: X-Frame-Options: DENY or SAMEORIGIN',
            },
            'content-security-policy': {
                'name': 'Content-Security-Policy Missing',
                'severity': 'medium',
                'description': 'No CSP header — XSS attacks are easier to execute.',
                'fix': 'Implement a Content-Security-Policy header.',
            },
            'strict-transport-security': {
                'name': 'HSTS Not Enabled',
                'severity': 'medium',
                'description': 'Site does not enforce HTTPS via HSTS.',
                'fix': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            },
            'x-content-type-options': {
                'name': 'X-Content-Type-Options Missing',
                'severity': 'low',
                'description': 'Browser may MIME-sniff responses.',
                'fix': 'Add header: X-Content-Type-Options: nosniff',
            },
            'x-xss-protection': {
                'name': 'X-XSS-Protection Missing',
                'severity': 'low',
                'description': 'Browser XSS filter not explicitly enabled.',
                'fix': 'Add header: X-XSS-Protection: 1; mode=block',
            },
            'referrer-policy': {
                'name': 'Referrer-Policy Missing',
                'severity': 'low',
                'description': 'Referrer information may leak to external sites.',
                'fix': 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
            },
        }

        for header_key, info in security_headers.items():
            if header_key not in headers:
                findings.append({
                    'type': 'Missing Security Header',
                    'name': info['name'],
                    'severity': info['severity'],
                    'description': info['description'],
                    'fix': info['fix'],
                })

        # Check for server version disclosure
        server = headers.get('server', '')
        if server and any(c.isdigit() for c in server):
            findings.append({
                'type': 'Information Disclosure',
                'name': 'Server Version Exposed',
                'severity': 'low',
                'description': f'Server header reveals version info: {server}',
                'fix': 'Remove or obscure the Server header.',
            })

        x_powered = headers.get('x-powered-by', '')
        if x_powered:
            findings.append({
                'type': 'Information Disclosure',
                'name': 'X-Powered-By Header Exposed',
                'severity': 'low',
                'description': f'Technology stack exposed: {x_powered}',
                'fix': 'Remove the X-Powered-By header.',
            })

    except requests.exceptions.SSLError:
        findings.append({
            'type': 'SSL Error',
            'name': 'SSL Certificate Error',
            'severity': 'critical',
            'description': 'SSL certificate is invalid or expired.',
            'fix': 'Renew or fix the SSL certificate.',
        })
    except Exception as e:
        findings.append({
            'type': 'Scanner Error',
            'name': 'Header Check Failed',
            'severity': 'low',
            'description': str(e),
            'fix': 'Verify target URL is accessible.',
        })

    return findings


def check_ssl(target_url):
    """Check SSL/TLS configuration."""
    findings = []
    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        if parsed.scheme != 'https':
            findings.append({
                'type': 'No HTTPS',
                'name': 'Site Not Using HTTPS',
                'severity': 'high',
                'description': 'Site is served over HTTP — all traffic is unencrypted.',
                'fix': 'Install an SSL certificate and redirect HTTP to HTTPS.',
            })
            return findings

        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=10),
                             server_hostname=hostname) as sock:
            cert = sock.getpeercert()
            version = sock.version()

            # Check certificate expiry
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (not_after - datetime.utcnow()).days

            if days_left < 0:
                findings.append({
                    'type': 'SSL',
                    'name': 'SSL Certificate Expired',
                    'severity': 'critical',
                    'description': f'Certificate expired {abs(days_left)} days ago.',
                    'fix': 'Renew the SSL certificate immediately.',
                })
            elif days_left < 30:
                findings.append({
                    'type': 'SSL',
                    'name': 'SSL Certificate Expiring Soon',
                    'severity': 'high',
                    'description': f'Certificate expires in {days_left} days.',
                    'fix': 'Renew the SSL certificate before it expires.',
                })

            # Check TLS version
            if version in ('TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'):
                findings.append({
                    'type': 'Weak TLS',
                    'name': f'Outdated TLS Version: {version}',
                    'severity': 'high',
                    'description': f'{version} is considered insecure and deprecated.',
                    'fix': 'Upgrade to TLS 1.2 or TLS 1.3 only.',
                })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            'type': 'SSL',
            'name': 'SSL Certificate Invalid',
            'severity': 'critical',
            'description': str(e),
            'fix': 'Fix or replace the SSL certificate.',
        })
    except Exception:
        pass  # Skip if host not reachable

    return findings


def check_common_paths(target_url):
    """Check for exposed sensitive paths."""
    findings = []
    sensitive_paths = [
        ('/robots.txt', 'Robots.txt Accessible', 'low', 'May expose sensitive URL paths to crawlers.'),
        ('/.git/', 'Git Repository Exposed', 'critical', 'Source code may be publicly accessible.'),
        ('/admin', 'Admin Panel Exposed', 'high', 'Admin interface accessible without authentication check.'),
        ('/wp-admin', 'WordPress Admin Exposed', 'medium', 'WordPress admin login page is publicly accessible.'),
        ('/phpmyadmin', 'phpMyAdmin Exposed', 'critical', 'Database admin interface is publicly accessible.'),
        ('/.env', '.env File Exposed', 'critical', 'Environment file may contain API keys and passwords.'),
        ('/config.php', 'Config File Exposed', 'critical', 'Configuration file may be publicly accessible.'),
        ('/backup', 'Backup Directory Accessible', 'high', 'Backup files may be publicly accessible.'),
        ('/api/v1', 'API Endpoint Detected', 'low', 'Verify API endpoints require authentication.'),
    ]

    base_url = target_url.rstrip('/')
    for path, name, severity, desc in sensitive_paths:
        try:
            url = base_url + path
            resp = requests.get(url, timeout=5, allow_redirects=False,
                               headers={'User-Agent': 'SOC-Scanner/1.0'})
            if resp.status_code in (200, 403):
                status_note = 'accessible' if resp.status_code == 200 else 'found (forbidden)'
                findings.append({
                    'type': 'Sensitive Path',
                    'name': name,
                    'severity': severity,
                    'description': f'{path} is {status_note}. {desc}',
                    'fix': f'Restrict access to {path} or remove it.',
                    'url': url,
                })
        except Exception:
            continue

    return findings


def scan_target(target_url):
    """Run full vulnerability scan on a target URL."""
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    all_findings = []
    all_findings.extend(check_headers(target_url))
    all_findings.extend(check_ssl(target_url))
    all_findings.extend(check_common_paths(target_url))

    # Deduplicate and count severity
    summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for f in all_findings:
        sev = f.get('severity', 'low')
        summary[sev] = summary.get(sev, 0) + 1

    # Add IDs
    for i, f in enumerate(all_findings):
        f['id'] = i + 1

    risk_score = (summary['critical'] * 40 + summary['high'] * 20 +
                  summary['medium'] * 10 + summary['low'] * 5)
    risk_score = min(100, risk_score)

    return {
        'target': target_url,
        'scanned_at': datetime.utcnow().isoformat(),
        'total_findings': len(all_findings),
        'summary': summary,
        'risk_score': risk_score,
        'findings': all_findings,
    }