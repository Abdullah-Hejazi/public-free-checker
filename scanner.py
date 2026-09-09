"""Small, dependency-free migration evidence prototype. CLI only; not a public API."""
import argparse
import csv
import datetime as dt
import hashlib
import html
from html.parser import HTMLParser
import http.client
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import time
from urllib.parse import urlsplit, urlunsplit, urljoin

REDIRECTS = {301, 302, 303, 307, 308}
MAX_BYTES = 512_000


def normalized(url):
    p = urlsplit(url.strip())
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
        raise ValueError('Only HTTP(S) URLs without credentials are supported')
    if any(ord(c) < 32 for c in url) or '\\' in url or '%' in p.netloc:
        raise ValueError('Invalid URL characters')
    if p.port not in (None, 80 if p.scheme == 'http' else 443):
        raise ValueError('Only standard HTTP(S) ports are supported')
    host = p.hostname.encode('idna').decode().lower().rstrip('.')
    netloc = '[' + host + ']' if ':' in host else host
    return urlunsplit((p.scheme, netloc, p.path or '/', p.query, ''))


def public_addresses(host, port):
    addresses = list(dict.fromkeys(x[4][0] for x in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):
        raise ValueError('Destination resolves to a non-public address')
    return addresses


class Metadata(HTMLParser):
    def __init__(self):
        super().__init__()
        self.canonicals = []
        self.robots = []
        self.refresh = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'link' and 'canonical' in (a.get('rel') or '').lower().split():
            self.canonicals.append(a.get('href') or '')
        if tag == 'meta':
            if (a.get('name') or '').lower() in ('robots', 'googlebot'):
                self.robots.append(a.get('content') or '')
            if (a.get('http-equiv') or '').lower() == 'refresh':
                self.refresh = True


class PublicTransport:
    """Pin the validated IP at connect time; revalidate every redirect hop."""
    def __init__(self, hosts, delay=1.0):
        self.hosts = set(hosts)
        self.last = {}
        self.delay = delay

    def __call__(self, url):
        url = normalized(url)
        p = urlsplit(url)
        if p.hostname not in self.hosts:
            raise ValueError('Redirect leaves explicitly authorized hostnames')
        port = 443 if p.scheme == 'https' else 80
        addresses = public_addresses(p.hostname, port)
        time.sleep(max(0, self.delay - (time.monotonic() - self.last.get(p.hostname, 0))))
        self.last[p.hostname] = time.monotonic()
        conn = http.client.HTTPConnection(p.hostname, port, timeout=10)
        sock = socket.create_connection((addresses[0], port), timeout=10)
        try:
            if p.scheme == 'https':
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=p.hostname)
            conn.sock = sock
            conn.request('GET', urlunsplit(('', '', p.path, p.query, '')), headers={
                'User-Agent': 'CutoverCheck/0.1 (owner-authorized migration QA)',
                'Accept': 'text/html,*/*;q=0.1', 'Accept-Encoding': 'identity', 'Connection': 'close'})
            response = conn.getresponse()
            headers = {}
            for k, v in response.getheaders():
                k = k.lower()
                headers[k] = headers.get(k, '') + (', ' if k in headers else '') + v
            body = response.read(MAX_BYTES + 1) if response.status not in REDIRECTS else b''
            return response.status, headers, body[:MAX_BYTES], len(body) > MAX_BYTES
        finally:
            conn.close()
            sock.close()


def check_pair(old, expected, fetch, expected_status=301):
    old, expected = normalized(old), normalized(expected)
    result = dict(old_url=old, expected_url=expected, expected_status=expected_status,
                  chain=[], findings=[], final_url=None, verdict='unknown')
    current = old
    seen = set()
    started = time.monotonic()
    try:
        for hop in range(7):
            if time.monotonic() - started > 75:
                raise ValueError('Per-pair time limit reached')
            if current in seen:
                result['findings'].append('redirect_loop')
                break
            seen.add(current)
            status, headers, body, truncated = fetch(current)
            result['chain'].append({'url': current, 'status': status})
            if status in REDIRECTS:
                if not headers.get('location'):
                    result['findings'].append('redirect_without_location')
                    break
                current = normalized(urljoin(current, headers['location']))
                if hop == 6:
                    result['findings'].append('redirect_limit')
                continue
            result['final_url'] = current
            if status in (401, 403, 429):
                result['findings'].append('access_blocked_or_rate_limited')
            elif status != 200:
                result['findings'].append('destination_http_' + str(status))
            if current != expected:
                result['findings'].append('wrong_destination')
            allowed_initial = {301, 308} if expected_status is None else {expected_status}
            if result['chain'][0]['status'] not in allowed_initial:
                result['findings'].append('unexpected_initial_status')
            if len(result['chain']) > 2:
                result['findings'].append('multiple_redirect_hops')
            if status == 200:
                content_type = headers.get('content-type', '').lower()
                if 'html' not in content_type:
                    result['findings'].append('html_metadata_not_checked')
                else:
                    meta = Metadata()
                    meta.feed(body.decode('utf-8', 'replace'))
                    directives = ','.join(meta.robots + [headers.get('x-robots-tag', '')]).lower()
                    if 'noindex' in directives or 'none' in directives.replace(',', ' ').split():
                        result['findings'].append('noindex_observed')
                    if len(meta.canonicals) > 1:
                        result['findings'].append('multiple_canonicals')
                    elif meta.canonicals:
                        if normalized(urljoin(current, meta.canonicals[0])) != expected:
                            result['findings'].append('canonical_mismatch')
                    else:
                        result['findings'].append('canonical_absent')
                    if meta.refresh:
                        result['findings'].append('meta_refresh_requires_review')
                if truncated:
                    result['findings'].append('response_truncated')
            break
    except (ValueError, OSError, http.client.HTTPException) as exc:
        result['findings'].append('not_verified: ' + str(exc)[:180])
    failures = {'wrong_destination', 'redirect_loop', 'redirect_without_location', 'noindex_observed', 'canonical_mismatch'}
    uncertain = any(x.startswith('not_verified') or x in {'access_blocked_or_rate_limited','redirect_limit','response_truncated'} for x in result['findings'])
    failed = any(x in failures or x.startswith('destination_http_') for x in result['findings'])
    result['verdict'] = 'unknown' if uncertain else 'fail' if failed else 'review' if result['findings'] else 'pass'
    return result


def report_html(report):
    esc = lambda v: html.escape(str(v), quote=True)
    rows = ''.join('<tr><td>'+esc(r['old_url'])+'</td><td>'+esc(r['expected_url'])+'</td><td>'+esc(r['verdict'])+'</td><td>'+esc(', '.join(r['findings']) or 'Observed checks passed')+'</td></tr>' for r in report['results'])
    label = 'SYNTHETIC EXAMPLE — not a customer audit' if report.get('synthetic') else 'Migration evidence prototype'
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>CutoverCheck evidence report</title><style>body{font:16px/1.6 system-ui;max-width:1100px;margin:50px auto;padding:0 24px;color:#17202a}table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #ddd;text-align:left;padding:12px;overflow-wrap:anywhere}h1{font-size:32px}small{color:#555}@media print{body{margin:0}}</style><h1>CutoverCheck evidence report</h1><p>'+esc(label)+'</p><p>Observed at '+esc(report['created_at'])+'</p><table><thead><tr><th>Old URL</th><th>Expected destination</th><th>Result</th><th>Findings</th></tr></thead><tbody>'+rows+'</tbody></table><p>Scope: HTTP redirects and selected server-delivered HTML metadata for the supplied URL pairs. No JavaScript rendering, robots.txt interpretation, search-engine indexing verification, traffic guarantees, security testing, or private staging access. A pass applies only to the listed checks at the recorded time.</p><small>Input SHA-256: '+esc(report['input_sha256'])+'</small></html>'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mapping', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--authorized', action='store_true', help='Confirm permission to check every supplied host')
    args = parser.parse_args()
    if not args.authorized:
        parser.error('Use --authorized only for domains you own or are authorized to test')
    raw = args.mapping.read_bytes()
    if len(raw) > 200_000:
        parser.error('CSV must be under 200 KB')
    records = list(csv.DictReader(raw.decode('utf-8-sig').splitlines()))
    if not 1 <= len(records) <= 500:
        parser.error('Supply 1–500 URL pairs')
    hosts = {urlsplit(normalized(r[k])).hostname for r in records for k in ('old_url', 'new_url')}
    fetch = PublicTransport(hosts)
    results = [check_pair(r['old_url'], r['new_url'], fetch, int(r.get('expected_status') or 301)) for r in records]
    report = dict(created_at=dt.datetime.now(dt.timezone.utc).isoformat(), input_sha256=hashlib.sha256(raw).hexdigest(), results=results)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'report.json').write_text(json.dumps(report, indent=2))
    (args.output / 'report.html').write_text(report_html(report))
    print(json.dumps({'rows': len(results), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
