#!/usr/bin/env python3
"""
headeraudit - grade a website's HTTP security headers.

Fetches a URL and checks the response for the headers that harden a site
against clickjacking, MIME sniffing, downgrade attacks and data leaks,
then reviews cookie flags and server banners and gives an overall grade.

Standard library only. Python 3.8+.
"""

import argparse
import json
import ssl
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

__version__ = "1.0.0"

USER_AGENT = f"headeraudit/{__version__} (+https://github.com/Landull/headeraudit)"

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"
WEIGHTS = {PASS: 0, INFO: 0, WARN: 1, FAIL: 3}


def ssl_context(verify=True):
    """Default TLS context. python.org builds for macOS ship without CA certificates,
    so when none are loaded there, borrow the system roots from the macOS keychain."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if sys.platform == "darwin" and not ctx.cert_store_stats().get("x509_ca"):
        try:
            pem = subprocess.run(
                ["security", "find-certificate", "-a", "-p",
                 "/System/Library/Keychains/SystemRootCertificates.keychain"],
                capture_output=True, text=True, timeout=30).stdout
            if pem:
                ctx.load_verify_locations(cadata=pem)
        except (OSError, subprocess.SubprocessError, ssl.SSLError, ValueError):
            pass
    return ctx


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(url, timeout, follow, insecure):
    """Return (final_url, status, list of (header, value), redirect_chain)."""
    ctx = ssl_context(verify=not insecure)
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow:
        handlers.append(NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as err:
        # 4xx/5xx and unfollowed 3xx still carry headers worth auditing
        resp = err
    final = resp.geturl() if hasattr(resp, "geturl") else url
    return final, resp.status if hasattr(resp, "status") else resp.code, list(resp.headers.items())


def header_map(pairs):
    """Lower-cased header name -> list of values."""
    out = {}
    for name, value in pairs:
        out.setdefault(name.lower(), []).append(value.strip())
    return out


def first(h, name):
    vals = h.get(name)
    return vals[0] if vals else None


def check_hsts(h, is_https):
    v = first(h, "strict-transport-security")
    if not is_https:
        return FAIL, "Site served over plain HTTP; HSTS can't apply", v
    if not v:
        return FAIL, "Missing; browsers may be downgraded to HTTP", v
    max_age = 0
    for part in v.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1].strip('"'))
            except ValueError:
                pass
    if max_age < 15552000:  # 180 days
        return WARN, f"max-age is {max_age}s; 15552000 (180 days) or more is recommended", v
    extra = " with includeSubDomains" if "includesubdomains" in v.lower() else ""
    return PASS, f"max-age {max_age}s{extra}", v


def check_csp(h):
    v = first(h, "content-security-policy")
    ro = first(h, "content-security-policy-report-only")
    if not v:
        if ro:
            return WARN, "Only Report-Only is set; nothing is enforced", ro
        return FAIL, "Missing; no defense in depth against XSS", v
    low = v.lower()
    issues = []
    if "'unsafe-inline'" in low and "nonce-" not in low and "sha256-" not in low:
        issues.append("allows 'unsafe-inline'")
    if "'unsafe-eval'" in low:
        issues.append("allows 'unsafe-eval'")
    if "default-src" not in low and "script-src" not in low:
        issues.append("no default-src or script-src")
    for d in low.split(";"):
        toks = d.split()
        if len(toks) > 1 and toks[0] in ("default-src", "script-src") and "*" in toks[1:]:
            issues.append(f"{toks[0]} allows *")
    if issues:
        return WARN, "Present but weak: " + ", ".join(issues), v
    return PASS, "Present", v


def check_xcto(h):
    v = first(h, "x-content-type-options")
    if not v:
        return FAIL, "Missing; browsers may MIME-sniff responses", v
    if v.lower() != "nosniff":
        return WARN, "Should be exactly 'nosniff'", v
    return PASS, "nosniff", v


def check_framing(h):
    v = first(h, "x-frame-options")
    csp = (first(h, "content-security-policy") or "").lower()
    if "frame-ancestors" in csp:
        return PASS, "Protected by CSP frame-ancestors", v
    if not v:
        return FAIL, "Missing X-Frame-Options and frame-ancestors; clickjacking possible", v
    if v.upper() in ("DENY", "SAMEORIGIN"):
        return PASS, v.upper(), v
    return WARN, "Unrecognized value; use DENY or SAMEORIGIN", v


def check_referrer(h):
    v = first(h, "referrer-policy")
    good = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
    if not v:
        return WARN, "Missing; browser default applies", v
    last = v.split(",")[-1].strip().lower()
    if last in good:
        return PASS, last, v
    if last == "unsafe-url" or last == "no-referrer-when-downgrade":
        return WARN, f"'{last}' can leak full URLs to other sites", v
    return PASS, last, v


def check_permissions(h):
    v = first(h, "permissions-policy")
    if not v:
        return WARN, "Missing; camera, mic, geolocation etc. not restricted", v
    return PASS, "Present", v


def check_coop(h):
    v = first(h, "cross-origin-opener-policy")
    if not v:
        return INFO, "Not set (optional; isolates the window from cross-origin popups)", v
    return PASS, v, v


def check_disclosure(h):
    found = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        v = first(h, name)
        if v and any(c.isdigit() for c in v):
            found.append(f"{name}: {v}")
    if found:
        return WARN, "Version info disclosed: " + "; ".join(found), None
    return PASS, "No version numbers in server banners", None


def check_cookies(h, is_https):
    results = []
    for raw in h.get("set-cookie", []):
        name = raw.split("=", 1)[0].strip()
        attrs = [a.strip().lower() for a in raw.split(";")[1:]]
        missing = []
        if is_https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        samesite = [a for a in attrs if a.startswith("samesite")]
        if not samesite:
            missing.append("SameSite")
        elif samesite[0].endswith("none") and "secure" not in attrs:
            missing.append("Secure (required with SameSite=None)")
        if missing:
            status = FAIL if "Secure" in missing or "HttpOnly" in missing else WARN
            results.append((f"Cookie {name}", status, "Missing " + ", ".join(missing), raw))
        else:
            present = [f for f in ("Secure", "HttpOnly") if f.lower() in attrs] + ["SameSite"]
            results.append((f"Cookie {name}", PASS, ", ".join(present), raw))
    return results


def grade(results):
    penalty = sum(WEIGHTS[r["status"]] for r in results)
    for limit, letter in ((0, "A+"), (2, "A"), (4, "B"), (7, "C"), (10, "D")):
        if penalty <= limit:
            return letter
    return "F"


def audit(url, timeout=10, follow=True, insecure=False):
    if "://" not in url:
        url = "https://" + url
    final, status, pairs = fetch(url, timeout, follow, insecure)
    h = header_map(pairs)
    is_https = final.lower().startswith("https://")

    checks = [
        ("Strict-Transport-Security", check_hsts(h, is_https)),
        ("Content-Security-Policy", check_csp(h)),
        ("X-Content-Type-Options", check_xcto(h)),
        ("Clickjacking protection", check_framing(h)),
        ("Referrer-Policy", check_referrer(h)),
        ("Permissions-Policy", check_permissions(h)),
        ("Cross-Origin-Opener-Policy", check_coop(h)),
        ("Server disclosure", check_disclosure(h)),
    ]
    results = [{"check": name, "status": s, "detail": d, "value": v} for name, (s, d, v) in checks]
    for name, s, d, v in check_cookies(h, is_https):
        results.append({"check": name, "status": s, "detail": d, "value": v})

    return {
        "url": url,
        "final_url": final,
        "status_code": status,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "grade": grade(results),
        "results": results,
    }


def color(status, enabled):
    if not enabled:
        return status
    codes = {PASS: "32", WARN: "33", FAIL: "31", INFO: "36"}
    return f"\033[{codes[status]}m{status}\033[0m"


def print_report(report, use_color, verbose):
    print(f"{report['final_url']}  (HTTP {report['status_code']})")
    print(f"Grade: {report['grade']}\n")
    width = max(len(r["check"]) for r in report["results"])
    for r in report["results"]:
        print(f"  [{color(r['status'], use_color)}] {r['check']:<{width}}  {r['detail']}")
        if verbose and r["value"]:
            print(f"         {'':<{width}}  {r['value']}")
    counts = {s: sum(1 for r in report["results"] if r["status"] == s) for s in (PASS, WARN, FAIL)}
    print(f"\n[*] {counts[PASS]} pass, {counts[WARN]} warn, {counts[FAIL]} fail")


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="headeraudit",
        description="Grade a website's HTTP security headers and cookie flags.",
    )
    p.add_argument("urls", nargs="*", help="URL(s) or domain(s) to audit")
    p.add_argument("-i", "--input", metavar="FILE", help="read URLs from a file, one per line")
    p.add_argument("-f", "--format", choices=("table", "json"), default="table", help="output format")
    p.add_argument("-o", "--output", metavar="FILE", help="write JSON results to a file")
    p.add_argument("-v", "--verbose", action="store_true", help="show raw header values")
    p.add_argument("-t", "--timeout", type=float, default=10, help="request timeout in seconds (default 10)")
    p.add_argument("--no-follow", action="store_true", help="audit the first response, don't follow redirects")
    p.add_argument("-k", "--insecure", action="store_true", help="don't verify the TLS certificate")
    p.add_argument("--no-color", action="store_true", help="plain output without colors")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    urls = list(args.urls)
    if args.input:
        try:
            with open(args.input, encoding="utf-8") as fh:
                urls += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as err:
            print(f"[!] {err}", file=sys.stderr)
            return 2
    if not urls:
        print("[!] Give at least one URL or use --input.", file=sys.stderr)
        return 2

    reports, errors = [], 0
    use_color = sys.stdout.isatty() and not args.no_color
    for i, url in enumerate(urls):
        try:
            report = audit(url, args.timeout, not args.no_follow, args.insecure)
        except (urllib.error.URLError, OSError, ValueError) as err:
            reason = getattr(err, "reason", err)
            print(f"[!] {url}: {reason}", file=sys.stderr)
            errors += 1
            continue
        reports.append(report)
        if args.format == "table":
            if i:
                print()
            print_report(report, use_color, args.verbose)

    if args.format == "json" or args.output:
        data = json.dumps(reports if len(reports) != 1 else reports[0], indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(data + "\n")
            print(f"[*] Wrote {args.output}", file=sys.stderr)
        else:
            print(data)

    if errors and not reports:
        return 2
    return 1 if any(r["status"] == FAIL for rep in reports for r in rep["results"]) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:  # e.g. piped into `head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
