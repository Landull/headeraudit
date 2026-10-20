# headeraudit

A small, dependency-free command-line tool that grades a website's HTTP security headers, cookie flags and server banners.

- Checks **HSTS, CSP, X-Content-Type-Options, clickjacking protection, Referrer-Policy, Permissions-Policy** and COOP
- Reviews every **cookie** for Secure, HttpOnly and SameSite
- Flags **version numbers** leaking from `Server` and `X-Powered-By`
- Gives each site a letter **grade (A+ to F)**, audits one site or a whole list
- Export results as **JSON** for reports

Python 3.8+, standard library only. Windows, macOS and Linux.

## Usage

```bash
# Grade a site (https:// is assumed)
python headeraudit.py example.com

# Show the raw header values too
python headeraudit.py https://example.com/login -v

# A list of sites, saved as JSON
python headeraudit.py -i sites.txt -o headers.json

# Audit the redirect itself instead of the final page
python headeraudit.py http://example.com --no-follow
```

### Example output

```
$ python headeraudit.py shop.example.com
https://shop.example.com/  (HTTP 200)
Grade: D

  [PASS] Strict-Transport-Security   max-age 31536000s with includeSubDomains
  [WARN] Content-Security-Policy     Present but weak: allows 'unsafe-inline'
  [PASS] X-Content-Type-Options      nosniff
  [PASS] Clickjacking protection     DENY
  [PASS] Referrer-Policy             strict-origin-when-cross-origin
  [WARN] Permissions-Policy          Missing; camera, mic, geolocation etc. not restricted
  [INFO] Cross-Origin-Opener-Policy  Not set (optional; isolates the window from cross-origin popups)
  [WARN] Server disclosure           Version info disclosed: server: Apache/2.4.41 (Ubuntu)
  [PASS] Cookie session              Secure, HttpOnly, SameSite
  [FAIL] Cookie tracker              Missing HttpOnly, SameSite

[*] 5 pass, 3 warn, 1 fail
```

## Options

| Flag | Description |
|---|---|
| `-i, --input FILE` | Read URLs from a file, one per line |
| `-f, --format` | Output format (`table` / `json`) |
| `-o, --output FILE` | Write JSON results to a file |
| `-v, --verbose` | Show raw header values |
| `-t, --timeout N` | Request timeout in seconds (default 10) |
| `--no-follow` | Audit the first response, don't follow redirects |
| `-k, --insecure` | Don't verify the TLS certificate |
| `--no-color` | Plain output without colors |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No failing checks |
| `1` | At least one check failed |
| `2` | Bad input, or no site could be reached |

## Notes

Headers are defense in depth, not a substitute for fixing the app itself. A missing CSP doesn't mean a site has an XSS bug, and a perfect grade doesn't mean it's secure.

The grade is a simple weighted count (fail = 3 points, warn = 1). It's meant for comparing sites and tracking progress, not as an official score.

## License

MIT, see [LICENSE](LICENSE).

---

Part of [Landull](https://github.com/Landull)'s auditkit.
