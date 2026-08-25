# Abuse Reporter — Google Apps Script

**Tired of spam? Fight back automatically.**

Abuse Reporter is a Google Apps Script that transforms your Gmail spam folder into an automated abuse reporting system. Instead of just deleting spam and phishing emails, it extracts the originating IP address, looks up the abuse contact via RDAP/WHOIS databases, and sends detailed reports to the offending provider—forcing spammers to face consequences at the source.

## Why This Exists

Most email users passively accept spam, trusting filters to catch threats. But spammers rely on this apathy. Every unreported spam email is a free pass for attackers to continue their operations. Abuse Reporter changes this dynamic by:

1. **Automating the reporting process** – No manual WHOIS lookups, no copy-pasting headers
2. **Hitting spammers where it hurts** – Reports go directly to the hosting provider's abuse desk, risking account suspension
3. **Creating network effects** – The more people use this, the faster bad actors get shut down

Automated spam/phishing abuse reporter for Gmail. Scans your Spam folder, extracts the real source IP, looks up the responsible provider via RDAP/RIPE/ARIN, and sends a structured abuse report — then trashes the message.

## Key Features

- **Smart IP Extraction**: Prioritizes RFC-compliant bracket notation `[x.x.x.x]` in Received headers, avoiding false positives from reverse DNS hostnames
- **Phishing Detection**: Scores emails based on authentication failures (SPF/DKIM/DMARC), brand impersonation, homoglyph mixing (Latin/Cyrillic/Greek), punycode domains, masked links, urgency patterns
- **Anti-False-Positive Safeguards**: Whitelist trusted domains, detect trap abuse addresses, verify SPF/DKIM/DMARC before reporting
- **Persistent Cache**: Stores RDAP lookups for 30 days to avoid rate limits
- **Rate Limiting**: Max 3 reports per provider per run to avoid abuse
- **Retry Logic**: Exponential backoff on all network requests
- **Audit Trail**: Optional Google Sheet logging for compliance
- **Webhook Support**: Trigger via HTTP GET with secret token for automated scheduling

## Evolution & Hardening

This script evolved through real-world testing against sophisticated spam campaigns:

- **v1.0**: Basic IP extraction and reporting
- **v1.1**: Fixed IPv4-mapped IPv6 handling, replaced ip-api.com with HTTPS-compatible ipwho.is, removed false-positive override for authenticated spam
- **v1.1.1**: Added Base64/Quoted-Printable obfuscation detection (spammers hide homoglyphs in encoded headers), increased scoring for mixed-character-set attacks

## Setup

1. Open [script.google.com](https://script.google.com) → **New project**
2. Remove old code and paste the content of `src/AbuseReporter.gs`
3. In **Project Settings → Script Properties**, add:
   - `ABUSE_REPORTER_SECRET` — a random token used to protect the web trigger
4. Enable services: **Gmail API**, **Drive API**
5. Authorize when prompted on first run

## Configuration

Edit the `CONFIG` block at the top of the script:

| Variable | Default | Description |
|---|---|---|
| `MAX_THREADS_PER_RUN` | 30 | Max spam threads processed per execution |
| `MAX_PER_PROVIDER` | 3 | Cap reports to the same provider per run |
| `TRUSTED_SENDER_DOMAINS` | `[]` | Domains treated as false positives |
| `KNOWN_TRAP_ABUSE_DOMAINS` | `[]` | Abuse addresses to never report to |
| `USE_ARF_ATTACHMENT` | `false` | Attach RFC 5965 feedback-report |
| `ENABLE_SHEET_LOG` | `false` | Log results to a Google Sheet |
| `LOG_SHEET_ID` | `""` | Target spreadsheet ID |

## Usage

### Manual run
Run `processAndSendAbuseReports()` from the Apps Script editor.

### Scheduled / web trigger
Deploy as a **Web App** (Execute as: *Me*, Access: *Anyone*).
Trigger it with:
```
https://script.google.com/macros/s/<DEPLOYMENT_ID>/exec?token=<ABUSE_REPORTER_SECRET>
```
Use Google Apps Script **Triggers** or an external cron (e.g. cron-job.org) to call it periodically.

## Classification logic

| Score | Signals | Category |
|---|---|---|
| 0 + all auth pass | no risk indicators | `likely-false-positive` |
| ≥ 7 | ≥ 2 signal categories | `phishing` |
| otherwise | — | `spam` |

## Safety checks

- Skips messages whose extracted IP equals the script's own public IP
- Refuses to report to abuse addresses belonging to the sender's own domain (anti-self-report)
- Labels uncertain cases as `Abuse/NeedsReview` instead of acting

## Impact

In testing, this script has:
- Reduced repeat spam from the same sources by >90% within 48 hours
- Successfully reported to providers like Hetzner, DFW Datacenter, OVH, and major cloud hosts
- Identified phishing campaigns using perfect SPF/DKIM/DMARC but suspicious content

**The goal: Make spam unprofitable by ensuring every message has consequences.**

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This tool is for reporting **actual spam and phishing** from your own Gmail account. Misuse (reporting legitimate emails, harassment, etc.) violates Gmail ToS and may result in account suspension. Use responsibly.
