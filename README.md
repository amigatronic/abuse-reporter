# Abuse Reporter — Google Apps Script

**Tired of spam? Fight back automatically.**

Abuse Reporter is a Google Apps Script that transforms your Gmail spam folder into an automated abuse reporting system. Instead of just deleting spam and phishing emails, it extracts the originating IP address, looks up the abuse contact via RDAP/WHOIS databases, and sends detailed reports to the offending provider—forcing spammers to face consequences at the source.

## Why This Exists

Most email users passively accept spam, trusting filters to catch threats. But spammers rely on this apathy. Every unreported spam email is a free pass for attackers to continue their operations. Abuse Reporter changes this dynamic by:

1. **Automating the reporting process** – No manual WHOIS lookups, no copy-pasting headers
2. **Hitting spammers where it hurts** – Reports go directly to the hosting provider's abuse desk, risking account suspension
3. **Creating network effects** – The more people use this, the faster bad actors get shut down

Automated spam/phishing abuse reporter for Gmail. Scans your Spam folder, extracts the real source IP, looks up the responsible provider via RDAP/RIPE/ARIN, and sends a structured abuse report — then trashes the message.

## Features

- **Smart IP extraction** — walks `Received:` headers bottom-up, handles IPv4/IPv6, skips private/NAT ranges
- **Forward detection** — supports inline forwards, `message/rfc822` attachments, and direct mail
- **Phishing classifier** — scores messages on SPF/DKIM/DMARC failures, brand impersonation, punycode/homoglyph domains, masked links, high-risk TLDs
- **False-positive safe** — whitelists trusted domains, skips self-IP, labels suspicious cases for manual review
- **RDAP + RIPE + ARIN fallback chain** with persistent cache (30-day TTL)
- **Optional ARF (RFC 5965) attachment**
- **Per-provider rate limiting** and optional Google Sheets log

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

## License

MIT — see [LICENSE](LICENSE).
