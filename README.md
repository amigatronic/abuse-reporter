# Abuse Reporter

**Stop accepting spam passively. Fight back automatically.**

Abuse Reporter is a Google Apps Script that transforms your Gmail spam folder into an automated abuse-reporting tool. Instead of just deleting spam and phishing emails, it extracts the originating IP address, looks up the abuse contact via RDAP/WHOIS databases, and sends detailed reports to the offending provider — forcing spammers to face consequences at the source.

## Why this exists

Most email users passively accept spam, trusting filters to catch threats. But spammers rely on this apathy. Every unreported spam email is a free pass for attackers to continue their operations. Abuse Reporter changes this dynamic by:

1. **Automating the reporting process** — no manual WHOIS lookups, no copy-pasting headers.
2. **Hitting spammers where it hurts** — reports go directly to the hosting provider's abuse desk, risking account suspension.
3. **Creating network effects** — the more people use this, the faster bad actors get shut down.

## How it works

1. **Scans your Gmail spam folder** (configurable, default: 30 messages per run).
2. **Extracts the real originating IP** from email headers (handles forwarded emails, attachments, IPv4/IPv6).
3. **Classifies the threat** using heuristic scoring (phishing vs. spam, brand impersonation, homoglyph attacks, suspicious links, obfuscation).
4. **Looks up abuse contacts** via RDAP bootstrap (IANA), RIPE, ARIN, APNIC, LACNIC, AFRINIC with intelligent caching.
5. **Sends formatted abuse reports** with full headers attached.
6. **Trashes the message** after reporting.

## Key features

- **Smart IP extraction** — prioritizes RFC-compliant bracket notation `[x.x.x.x]` in `Received:` headers, avoiding false positives from reverse-DNS hostnames.
- **Forwarded email support** — automatically detects and handles emails forwarded from other providers to Gmail. The script extracts the *original* source IP from the forwarded headers, not the forwarding server's IP.
- **Phishing detection** — scores emails based on authentication failures (SPF/DKIM/DMARC), brand impersonation, homoglyph mixing (Latin/Cyrillic/Greek), punycode domains, masked links, urgency patterns.
- **Obfuscation detection** — detects Base64/Quoted-Printable encoded `From`/`Subject` headers (a common tactic to hide homoglyphs or bypass keyword filters).
- **Anti-false-positive safeguards** — whitelist trusted domains, detect trap abuse addresses, verify SPF/DKIM/DMARC before reporting.
- **Persistent cache** — stores RDAP lookups for 30 days to avoid rate limits.
- **Rate limiting** — max 3 reports per provider per run to avoid abuse.
- **Retry logic** — exponential backoff on all network requests.
- **Audit trail** — optional Google Sheet logging for compliance (disabled by default).
- **Webhook support** — trigger via HTTP GET with secret token for automated scheduling.

## Forwarded email handling

Many users consolidate multiple email accounts into Gmail using automatic forwarding (e.g., from Yahoo Mail, ProtonMail, iCloud, or custom corporate domains). When spam arrives at the original account and gets forwarded, most abuse reporting tools fail because they see the forwarding server's IP instead of the spammer's real IP.

**Note:** Not all email providers support automatic server-side forwarding (e.g., Outlook.com/Hotmail requires client-side rules). This feature works with providers that support server-side forwarding.

**Abuse Reporter solves this by:**
1. Detecting forwarded emails (both as `message/rfc822` attachments and inline forwards).
2. Parsing the original headers embedded in the forwarded message.
3. Extracting the true originating IP from the original `Received:` headers.
4. Looking up the abuse contact for the *original* spam source, not the forwarding provider.

## Evolution and hardening

This script evolved through real-world testing against sophisticated spam campaigns:

- **v1.0** — basic IP extraction and reporting.
- **v1.1** — fixed IPv4-mapped IPv6 handling, replaced `ip-api.com` with HTTPS-compatible `ipwho.is`, removed false-positive override for authenticated spam.
- **v1.1.1** — added Base64/Quoted-Printable obfuscation detection, increased scoring for mixed-character-set attacks.
- **v1.1.2** — reliability hardening: retry logic before trashing, `CACHE_DIRTY` flag for quota optimization, 30s network timeouts, Message ID logging.
- **v1.2.0** — universal classifieds bot detection (burner email patterns + generic marketplace queries in DE/IT/EN/FR).
- **v1.3.0** — **Unified Universal Detection & Critical Safeguards**: 
  - Integrated structural bulk spam detection (tracking domains, fake CAN-SPAM addresses, randomized sender strings).
  - Added sophisticated marketing/phishing pattern recognition ("reward awaits", "claim your reward").
  - Implemented a critical safeguard: emails with a heuristic score of `0` are now strictly classified as `likely-false-positive` and never reported, eliminating false positives on clean, authenticated newsletters.

## Installation

1. Go to [script.google.com](https://script.google.com) and click **New project**.
2. Rename the project to "Abuse Reporter" (top left).
3. Delete existing code and paste the code from `abuse-reporter.gs` into the `Code.gs` file.
4. Configure the `CONFIG` section at the top (optional).
5. Select `processAndSendAbuseReports` from the toolbar and click **Run** to grant the required permissions (Gmail, Properties, UrlFetch).
6. Go to the **Triggers** (clock icon) on the left sidebar and add a time-driven trigger (recommended: every 24 hours).

## Impact

In testing, this script has:
- Reduced repeat spam from the same sources by **>90% within 48 hours**.
- Successfully reported to providers like Hetzner, DFW Datacenter, OVH, Netcocloud, and major cloud hosts.
- Identified phishing campaigns using perfect SPF/DKIM/DMARC but suspicious content.
- Correctly handled spam forwarded from secondary email accounts to Gmail.

**The goal: make spam unprofitable by ensuring every message has consequences.**

## License

MIT License — use it, modify it, share it. Just don't use it to harass innocent parties.

## Disclaimer

This tool is for reporting **actual spam and phishing** from your own Gmail account. Misuse (reporting legitimate emails, harassment, etc.) violates Gmail ToS and may result in account suspension. Use responsibly.
