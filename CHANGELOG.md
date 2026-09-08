# Changelog

All notable changes to this project will be documented in this file.

## [1.4.0] - 2026-09-07

### Added
- **Advanced Bayesian Poisoning Detection**: Now detects and penalizes massive blocks of randomized alphanumeric strings (gibberish) used to bypass spam filters.
- **Cloud Hosting Abuse Detection**: Added specific rules to flag legitimate cloud storage domains (e.g., `storage.googleapis.com`, `drive.google.com`, `sites.google.com`, `github.io`) when used to host random `.html` phishing pages.
- **Expanded Brand Impersonation List**: Added detection for "State Farm", "State-Farm", "Enterprise", "YNAB", "Tim", "Vodafone", "Enel", "Eni", "Ebay", "Subito", "Sda", "Brt", and "Gls".
- **Urgency + Gift Pattern Recognition**: New heuristic that triggers a high penalty when urgency triggers (e.g., "final notice", "expires in") are combined with free gift/bonus claims.
- **Outgoing Email Sanitization**: The report body now automatically obscures active malicious URLs (`[LINK REMOVED FOR SAFETY]`) to prevent Gmail's outbound filters from blocking the abuse report itself, while keeping the full headers attached as proof.

### Fixed
- Resolved `ReferenceError: isSafeAbuseTarget is not defined` by ensuring the function is properly declared and scoped.
- Fixed cross-provider escalation contamination by replacing global `ESCALATION_PROVIDERS` arrays with a strict `ESCALATION_RULES` mapping object. This ensures OVH escalation emails are never accidentally sent to Alibaba, and vice versa.
- Updated `validateConfiguration` to explicitly check for the presence of `ESCALATION_RULES`.
- Improved logging clarity for escalation triggers, now specifying which keyword matched the provider.

## [1.3.1] - 2026-08-30

### Fixed
- **Critical IP Extraction Fix**: Strict bracketed IP matching in `Received:` headers to prevent reverse-DNS hostname false positives (e.g., ignoring `247.166.9.5` in favor of `[5.9.166.247]`).
- **Reserved IP Exclusion**: Added blocking for multicast/reserved IP ranges (octet >= 224) to prevent futile RDAP lookups.
- **Operational Safety**: Added `DRY_RUN` mode for risk-free testing, `validateConfiguration()` to prevent silent setup errors, and modularized `buildEmailBody()` for cleaner payload generation.
- Fixed UTF-8 encoding artifacts in regex patterns.

## [1.3.0] - 2026-08-25

### Added
- Unified universal detection & critical safeguards.
- Structural bulk spam detection.
- Sophisticated phishing hooks.
- Strict zero-score false-positive prevention (critical safeguard: never report an email with a score of 0).

## [1.2.0] - 2026-08-20

### Added
- Universal classifieds bot detection (burner email patterns + generic marketplace queries in DE/IT/EN/FR).
- Detection of short message bodies typical of automated templates.

## [1.1.2] - 2026-08-15

### Fixed
- Reliability hardening: retry logic before trashing.
- Added `CACHE_DIRTY` flag for quota optimization.
- 30s network timeouts.
- Message ID logging for better traceability.

## [1.1.1] - 2026-08-10

### Added
- Base64/Quoted-Printable obfuscation detection in `From`/`Subject` headers.
- Increased scoring for mixed-character-set attacks (homoglyphs).

## [1.1.0] - 2026-08-05

### Fixed
- Fixed IPv4-mapped IPv6 handling.
- Replaced `ip-api.com` with HTTPS-compatible `ipwho.is`.
- Removed false-positive override for authenticated spam.

## [1.0.0] - 2026-08-01

### Added
- Initial release.
- Basic IP extraction from email headers.
- Automated abuse reporting to provider contacts.
- RDAP/WHOIS lookup integration.
