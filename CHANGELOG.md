# Changelog

All notable changes to this project will be documented in this file.

## [1.4.0] - 2026-09-07

### Added
- **Advanced Bayesian Poisoning Detection**: Now detects and penalizes massive blocks of randomized alphanumeric strings (gibberish) used to bypass spam filters.
- **Cloud Hosting Abuse Detection**: Added specific rules to flag legitimate cloud storage domains (e.g., `storage.googleapis.com`, `drive.google.com`) when used to host random `.html` phishing pages.
- **Expanded Brand Impersonation List**: Added detection for "State Farm", "Enterprise", "YNAB", "Tim", "Vodafone", "Enel", "Eni", "Ebay", "Subito", "Sda", "Brt", and "Gls".
- **Urgency + Gift Pattern Recognition**: New heuristic that triggers a high penalty when urgency triggers (e.g., "final notice", "expires in") are combined with free gift claims.
- **Outgoing Email Sanitization**: The report body now automatically obscures active malicious URLs (`[LINK REMOVED FOR SAFETY]`) to prevent Gmail's outbound filters from blocking the abuse report itself, while keeping the full headers attached as proof.

### Fixed
- Resolved `ReferenceError: isSafeAbuseTarget is not defined` by ensuring the function is properly declared and scoped.
- Fixed cross-provider escalation contamination by replacing global `ESCALATION_PROVIDERS` arrays with a strict `ESCALATION_RULES` mapping object. This ensures OVH escalation emails are never accidentally sent to Alibaba, and vice versa.

### Changed
- Updated `validateConfiguration` to explicitly check for the presence of `ESCALATION_RULES`.
- Improved logging clarity for escalation triggers, now specifying which keyword matched the provider.

## [1.3.1] - 2026-08-30
### Fixed
- Removed flawed SPF `client-ip` priority that caused false positives on forwarded emails.
- Improved `Received:` header parsing to strictly trust bracketed IPs `[x.x.x.x]` and skip malformed headers containing `javascript:` or missing standard MTA formatting (` by `).
