# Phishing Analysis CasebookStatic analyses of phishing emails, written up the way a SOC analyst
would document them: how the sample was acquired, what the headers,
authentication results, links and attachments show, a verdict with its
basis, an ATT&CK mapping, the response a SOC would take, and a
detection opportunity. Each case is a folder under `cases/`, and its
`README.md` is the full report.

## Methodology

Samples are analyzed in an isolated Ubuntu 26.04 VM with shared folders
and the shared clipboard disabled. Each sample is forwarded as an
attachment to a dedicated analysis mailbox and downloaded inside the VM.
The header block extracted from the received .eml is the source of
record. Authentication results are read from the receiving provider's
own Authentication-Results header, and everything below the receiving
provider's first hop is treated as sender-reported. Upstream results
stamped by the receiving provider's own infrastructure are used only as
supporting evidence. Tool output is checked against the raw headers
rather than trusted on its own.

URLs are scanned with urlscan.io and checked on VirusTotal. A URL
carrying a per-recipient token is scanned privately and looked up on
VirusTotal rather than submitted. Attachments are extracted to neutral
filenames, hashed and looked up by hash before any upload. They are
never opened or executed in the VM, only examined with read-only tools;
image content is read from the message as rendered in webmail. Any
deviation from the methodology is recorded in section 0 of the case
report.

Before any malicious sample, the pipeline was validated on a benign
baseline: authenticated mail from an organization's own Microsoft 365
tenant. See section 10 of [methodology.md](methodology.md).

The full process, including verification checks, tool behavior
observed in testing and redaction rules, is in
[methodology.md](methodology.md).

## Cases

| Case | Campaign type | Verdict | Summary |
|---|---|---|---|
| [000](cases/case-000/) | Not applicable (benign baseline) | Benign (High) | Promotional email from an organization's own Microsoft 365 tenant, with SPF and DKIM both aligned; used to validate the pipeline |
| [001](cases/case-001/) | Callback phishing / untargeted bulk distribution | Malicious (High) | Fake PayPal purchase order carried as an image, sent from a personal Gmail account to 249 visible recipients, with its text disguised in lookalike characters |
| [002](cases/case-002/) | Callback phishing | Malicious (High) | Fake PayPal order confirmation in a mislabeled image (declared HEIF, actually BMP), sent from a Gmail account through the Gmail API with two callback numbers |
| [003](cases/case-003/) | Brand-impersonation health scam (spoofed sender, link lure) | Malicious (Medium) | Spoofed microsoft.com sender that passed SPF and DMARC by relaying through Microsoft 365, with an ABC News-branded weight-loss lure linking to a tracked redirect chain |

## Repository layout

- `cases/`: one folder per case; each folder's `README.md` is the full report.
- `scripts/`: helper scripts used in the analyses (see section 7 of [methodology.md](methodology.md)).
- [methodology.md](methodology.md): acquisition, analysis order, verification checks, tool behavior and redaction rules.

## Sources and safety

All samples come from the analyst's own personal Gmail and Outlook.com
mailboxes.

No malware binaries, email files or attachments are included in this
repository. In each case's indicator table, URLs, domains, email addresses and IPv4
addresses are defanged; hashes and phone numbers are given as they are,
and Message-IDs are left un-defanged so they match log searches.Personal data, including recipient addresses, staff names and tracking tokens, is redacted as
described in section 8 of [methodology.md](methodology.md).