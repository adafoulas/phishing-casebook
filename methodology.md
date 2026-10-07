# Methodology

How samples in this casebook are acquired, analyzed, verified and
redacted, and what testing showed about the tools used. A benign
baseline (section 10) was worked first, to validate the pipeline before
any malicious sample. Section 11 lists the case that prompted each rule.
Each case report records its own results, and any deviations from this
methodology, in its section 0.

## 1. Environment and isolation

Analysis runs in an Ubuntu 26.04 VirtualBox VM. Shared folders and the
shared clipboard are disabled, so no file or clipboard content crosses
the host boundary. Samples reach the VM only by email: they are
forwarded as attachments to a dedicated analysis mailbox and downloaded
inside the VM.

No personal email credentials are used in the VM. The only credential
stored there is a fine-grained GitHub token scoped to this repository.

Samples, extracted files and unredacted notes live in `~/samples/`,
outside the repository, and are never committed. `.gitignore` blocks
common sample formats as a backstop.

Analysis is static only: no attachment is opened or executed in the VM.
A VM snapshot is taken before attachments are extracted. Extracted
files are examined only with read-only tools (`file`, `sha256sum`,
TrID, Magika, pngchunks.py), never opened in a viewer. When an image's
content needs to be read, the message is viewed as rendered by the
webmail client on the host.

Automatic loading of external images is turned off in the webmail
client, where it allows it, before a sample is viewed. Remote images and
tracking pixels can tell the sender the message was opened, and the
link checks in section 7 do not enumerate them. Viewing a sample with
remote images loaded is recorded as a deviation in the case report.

The VM does not hide the analyst's IP. Under NAT it shares the host's
public address, so any lookup or scan run from the VM is attributable
to the analyst's network.

## 2. Acquisition

**Gmail path.** The header block is copied from Show original. The
message is forwarded with Forward as attachment, with the header block
pasted into the body as a cross-check. Gmail attaches the forwarded
message server-side, so the sample never touches the Windows disk.

**Outlook path.** The message source is copied via View message source
in new Outlook. The message is then forwarded as an attachment to the
analysis mailbox, with the header block pasted into the body as a
cross-check.

**Analysis mailbox (Proton Mail).** Proton's attachment download can
produce a combined zip of the .eml and its inner attachment. Download
the .eml on its own instead. If the zip was downloaded, revert the VM to
the clean snapshot without opening anything from it.

On both paths, the header block extracted from the received .eml is the
source of record:

    sed -n '1,/^\r\?$/p' sample.eml > original-headers.txt

The range includes the blank line that ends the header block. The
pasted copy is used only to check fidelity (section 4).

## 3. Analysis order

1. Hash and identify the sample (`sha256sum`, `file`), list its MIME
   parts (section 7) and confirm its attachments survived the forward.
2. Extract the header block (section 2) and run the verification checks
   (section 4).
3. Build the header tables from the raw headers, then compare tool
   output against them.
4. Read authentication results from the receiving provider's own
   Authentication-Results header. Exclude sender-side authentication
   headers from the verdict. Results that the receiving provider's own
   infrastructure stamped at an earlier hop, such as Microsoft's
   X-MS-Exchange-Authentication-Results on mail relayed through
   Microsoft 365, may be used as supporting evidence, labelled as not
   independently verifiable.
5. Locate the trust boundary: the Received header in which the
   receiving provider records the connection from the sending server.
   Everything below it is sender-reported. Identify the connecting IP's
   owner from the regional registry's whois, and its ASN from Team Cymru
   or bgp.he.net, since ARIN's OriginAS field can be blank.
6. Check the sending domain's current DNS records (SPF, the DKIM
   selector's key, DMARC) with `dig`, and record the lookup date.
7. Body and links: list links in the HTML part, check the plain-text
   part and form/image-map tags, recover original destinations from any
   Safe Links wrappers (section 5), identify each registered domain and
   run whois. Scan URLs with urlscan.io, using Private visibility (or at
   least Unlisted) for any URL carrying a per-recipient token. Look up a
   token-bearing URL on VirusTotal rather than submitting it: a
   submission adds the full URL, including the token, to VirusTotal's
   corpus.
8. Attachments: extract to a neutral filename
   (`extracted/attachment-<index>.bin`), run `file` and `sha256sum`, and
   compare the detected type with the declared Content-Type and filename
   extension. Look up the hash on VirusTotal before any upload, then run
   the type-appropriate tool.
9. Verdict, response, ATT&CK mapping and detection opportunity.

ATT&CK mappings record the ATT&CK version and the date the IDs were
checked. Only what the sample shows is mapped. When the purpose of a
call or link is unknown, the report states which rows are kept and why.

## 4. Verification checks and their limits

| Check | Command | What it shows | Limit |
|---|---|---|---|
| Folding intact | `grep -c "^[[:blank:]]" original-headers.txt` | Number of folded continuation lines; zero means the file is damaged | A count only; does not prove content is intact |
| Paste fidelity | `diff <(tr -d '\r' < original-headers.txt) <(tr -d '\r' < pasted-headers.txt)` | Every line that differs | Reports formatting changes as differences |
| Paste fidelity, whitespace-insensitive | as above with `diff -w` | Differences other than whitespace within a line | Still reports moved line breaks, so it cannot come back clean for a re-wrapped copy. It can also misalign similar lines, making a header appear to be missing when it is not |
| Content identical apart from whitespace | `cmp <(tr -d ' \t\r\n' < original-headers.txt) <(tr -d ' \t\r\n' < pasted-headers.txt) && echo identical` | Whether the copies differ only in whitespace and line breaks | Cannot detect a change consisting only of an added or removed space inside a header value. On the Outlook path it can fail because of changes made by View message source (section 5); the line diff then shows what changed |
| Hop count | `grep -in "^received:" original-headers.txt` | Raw Received count, compared with each tool's hop table | — |
| PNG structure | `python3 ~/phishing-casebook/scripts/pngchunks.py <file>` | See section 7 | See section 7 |

Each case report records the results of these checks for its own
sample.

## 5. Provider transformation notes

**Gmail (Show original).** `file` labels mail by its first header line.
Gmail's raw message begins with Delivered-To, so its label (SMTP mail)
can differ from that of Outlook-path samples (RFC 822 mail). Either
label means an email text file. The pasted header copy can lose the
leading whitespace on continuation lines, be re-wrapped at different
points, and lack the blank line that ends the header block. The step
that introduces the re-wrapping has not been determined. In the samples
so far, Gmail did not rewrite links: hrefs in the .eml point directly at
their destinations.

**Outlook (View message source).** The pasted copy can differ from the
extracted block in whitespace (headers unfolded onto one line,
continuation lines indented with a tab instead of a space, the trailing
blank line dropped, trailing spaces removed) and occasionally in content
(a To: value with no address wrapped in quotes, header-name
capitalisation normalised). The extracted block remains the source of
record, and each report records the differences found.

**Safe Links.** Outlook.com can rewrite links in delivered mail as
safelinks.protection.outlook.com wrappers. The original destination is
the URL-decoded `url=` parameter, or the `originalsrc` attribute where
present:

    python3 -c "import sys,urllib.parse as u; print(u.parse_qs(u.urlparse(sys.argv[1]).query)['url'][0])" 'SAFELINKS_URL'

The wrapper's `data=` parameter contains the recipient's address, and
the recovered URL may carry a per-recipient token. Both are redacted
(section 8).

**Microsoft headers.** Mail relayed through Microsoft 365 before
delivery can carry upstream results in X-MS-Exchange-Authentication-Results,
and the original connecting IP in
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp, with no
Received headers for those hops. Microsoft documents its compauth
reason codes for Microsoft 365 organizations. They are applied to
consumer Outlook.com mail on the assumption that the same codes are
used.

**Sender-side headers.** A sender's own mail system can stamp its own
authentication results, such as a lowercase `authentication-results`
header reading `dkim=none (message not signed)` that may predate
outbound DKIM signing. Such headers sit below the receiving provider's
hop and are excluded from the verdict.

## 6. Tool behavior observed

| Tool | Observed | Lesson |
|---|---|---|
| Google Admin Toolbox | Parses Gmail-format headers, including the IP and signing domain, but can show an unlabeled second result line taken from a sender-side header. On Microsoft-format headers it has reported the IP and domain as "Unknown", produced incomplete hop tables, and measured delivery time only to the last hop it parsed | Parsing a format is not the same as knowing the trust boundary. Check its hop table against the raw Received count |
| MXToolbox | Its hop tables have matched the raw Received count so far. A headers-only submission always fails DKIM body-hash verification, because the expected body hash is that of an empty body. Its DKIM expiry check has reported an expired signature as not expired. Its blacklist results have flagged loopback, link-local and reserved addresses, and shared provider relays listed for other messages. PDF exports can truncate content the saved page shows in full, and the saved page footer shows the analyst's public IP | A headers-only DKIM failure is not evidence; the receiver's result at delivery is. Check every result for plausibility. Keep saved tool pages in `~/samples/`. Use "Permanently forget this email header" afterwards, since analyzed headers are stored behind a shareable URL |
| Both header tools | Neither evaluates X-MS-Exchange-Authentication-Results or the other Microsoft diagnostic headers | Read Microsoft's diagnostic headers by hand |
| VirusTotal | An upload creates a public submission record, including the filename, and uploaded files can be downloaded by paid subscribers. A submitted URL, including any token, joins its corpus. A hash search with no file match shows only a Comments tab with 0 entries. Its URL redirection panel has disagreed with its own network requests | Search by hash before uploading. Look up token-bearing URLs instead of submitting them: the API's GET /api/v3/urls/{id}, where {id} is the URL base64url-encoded without padding, returns an existing report without scanning. Cross-check redirect chains against urlscan.io |
| urlscan.io | "No classification" means nothing malicious was triggered during the scan. A destination that returns an empty response produces no screenshot and no classification. Default visibility is Public; Private results open only for the submitting account | Neither result shows a page is safe. Use Private (or at least Unlisted) for URLs with per-recipient tokens, and do not publish Private result links |

Zero detections on a file or URL is weak evidence on its own. Scans and
DNS lookups show the current state of a site or domain, not its state
when the email was delivered. Record both dates.

## 7. Custom scripts and commands

Replace `sample.eml` with the sample's filename.

**MIME parts listing.** Prints each part's walk index, content type,
disposition and filename:

    python3 -c "import email,email.policy; m=email.message_from_binary_file(open('sample.eml','rb'),policy=email.policy.default); [print(i, p.get_content_type(), p.get_content_disposition(), repr(p.get_filename()) if p.get_filename() else None) for i,p in enumerate(m.walk())]"

**[`list-links.py`](scripts/list-links.py).** Prints the visible text
and destination of each `<a href>` link in the HTML part. It does not
cover URLs in the text/plain part, form submission addresses, image-map
links, or links inside attachments; those are checked with the two
commands below. Nor does it cover `<img src>` or other non-anchor URLs,
so remote images and tracking pixels are not enumerated (section 9).
When one link wraps the whole message, the printed anchor text is the
entire message text.

URLs in the plain-text part. This prints nothing both when there are no
URLs and when the message has no text/plain part; the parts listing
shows which:

    python3 -c "import email,email.policy,re; m=email.message_from_binary_file(open('sample.eml','rb'),policy=email.policy.default); [print(u) for p in m.walk() if p.get_content_type()=='text/plain' for u in re.findall(r'(?:https?://|www\.)[^\s<>\"]+', p.get_content())]"

Form and image-map tags in the HTML part (prints `[]` for each HTML part
with none):

    python3 -c "import email,email.policy,re; m=email.message_from_binary_file(open('sample.eml','rb'),policy=email.policy.default); [print(re.findall(r'<(?:form|area)\b[^>]*>', p.get_content(), re.I)) for p in m.walk() if p.get_content_type()=='text/html']"

**[`pngchunks.py`](scripts/pngchunks.py).** The setup toolset covers
Office documents (oletools); PDF tools are still to be installed
(section 9), and nothing else covers images. This read-only script,
using only the Python standard library, confirms the 8-byte PNG
signature and walks the chunks by their declared lengths, printing each
chunk's offset, type and length. It prints the first 200 bytes of any
text chunk (tEXt, iTXt, zTXt) and reports whether IEND is present and
how many bytes follow it. Data after IEND is a known way to append
hidden content to a valid image.

Limits: it covers PNG only. It does not verify chunk CRCs, decompress
compressed text, parse EXIF data, or examine pixel data. It cannot
detect steganography, and it says nothing about what the image depicts,
such as visible text or a QR code.

## 8. Redaction

Working notes are drafted with real values in `~/samples/` and redacted
only when content moves into the repository. Redaction uses `sed` with
bracketed placeholders, and a `grep` for every redacted value must
return nothing before `git add`. The grep includes the analyst's own
mailbox domain.

**All paths:**
- the analyst's address and mailbox domain wherever they appear,
  including `for <…>` clauses in Received headers and
  `smtp.rcpttodomain` in ARC-Authentication-Results
- the Safe Links `data=` parameter
- per-recipient tracking tokens, and any URL path or parameter not
  confirmed to be campaign-level
- links to private scan results

**Gmail path:** Delivered-To, and Gmail's SMTP transaction ID in
excerpts.

**Outlook path:** X-MS-UserLastLogonTime, the long antispam blob, and
GUIDs that identify the analyst's own mailbox or copy of the message.

**Benign samples:** the sender's staff name and mailbox (the domain is
kept), and details that reveal the analyst's location, such as a local
branch name.

**Malicious samples:** sender addresses, attacker-controlled domains,
attacker-attributed tenant IDs and Message-IDs are kept as indicators.
Third-party organizations whose infrastructure appears in the chain,
such as an onmicrosoft.com tenant that may have been abused, are named
with a note that they may be victims rather than attackers.

Sender domains, authentication results, originating IPs and provider
hostnames are kept: without them the analysis cannot be followed.

**Defanging.**
- URLs: `hxxp`/`hxxps`, with `[.]` in the domain, everywhere outside
  raw header excerpts.
- Attacker-associated domains and email addresses: defanged everywhere
  outside raw header excerpts. Domains have at least the final dot
  replaced with `[.]`; email addresses use `[@]` and `[.]`.
- Indicator tables (section 6 of each report): every URL, domain, email
  address and IPv4 address is defanged, including shared-infrastructure
  values listed as "not an IOC". IPv6 addresses are left as they are.
- Prose and metadata tables: IP addresses and benign or provider
  domains may be left plain.
- Message-IDs: not defanged. They are kept in backticks with their
  angle brackets, because a defanged value would not match in a log
  search.
- Raw header excerpts in appendices: verbatim apart from redactions,
  inside code blocks.
- Values in backticks or code blocks are never auto-linked by GitHub;
  use them for any undefanged address or hostname that should not
  become a link.

## 9. Deviations and open items

Deviations from this methodology in a specific case are recorded in
section 0 of that case's report, so each report states its own limits.

Open:
- `pdfid` and `pdf-parser` are not part of the current toolset. They
  will be installed before the first PDF sample.
- Image formats other than PNG get no structure check; they are only
  identified and hashed.
- Text inside images is not machine-read. It is read by viewing the
  rendered message, so values that appear only in an image are not
  covered by text searches.
- `<img src>` and other non-anchor URLs are not enumerated by any
  current tool.

## 10. Baseline

**Sample:** A legitimate promotional email received on the Gmail path,
sent from the organization's own Microsoft 365 tenant, with one image
attachment and links only to the sender's own domain. Full details are
in the case-000 report.

**What it confirmed:** The pipeline worked end to end: acquisition,
header extraction and fidelity checks, link and form checks, attachment
extraction and the PNG structure check. It also showed what fully
aligned authentication looks like: SPF and DKIM both aligned with the
From domain, so either alone would carry DMARC.

**Lesson:** Authentication proves origin, not intent.

## 11. Rule provenance

| Rule or observation | Prompted by |
|---|---|
| Gmail-path transformation notes; exclusion of sender-side authentication headers | case-000 |
| Search VirusTotal by hash before uploading; urlscan.io visibility for token-bearing URLs | case-000 |
| Keep saved tool pages in `~/samples/`; forget analyzed headers in MXToolbox | case-000 |
| Redact details that reveal the analyst's location in benign samples | case-000 |
| Proton zip handling | case-001 |
| Outlook-path transformation notes | cases 001–003 |
| Google Admin Toolbox behaviour on Microsoft-format headers | cases 001 and 003 |
| MXToolbox headers-only DKIM failure | cases 001–003 |
| MXToolbox DKIM expiry check | case-001 |
| Blacklist results on loopback, link-local and shared relay addresses | cases 000–002 |
| ASN from Team Cymru or bgp.he.net when ARIN's OriginAS is blank | cases 001 and 003 |
| Message-IDs not defanged | case-001 |
| Redact `smtp.rcpttodomain` | cases 001 and 002 |
| Compare an attachment's detected type with its declared type | case-002 |
| compauth codes applied to consumer Outlook.com mail | case-002 |
| No structure check for non-PNG images; image text not machine-read | case-002 |
| Upstream Microsoft authentication headers as supporting evidence | case-003 |
| Content check can fail for non-whitespace reasons on the Outlook path | case-003 |
| Safe Links recovery and `data=` redaction | case-003 |
| Private urlscan.io scans; look up, don't submit, token-bearing URLs | case-003 |
| Turn off external images before viewing | case-003 |
| Non-anchor URLs not enumerated; empty output from the plain-text URL check | case-003 |