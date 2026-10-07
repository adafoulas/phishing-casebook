# Case 000 — Baseline: authenticated promotional email with image attachment (Gmail)

**Analyst:** Alex Dafoulas

**Date of analysis:** 2026-10-02

## 0. Acquisition and handling
**Source:** Personal Gmail mailbox

**Original filename:** [REDACTED] YMCA_ Join Now & Save $75—No Join Fee (Limited Time!).eml

**Working filename:** case-000.eml

**Method:** Forwarded from Gmail using "Forward as attachment" to the
isolated analysis mailbox. The header block was also copied from Gmail's
"Show original" view and pasted into the message body as a fidelity
cross-check.

**Received format:** .eml (`file`: SMTP mail, ASCII text, with very long lines (749))

**Header source of record:** Header block extracted directly from the
received .eml; pasted copy retained for diff comparison

**Sample SHA256:** 0aa6b35bcfd778b340128b38cc52461a3834cde1850c0e596b95423324abc106

**Attachment:** April Family Newsletter.png; index 9 in the parser's walk
order; image/png attachment, SHA256
e854b7b641a2f4b32ae075a87605cb1bff07877c1ce7ae68b123a35977c2edc8.
The only attachment in the email.

**Environment:** Ubuntu 26.04 VM; shared folders and clipboard disabled;
static analysis only, no execution

**Known limitations:** The pasted header copy is not byte-exact. It lost the leading whitespace on folded continuation lines, was re-wrapped at
different points, and lacks the blank line that ends the extracted
header block. With all whitespace and line breaks removed, the two copies
are identical: no header was added, removed or changed in value. The step
that introduced the re-wrapping was not determined; candidates include
Gmail's "Show original" view, the Gmail compose window, Proton's display,
and the paste into a text editor in the VM. The extracted .eml remains
the source of record.

## 1. Executive summary
A [REDACTED] YMCA membership promotion, sent from ymcaswfl.org through
Microsoft 365, was analysed as a benign baseline. It passed SPF, DKIM and
DMARC, with every authenticated identity aligned to the sender's domain.
The two links in its HTML part point only to that domain, and its image
attachment is structurally clean with no antivirus detections. No
malicious indicators were found.

## 2. Verdict
**Classification:** Benign — legitimate promotional email

**Campaign type:** Not applicable

**Confidence:** High

**Basis:** Fully aligned authentication from the organisation's own
Microsoft 365 tenant; links only to the sender's own domain, with no
anchor-text mismatch; a structurally clean image attachment; no
detections from VirusTotal or urlscan.io.

## 3. Email metadata
| Field | Value |
|---|---|
| Subject | [REDACTED] YMCA: Join Now & Save $75—No Join Fee (Limited Time!) |
| From (display) | [REDACTED-STAFF-NAME] |
| From (address) | `[REDACTED]@ymcaswfl.org` |
| Return-Path | `[REDACTED]@ymcaswfl.org` (same mailbox as From) |
| Reply-To | Not present |
| Originating IP | 2a01:111:f403:c105::1 |
| Originating ASN / Org | AS8075 — Microsoft Corporation (sent via Microsoft-hosted mail infrastructure) |
| Date | Wed, 8 Apr 2026 15:20:26 +0000 |
| Message-ID | …@DM6PR03MB4858.namprd03.prod.outlook.com |
| X-Mailer | Not present (User-Agent and X-MIMEOLE also absent) |

## 4. Authentication results
| Check | Result | Interpretation |
|---|---|---|
| SPF | pass | Passed for ymcaswfl.org (smtp.mailfrom), the same domain as From, so aligned. The sending IP is in 2a01:111:f403:c000::/51, a range published by include:spf.protection.outlook.com in the domain's record, which ends in -all (record as published on 2026-10-02). |
| DKIM | pass | d=ymcaswfl.org, s=selector1, taken from DKIM-Signature. Gmail's header.b=c0BzReFe matches the start of the signature. Aligned with From. |
| DMARC | pass (p=QUARANTINE sp=QUARANTINE dis=NONE) | Both SPF and DKIM aligned, so either alone would have carried it. No action was applied because the message passed. |
| ARC | pass (i=2, cv=pass) | Gmail sealed instance 2. Instance 1 (d=microsoft.com) came from the sender's own tenant, not a forwarder. |
| compauth | Not present | Stamped only by Microsoft's inbound filtering; the recipient was Gmail. |

## 5. Analysis
**Acquisition.** The forwarded .eml parsed cleanly as multipart/mixed, with the attachment intact. The header block was extracted from the .eml
and compared against the copy pasted from "Show original". The plain
diff showed formatting differences only: continuation lines had lost
their leading spaces and tabs, and many headers were re-wrapped at
different points. `diff -w` removed the leading-whitespace differences.
Because it still compares line by line, the re-wrapped headers remained,
along with the extracted block's final blank line. One hunk appeared to
show a missing Received header; this was an alignment artifact, and both
Microsoft Received headers are present in the pasted copy. With all
whitespace removed, the two copies are identical. The encoded Subject was
not decoded.

**Headers.** From and Return-Path are the same ymcaswfl.org mailbox.
Reply-To is absent, so replies go to the sender. No X-Mailer, User-Agent
or X-MIMEOLE header is present. The Message-ID was generated by
Microsoft 365. From and To are the same staff member, and the analyst's
address appears in neither To nor Cc, consistent with blind-copy or
list delivery.

**Authentication.** All values were read from Gmail's own
Authentication-Results header (authserv-id mx.google.com); the results
are in section 4. A lowercase sender-side header reporting
`dkim=none (message not signed)` is also present. It sits below Gmail's
receiving hop and most likely predates outbound DKIM signing, so it was
excluded from the verdict.

**DNS records (checked 2026-10-02).** The SPF record lists six ip4
entries, includes spf.protection.outlook.com and ends in -all. The
sending address falls in that include's 2a01:111:f403:c000::/51 range.
The DKIM selector is a CNAME into the organisation's onmicrosoft.com
tenant, so signing is managed by Microsoft 365, with a 2048-bit key. The
DMARC record is `v=DMARC1; p=quarantine` with no adkim or aspf tags, so
relaxed alignment applies, and the subdomain policy inherits quarantine.
It has no rua tag, so the domain owner receives no DMARC aggregate
reports, which limits its visibility of spoofing attempts against the
domain. That is an observation about the domain's posture, not about
this message. The DKIM h= tag signs each header once; there is no oversigning.

**Trust boundary.** The raw file holds four Received headers. The first
trustworthy hop is mx.google.com receiving from
CH1PR05CU001.outbound.protection.outlook.com [2a01:111:f403:c105::1].
Above it is one Google-internal hop. Below it are two sender-reported
Microsoft hops: MAPI submission and an internal relay. The ARC
instance 1 set and Microsoft's outbound spam verdict (SCL 1, BCL 0,
SFV:NSPM) are also below the boundary. They are recorded as context, not
evidence.

**Tools.** MXToolbox rendered all four hops, matching the raw count.
However, it flagged the hop-1 address fe80::78b2:9add:90d2:e0c8 as
blacklisted. That is an IPv6 link-local address, valid only on a local
network segment and not routable on the internet, so the result is
meaningless. Google Admin Toolbox parsed Gmail's format correctly,
showing the IP and domain. But it also showed a second "none" line under DKIM and
DMARC, almost certainly from the sender-side header, without labelling
it as untrusted.

**Body and links.** The HTML part contains two links, both on ymcaswfl[.]org, the sender's
own domain: hxxps://www.ymcaswfl[.]org/april-campaign and
hxxp://www.ymcaswfl[.]org/. In both, the visible text is the URL itself
and matches the destination: no mismatch, third-party redirector or
shortener. The plain-HTTP link is redirected by the site to
hxxps://www.ymcaswfl[.]org/ as shown in the urlscan.io redirect chain.
No form or image-map tags
were found in the HTML part. The domain was registered on 2021-05-25,
over five years before analysis, which rules out a newly registered
domain but does not by itself establish legitimacy. VirusTotal URL
lookups: 0/92 for each URL. urlscan.io returned "No classification"
for both URLs, meaning nothing malicious was triggered during the scan;
this is not a positive confirmation of safety. These scans reflect the site on 2026-10-02, not on 2026-04-08 when the email was sent.

**Attachment.** The attachment was
extracted at index 9 of the parser's walk order to a neutral filename.
`file`, TrID and Magika all identify it as a PNG, 1545 × 1999,
2,642,684 bytes. A read-only structure check found a valid signature and
the chunk sequence IHDR, eXIf, pHYs, iTXt (Adobe XMP metadata), a run of
IDAT image chunks, then IEND. The chunk lengths account for every byte
of the file, and nothing follows IEND. No VirusTotal vendor flagged the
file. It had no earlier submissions; its first submission was 2026-10-02
19:06:32 UTC by the analyst. Zero detections on a
first-seen image is weak evidence on its own; the structure check
carries more weight. The oletools and PDF tools do not apply to images.

**Conclusion.** The message came from the organisation's own Microsoft
365 tenant, with SPF and DKIM both aligned to the From domain. Its links
stay on that domain, and its attachment is an ordinary image.
Authentication alone would not rule out a compromised mailbox, but
nothing in the content, links or attachment suggests one. The
organisation sends from its own domain through its own tenant, and both
mechanisms align.

## 6. Indicators of compromise
None identified. The values below are reference observables, not IOCs.

| Type | Value (defanged) | Context |
|---|---|---|
| Domain | ymcaswfl[.]org | Sender and link domain; benign |
| IP | 2a01:111:f403:c105::1 | Shared Microsoft 365 outbound infrastructure; do not block |
| SHA256 | e854b7b641a2f4b32ae075a87605cb1bff07877c1ce7ae68b123a35977c2edc8 | Attachment "April Family Newsletter.png"; benign |

## 7. MITRE ATT&CK mapping
Not applicable: no adversary activity identified.

## 8. Recommended actions
**Contain:** No action. Blocking ymcaswfl.org would stop legitimate mail.
Blocking the sending IP would affect many unrelated Microsoft 365
tenants.

**Scope:** Not required. If a user had reported this message, the ticket
would be closed as benign, with feedback thanking them for reporting.

**Eradicate:** Not applicable. No credentials were requested or
submitted.

**Intelligence:** No IOCs to push. Do not allowlist the sender domain:
an allowlist entry would let a future compromise of that mailbox bypass
filtering.

## 9. Detection opportunity
For a benign baseline, the useful question is which plausible phishing
rules this message would trip. Each one below would generate false
positives on legitimate mail like it.

Urgency or discount language in the subject ("Limited Time!", "Save
$75") would fire. Such language is common in legitimate marketing, so
this rule would produce false positives.

External mail where the recipient is in neither To nor Cc, especially
with From equal to To, would fire. It is a real pattern in campaigns
from compromised accounts, but small organisations also mail lists this
way.

An image attachment from an external sender would fire. Legitimate
flyers and newsletters are often sent this way.

Rules that would correctly stay quiet: authentication failure or
misalignment, newly registered sender or link domains, anchor text that
differs from the href, and links to a domain other than the sender's. A
practical rule combines the weak signals with the strong ones. For
example: alert on blind-copy delivery plus urgency language only when
the link domain differs from the From domain or the domain is newly
registered. This message would not trigger that combination.

## 10. Appendix
Redacted header excerpt (Gmail's receiving hop and verdicts):

    Received: from CH1PR05CU001.outbound.protection.outlook.com (mail-northcentralusazlp170100001.outbound.protection.outlook.com. [2a01:111:f403:c105::1])
            by mx.google.com with ESMTPS id [REDACTED-SMTP-ID]
            (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
            Wed, 08 Apr 2026 08:21:13 -0700 (PDT)
    Received-SPF: pass (google.com: domain of [REDACTED]@ymcaswfl.org designates 2a01:111:f403:c105::1 as permitted sender) client-ip=2a01:111:f403:c105::1;
    Authentication-Results: mx.google.com;
           dkim=pass header.i=@ymcaswfl.org header.s=selector1 header.b=c0BzReFe;
           arc=pass (i=1 spf=pass spfdomain=ymcaswfl.org dkim=pass dkdomain=ymcaswfl.org dmarc=pass fromdomain=ymcaswfl.org);
           spf=pass (google.com: domain of [REDACTED]@ymcaswfl.org designates 2a01:111:f403:c105::1 as permitted sender) smtp.mailfrom=[REDACTED]@ymcaswfl.org;
           dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=ymcaswfl.org

Sender-side header, excluded from the verdict:

    authentication-results: dkim=none (message not signed)
     header.d=none;dmarc=none action=none header.from=ymcaswfl.org;

PNG structure check (pngchunks.py), abbreviated:

    PNG signature OK: True
    8 IHDR 13
    33 eXIf 180
    225 pHYs 9
    246 iTXt 1535
        [text-chunk preview line omitted: start of the Adobe XMP packet]
    1793 IDAT 8192
    [319 IDAT lines omitted, each 8192 bytes, offsets 9997 to 2618869]
    2627073 IDAT 8192
    2635277 IDAT 7383
    2642672 IEND 0
    File size: 2642684
    IEND found: True  bytes after IEND: 0
