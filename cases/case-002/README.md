# Case 002 — Callback phishing: fake PayPal order confirmation sent from Gmail

**Analyst:** Alex Dafoulas

**Date of analysis:** 2026-10-05

## 0. Acquisition and handling
**Source:** Personal Outlook mailbox (Outlook.com consumer account). Delivered 2026-09-08 19:17:21 UTC (top Received header).

**Original filename:** email-1.2.eml

**Working filename:** case-002.eml

**Method:** Forwarded as an attachment to an isolated analysis mailbox. The
header block was also copied from Outlook "View message source" and pasted
into the message body as a fidelity cross-check.

**Received format:** .eml (`file`: RFC 822 mail, ASCII text, with very long lines (347))

**Header source of record:** Header block extracted directly from the
received .eml (`sed` through the first blank line, saved as
original-headers.txt). Pasted copy compared with all whitespace removed:
identical. A line diff (CRs stripped) differed only in whitespace: seven
headers unfolded onto one line in the pasted copy, two continuation lines
indented with a tab instead of a space, and the trailing header/body
separator line that the `sed` range includes.

**Sample SHA256:** 1b7b2d769409d6bebaf3b64d8854148ca3d15cb9dd413ee8bd50b365f3d690e0 (5,514,910 bytes)


**Attachments:** No file attachments (no MIME part has Content-Disposition:attachment). One inline part (index 4 in the email.walk() listing),
declared as image/heif with filename
CYRIL-2767755866786965381367-20260908.heic. Extracted as
extracted/attachment-4.bin. `file` identifies the content as a Windows
bitmap, not HEIF (PC bitmap, Windows 3.x format, 1024 x 1325 x 24). SHA256
0b2f6ff5a133f99099ec7cb9754e9e75492d766a42d8efa989e381524c75be9c.
MIME parts in walk() order: multipart/related, multipart/alternative,
text/plain, text/html, image/heif. The text/html body (walk index 3) was
also extracted, as extracted/attachment-3.bin (2,105 bytes; `file`: HTML
document, ASCII text; SHA256
990189aa27a07bbdce4362fd5b2f3d843cabe4ff278f48d3c525c48c80ba08b4).


**Environment:** Ubuntu 26.04 VM; shared folders and clipboard disabled;
static analysis only, no execution

**Known limitations:** No URLs were extracted, so there were no Safe
Links-rewritten URLs to recover from originalsrc and no URL scans were run.
DNS records (gmail.com SPF, DKIM key for selector 20251104, DMARC) and the
IP reputation check of 209.85.208.176 were checked on 2026-10-05, not at
delivery on 2026-09-08. Link extraction scope: a URL regex over the
text/plain part, the casebook's list-links.py run against case-002.eml, and
a search of the text/html part for `<form>` and `<area>` tags. All three
returned nothing. These text-based methods do not cover content rendered
inside the inline image. Image content was viewed in Outlook; in the VM the
extracted image was only identified with `file` and hashed. VirusTotal was
queried by hash search only, and nothing was uploaded. The search for the
HTML body hash (attachment-3.bin) on 2026-10-05 showed no file match (the
results page displayed only a Comments tab with 0 entries). The search for the image hash
(attachment-4.bin) on 2026-10-05 showed no file match (the
results page displayed only a Comments tab with 0 entries). Header-only copies were submitted to
MxToolbox Email Header Analyzer and Google Admin Toolbox Messageheader.
MxToolbox's "DKIM Authenticated" failure ("Body Hash Did Not Verify") is an
artifact of submitting headers without the body: its expected body hash
(47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=) is the SHA-256 of an empty
body. The receiving server's dkim=pass at delivery is the result of record.

## 1. Executive summary
On 8 September 2026, a personal Outlook.com mailbox received an email, sent from a personal Gmail account, containing a picture made to look like a PayPal order confirmation for a $319.47 Springfield Armory gun, which told the reader to call a "Dispute Center" within 24 hours to cancel the order. The email is assessed as malicious: it is a "callback phishing" phone scam, built to get the reader to call one of the two phone numbers it lists, where scammers commonly try to obtain payment, personal details or remote access to the caller's computer. The email passed the standard checks that confirm where a message came from, because it was genuinely sent from a Gmail account, but those checks cannot show whether a sender is honest, and carrying the order as a picture keeps its wording, including one of the phone numbers, out of reach of filters that read text. The recommended response is not to call either number, to confirm through PayPal itself (if the recipient has an account) that no such order exists, to report the email to PayPal and Microsoft and the sender to Google, and to block the sender and delete the message.

## 2. Verdict

**Classification:** Malicious

**Campaign type:** Callback phishing

**Confidence:** High

**Basis:** Every authentication check passed for gmail.com (SPF, DKIM, DMARC and Microsoft's compauth, reason 100), which shows the message was sent through Google's servers from a real Gmail account, not that the sender is legitimate; a personal Gmail account sending a PayPal order notice is itself inconsistent with genuine PayPal mail. The display name "Matilde Mosciski" does not match the address `tesdioongrdccxfhbvcdg3456[@]gmail[.]com`, neither relates to PayPal, and the subject, "Current Records and Relevant Account Information Prepared for Your Records", names no organisation. The message has no Reply-To, its only visible recipient is the analysed mailbox, and it was submitted through the Gmail API. The displayed body text, headed "ACCOUNT DOCUMENTAccount Activity", names no company and lists a reference ID and a "SUPPORT DESK" number, 1.856.409.8315. The inline image shows what appears to be a PayPal order confirmation for a $319.47 Springfield Armory gun and tells the reader "Call our Dispute Center to cancel this order. Call +1 856 409 8315, within 24H", while a line at the bottom gives a second number, +1 805 607 9630. No links were found by a URL regex over the text/plain part or by list-links.py, and the HTML part contains no `<form>` or `<area>` tags, so the call to action is a phone number rather than a link. There are no file attachments; the one inline image is declared image/heif with the filename CYRIL-2767755866786965381367-20260908.heic, but `file` identifies it as a Windows BMP (1024 x 1325, 24-bit), SHA256 0b2f6ff5a133f99099ec7cb9754e9e75492d766a42d8efa989e381524c75be9c; VirusTotal had no file match. Placing the branding and the second number in the image keeps them out of text-based filtering, and whether the image's mislabelling was deliberate cannot be determined from this sample.

## 3. Email metadata
| Field | Value |
|---|---|
| Subject | Current Records and Relevant Account Information Prepared for Your Records |
| From (display) | Matilde Mosciski |
| From (address) | `tesdioongrdccxfhbvcdg3456[@]gmail[.]com` |
| Return-Path | `tesdioongrdccxfhbvcdg3456[@]gmail[.]com` (same as From address) |
| Reply-To | Not present |
| Originating IP | 209.85.208.176 (mail-lj1-f176.google.com). This is Google's outbound relay and the last external hop, recorded by Microsoft at the trust boundary. The sender's own client IP is not in the headers; the message was submitted through gmailapi.google.com over HTTPREST. |
| Originating ASN / Org | Google LLC (ARIN OrgId GOGL), NetRange 209.85.128.0/17, NetName GOOGLE. ASN: AS15169 |
| Date | Tue, 8 Sep 2026 12:17:14 -0700 (2026-09-08 19:17:14 UTC) |
| Message-ID | `<CAOL1n_QBX0eU=Q0TfvjUr10-_5LEke7bg_rdxMNXjOEr6jFwqQ@mail.gmail.com>` |
| X-Mailer | Not present (no X-Mailer, User-Agent or X-MimeOLE header) |

## 4. Authentication results

| Check | Result | Interpretation |
|---|---|---|
| SPF | pass | Passed for gmail.com (`smtp.mailfrom`) from client IP 209.85.208.176, HELO mail-lj1-f176.google.com. Aligned: the MAIL FROM and From domains are both gmail.com. |
| DKIM | pass | Signing domain `d=gmail.com`, selector `s=20251104` (rsa-sha256, relaxed/relaxed). Aligned: `d=` matches the From domain. |
| DMARC | pass | `header.from=gmail.com`. SPF and DKIM both passed with alignment, so either would have satisfied DMARC on its own. Policy recorded at delivery: p=none, sp=quarantine, pct=100. sp applies only to subdomains, so p=none governs gmail.com. action=none. |
| ARC | pass (`arc=pass`) | Two instances. i=1 was added by Google (`d=google.com`, `s=arc-20260327`, cv=none); its AAR from mx.google.com records arc=none. i=2 was added by Microsoft (`d=microsoft.com`, `s=arcselector10001`, cv=pass). Delivery went directly from Google to Microsoft and DMARC passed without help, so ARC played no part in the outcome (compauth reason is 100, not the ARC-override code 130). |
| compauth | pass, reason=100 | Microsoft's composite authentication passed. Microsoft's header reference defines reason 100 as SPF or DKIM passing with the MAIL FROM and From domains aligned. That reference is written for Microsoft 365 organizations; this is a consumer Outlook.com mailbox, so the definition is applied on the assumption that the same codes are used. |

## 5. Analysis

**Authentication.** At delivery, Microsoft recorded passes for SPF, DKIM, DMARC, ARC and compauth (section 4). SPF passed for gmail.com from 209.85.208.176, DKIM passed with d=gmail.com and selector 20251104, and both align with the From domain. MxToolbox reported a DKIM authentication failure on the header-only copy it was given. These results show that gmail.com was not spoofed and that the message genuinely came from Google's systems. The MxToolbox failure is an artifact of analysing the headers without the body (section 0). The checks authenticate the domain only, so any Gmail account holder would pass them, and none of them cover the display name.

**Trust boundary.** The first Received header written by Microsoft is `from mail-lj1-f176.google.com (209.85.208.176) by DS2PEPF000061C1.mail.protection.outlook.com (10.167.23.68)` at 19:17:17 UTC, and everything above it is Microsoft-internal. The connecting IP also appears in Received-SPF (client-ip, with HELO mail-lj1-f176.google.com) and X-Sender-IP, and ARIN whois places it in 209.85.128.0/17, registered to Google LLC. and announced by AS15169. Microsoft stamped X-IncomingHeaderCount: 19, which matches the 19 headers in the block that Microsoft did not add: the 18 from Google's Received header through Content-Type, plus MIME-Version. It also stamped SCL 1 and BCL 0, and the message was found in Inbox. The last external hop is therefore Google's mail infrastructure, and because the message was submitted through the Gmail API, no client IP for the sender is recorded. DKIM's signed header list covers From, To, Subject, Date, Message-ID, Content-Type and MIME-Version and also names the absent Cc and Reply-To, so none of the signed headers could have been changed, and no Cc or Reply-To could have been added, after signing without breaking the signature. The Received lines below the boundary are not signed and are taken on trust from Google.

**Tools.** MxToolbox's Email Header Analyzer passed SPF alignment, SPF authentication and DKIM alignment, and flagged DKIM authentication and "DMARC Compliant" as problems. Its relay table marked 209.85.208.176 as blacklisted, along with ::1, the IPv6 loopback address on Microsoft's final internal hop. Google Admin Toolbox's Messageheader reported SPF, DKIM and DMARC as pass and labelled the Google hop "Originated at Gmail". MxToolbox's blacklist check found 209.85.208.176 on 1 of 60 lists (0SPAM), and the 0SPAM detail cites a different message sent on 2026-06-03. That listing records a message sent three months earlier through a shared Google relay, and the detail doesn't show its sender, so it can't be tied to this one; the other 59 lists were clean. The ::1 flag is meaningless, and MxToolbox's DKIM and "DMARC Compliant" flags do not outweigh the dkim=pass and dmarc=pass that the receiver recorded at delivery.

**Body and links.** The message has a text/plain part and a 2,105-byte text/html part that `file` reports as ASCII HTML. The displayed body text opens with "ACCOUNT DOCUMENTAccount Activity", states that "A summary of recent account activity is provided below for your review", and lists a reference ID (Q8MFZ30-LJ0E0MR8~DPN3LP4~X8V5PKFWQ3C), a date of "Tuesday, 2026, Sep 08-14:25:15", a "SUPPORT DESK" number, 1.856.409.8315, and "Bunker Hill, IL, 62014". The text names no company or brand, no URLs were found by a URL regex over the text/plain part or by the casebook's list-links.py, and the HTML contains no `<form>` or `<area>` tags. A VirusTotal hash search for the HTML part showed no file match. Apart from inviting the reader to review the activity, the body asks for nothing explicitly, but its support desk number is the same one the image tells the reader to call to cancel the order (see Attachments). No link-based payload was found in the text parts; the lure works through a phone number, which is consistent with callback phishing, and the PayPal branding appears only in the image. The VirusTotal result is weak evidence because a per-message HTML body is unlikely to be indexed.

## 6. Indicators of compromise
| Type | Value (defanged) | Context |
|---|---|---|
| Phone number | `+1 856 409 8315` | Primary callback number. In the body as the "SUPPORT DESK" number (written 1.856.409.8315) and in the image as the "Dispute Center" number to call "to cancel this order", "within 24H". |
| Phone number | `+1 805 607 9630` | Second callback number, at the bottom of the image: "please inform support immediately". |
| Email address | `tesdioongrdccxfhbvcdg3456[@]gmail[.]com` | Sender (From and Return-Path), display name "Matilde Mosciski". Authenticated Gmail account; message submitted via the Gmail API. |
| Email subject | `Current Records and Relevant Account Information Prepared for Your Records` | Subject line, for searching other mailboxes. |
| Message-ID | `CAOL1n_QBX0eU=Q0TfvjUr10-_5LEke7bg_rdxMNXjOEr6jFwqQ[@]mail[.]gmail[.]com` | Unique to this send; finds other copies of the same message. |
| SHA256 | `0b2f6ff5a133f99099ec7cb9754e9e75492d766a42d8efa989e381524c75be9c` | Inline image: the PayPal-branded order confirmation carrying both phone numbers. Declared image/heif, actually BMP. VirusTotal: no file match on 2026-10-05 (hash search only; the results page showed only a comments tab with 0 entries). |
| Filename | `CYRIL-2767755866786965381367-20260908.heic` | Filename of the inline image part. |
| String | `Q8MFZ30-LJ0E0MR8~DPN3LP4~X8V5PKFWQ3C` | "Reference ID" in the body text; may be generated per message. |
| IP address (not an IOC) | `209.85.208[.]176` | mail-lj1-f176.google[.]com, Google LLC (209.85.128.0/17). Shared Gmail outbound relay; blocking it would block legitimate Gmail. |
| Domain (not an IOC) | `gmail.com` | Sender's free-mail domain; SPF, DKIM and DMARC passed. |

## 7. MITRE ATT&CK mapping

| Tactic | Technique | ID ||---|---|---|
| Reconnaissance (TA0043) | Phishing for Information | T1598 |
| Initial Access (TA0001) | Phishing | T1566 |
| Stealth (TA0005) | Social Engineering: Impersonation | T1684.001 |

Nothing in the email is tailored to the recipient, and it directs the reader to call the phone numbers it gives rather than delivering a link or malicious file. ATT&CK's Phishing (T1566) and Phishing for Information (T1598) both cover non-targeted phishing and messages that tell victims to call a phone number: T1566 when the call leads to access, such as installing malware or remote-access tools, and T1598 when it is used to collect information. The email alone doesn't show which, so both are listed; if the purpose of the call becomes known, keep only the matching one. Their Spearphishing Voice sub-techniques (T1566.004, T1598.004) are not used, because ATT&CK defines spearphishing as targeting a specific individual, company or industry, which this message does not show. Impersonation covers the PayPal-branded order confirmation in the image. Not mapped: Email Spoofing (T1684.002), because the From address is a real, authenticated Gmail account; User Execution (T1204), because there is no link or file and no execution was observed; and Establish Accounts (T1585) or Compromise Accounts (T1586) for the Gmail account, because the evidence doesn't show which applies. IDs checked at attack.mitre.org (ATT&CK content v19.2) on 2026-10-07.

## 8. Recommended actions
**Contain:** No call was made to either number. Do not call +1 856 409 8315 or +1 805 607 9630. Add tesdioongrdccxfhbvcdg3456[@]gmail[.]com to the Outlook.com blocked senders list, because reporting a message as phishing does not block its sender on its own. If anyone did call either number, treat it as a possible compromise: sign in to PayPal and the bank directly rather than through anything in the email, check the device for remote-access software installed during or after the call, and change any passwords or codes that were shared.

**Scope:** The message has one visible recipient [REDACTED-RECIPIENT]; any Bcc recipients can't be seen from this copy. Search the mailbox, including Junk Email and Deleted Items, for the sender address, the subject line and the body number 1.856.409.8315. The second number, +1 805 607 9630, appears only in the image, so a text search won't find it unless the search covers image text. If the recipient has a PayPal account, sign in through the app or by typing paypal.com and confirm that no $319.47 Springfield Armory order exists. Record what each search found. In an organization, a message trace on the sender address, subject and Message-ID would identify other recipients.

**Eradicate:** Forward the email to phishing@paypal.com (the whole email, not as an attachment), then report it in Outlook.com with Report > Report phishing; forward first in case reporting removes the message. Delete any remaining copies, including from Deleted Items. The case copy is preserved as case-002.eml (SHA256 in section 0). No links were found, there are no file attachments and the message carried nothing executable, so no host clean-up is needed unless a call was made (see Contain).

**Intelligence:** Report the sender to Google through its Gmail abuse form, including the full headers from case-002 if the form asks for them. Add the section 6 indicators to the casebook so later cases can be matched against them, especially the two phone numbers, the image hash and the image filename pattern: an uppercase word, a 22-digit string and the send date, with a .heic extension on BMP content. Search VirusTotal for the image hash (hash only, per methodology) and repeat the search later, as the hash may appear once others submit it. If the recipient is in the US, the callback numbers can also be reported to the FTC at ReportFraud.ftc.gov.

## 9. Detection opportunity

Authentication and reputation controls had nothing to catch here. SPF, DKIM and DMARC passed for gmail.com, the connecting IP belongs to Google, no URL was found to check, and Microsoft scored the message SCL 1. Catching it needs a content rule that targets the shape of a callback lure sent from a free-mail account:

```text
Rule: Free-mail callback lure (no links)
Match when all of these are true:
  1. From domain is a consumer free-mail domain (gmail.com, outlook.com, yahoo.com, ...)
  2. Decoded body text (text/plain and visible text/html) contains no URLs
  3. Body text contains a North American phone number:
       (?<!\d)(?:\+?1[\s.\-]?)?\(?[2-9]\d{2}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)
  4. The message has an image part (inline or attachment)
  5. Subject or body contains a lure term (case-insensitive):
       account, transaction, order, invoice, receipt, payment, refund,
       cancel, dispute, unauthorized, support
Tuning, to separate lure images from signature logos:
  6. Visible body text is short (start at under 100 words)
  7. The largest image is page-sized (start at 800 px or more on one side)
Action: warning banner or quarantine for review, not reject
```
This message meets all seven conditions: a gmail.com sender, no URLs found, "1.856.409.8315" in the body, one inline image, "Account" in the subject and "account" and "SUPPORT" in the body, about 30 words of body text, and a 1024 x 1325 image. If the gateway can run OCR on images, adding a call instruction found in the image text (here "Call our Dispute Center"), plus the brand name where it appears as text rather than only as a logo, would make the rule more precise. It would also capture the second number, which appears only in the image, at the cost of OCR processing on every image-bearing message.

False positives: The main cost is small businesses, sole traders, landlords, tutors and clubs that run on Gmail and send invoices, receipts or order confirmations as an image or scanned page with a phone number; these can meet every condition. Personal messages that forward a screenshot of a real receipt or statement with a contact number also match. So do messages where a 10-digit order or account number looks like a phone number to the regex. Because legitimate mail of this shape exists, the rule should warn or queue for review rather than block. Measure its hit rate on a sample of your own mail before fixing the thresholds.

A second check would have flagged the inline image: compare each image part's leading bytes with its declared Content-Type and filename extension (BMP begins with "BM", PNG with 89 50 4E 47, JPEG with FF D8 FF, GIF with "GIF8", and HEIF carries "ftyp" at byte offset 4). Here the part is declared image/heif with a .heic name, but `file` identified the content as BMP. False positives come from images renamed without conversion and from senders that declare a wrong or generic image type (normalise aliases such as image/jpg and image/jpeg first), so use the mismatch to raise the score of a first-rule match rather than as a standalone alert.

## 10. Appendix

**A. Received chain (newest first, recipient redacted)**
```
Received: from CY5PR12MB6203.namprd12.prod.outlook.com (::1) by
 MW4PR12MB7238.namprd12.prod.outlook.com with HTTPS; Tue, 8 Sep 2026 19:17:21
 +0000
Received: from DS7PR05CA0073.namprd05.prod.outlook.com (2603:10b6:8:57::27) by
 CY5PR12MB6203.namprd12.prod.outlook.com (2603:10b6:930:24::17) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.21.382.15; Tue, 8 Sep 2026 19:17:17 +0000
Received: from DS2PEPF000061C1.namprd02.prod.outlook.com
 (2603:10b6:8:57:cafe::87) by DS7PR05CA0073.outlook.office365.com
 (2603:10b6:8:57::27) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.21.406.7 via Frontend Transport; Tue, 8
 Sep 2026 19:17:17 +0000
Received: from mail-lj1-f176.google.com (209.85.208.176) by
 DS2PEPF000061C1.mail.protection.outlook.com (10.167.23.68) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.21.406.5
 via Frontend Transport; Tue, 8 Sep 2026 19:17:17 +0000
Received: by mail-lj1-f176.google.com with SMTP id 38308e7fff4ca-3a34f7ebcedso42998281fa.3
        for <[REDACTED-RECIPIENT]>; Tue, 08 Sep 2026 12:17:17 -0700 (PDT)
Received: from 943475899706 named unknown by gmailapi.google.com with
 HTTPREST; Tue, 8 Sep 2026 12:17:14 -0700
Received: from 943475899706 named unknown by gmailapi.google.com with
 HTTPREST; Tue, 8 Sep 2026 12:17:14 -0700
```

**B. Authentication headers added by Microsoft**

```
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 209.85.208.176) [REDACTED] smtp.mailfrom=gmail.com; dmarc=pass
 (p=none sp=quarantine pct=100) action=none header.from=gmail.com; dkim=pass
 (signature was verified) header.d=gmail.com; arc=pass (0 oda=0 ltdi=1)
Authentication-Results: spf=pass (sender IP is 209.85.208.176)
 smtp.mailfrom=gmail.com; dkim=pass (signature was verified)
 header.d=gmail.com;dmarc=pass action=none header.from=gmail.com;compauth=pass
 reason=100
Received-SPF: Pass (protection.outlook.com: domain of gmail.com designates
 209.85.208.176 as permitted sender) receiver=protection.outlook.com;
 client-ip=209.85.208.176; helo=mail-lj1-f176.google.com; pr=C
```

**C. MIME parts and extracted files (parts listing, `file`, `sha256sum`)**

```
0 multipart/related None None
1 multipart/alternative None None
2 text/plain None None
3 text/html None None
4 image/heif inline 'CYRIL-2767755866786965381367-20260908.heic'
attachment-3.bin: HTML document, ASCII text
990189aa27a07bbdce4362fd5b2f3d843cabe4ff278f48d3c525c48c80ba08b4  attachment-3.bin
attachment-4.bin: PC bitmap, Windows 3.x format, 1024 x 1325 x 24, image size 4070400, resolution 3780 x 3780 px/m, cbSize 4070454, bits offset 54
0b2f6ff5a133f99099ec7cb9754e9e75492d766a42d8efa989e381524c75be9c  attachment-4.bin
```

**D. Tool results summary**

| Tool | Result | Assessment |
|---|---|---|
| Google Admin Toolbox Messageheader | SPF and DKIM pass with IP and domain "Unknown"; DMARC pass; 3 hop rows | IP and domain not extracted; hop table misses three Microsoft hops and both Gmail API lines |
| MXToolbox Analyze Headers | 8 hops; DKIM body hash failed | Hop order and times correct; DKIM failure caused by headers-only input |
| MXToolbox blacklist, 209.85.208.176 | Listed on 0SPAM (1 of 60) | Shared Google address; listing cites a different message received from that address on 2026-06-03 |
| MXToolbox relay table, `::1` | Flagged "Is on a blacklist" | Loopback address; meaningless |
| VirusTotal hash searches | HTML part: no file match; image: no file match | HTML result weak, as a per-message body is unlikely to be indexed |

**E. Links**

No URLs found in the message; urlscan not applicable.