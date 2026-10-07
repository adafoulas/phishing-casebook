# Case 003 — Spoofed Microsoft sender in an ABC News-branded weight-loss link lure

**Analyst:** Alex Dafoulas

**Date of analysis:**  2026-10-05

## 0. Acquisition and handling
**Source:** Personal Outlook mailbox (Outlook.com consumer account, recipient
[REDACTED-RECIPIENT]). Delivered 2026-09-15 04:05:42 UTC (top Received header).

**Original filename:** email-1.2.eml

**Working filename:** case-003.eml

**Method:** Forwarded as an attachment to an isolated analysis mailbox. The
header block was also copied from Outlook "View message source" and pasted
into the message body as a fidelity cross-check.

**Received format:** .eml (`file`: RFC 822 mail, Unicode text, UTF-8 text, with very long lines (749))

**Header source of record:** Header block extracted directly from the
received .eml (`sed` through the first blank line, saved as
original-headers.txt). Pasted copy compared with all whitespace removed:
differs at byte 3865, the start of the To: value. A line diff (CRs
stripped) found two non-whitespace changes in the pasted copy: the To:
value [Brain Health Alert] is wrapped in double quotes, and the header
name Reply-to is capitalised as Reply-To. All other differences were
whitespace: 22 headers had their first continuation line joined onto the
header-name line, two continuation lines were indented with a tab instead
of a space, and the trailing header/body separator line that the `sed`
range includes was missing. The extracted block is the source of record,
so neither change affects the analysis.

**Sample SHA256:** fd3687fc4d5b938e0996c91de9b07a1037a8bcae2310bd6767e55d8a2b82222a (23,449 bytes)

**Attachments:** None. The message is a single text/html part (the only
entry in the email.walk() listing, index 0), with no Content-Disposition
and no filename, so there are no attachments or inline parts to extract.

**Environment:** Ubuntu 26.04 VM; shared folders and clipboard disabled;
static analysis only, no execution

**Known limitations:** One URL was found. Safe Links had rewritten it as a
na01.safelinks.protection.outlook.com wrapper. The original destination
(hxxps://b2yx9l-gma-health[.]posirjdating[.]site/c/[...]) was recovered by
URL-decoding the wrapper's url= parameter, not from originalsrc. The
recovered URL was scanned on 2026-10-05, 20 days after delivery on
2026-09-15, so the results may not reflect what it served at delivery.
urlscan.io (Private, 19:39:00 UTC) followed two HTTP redirects to
www[.]skyresistserver[.]com, where the final request returned HTTP 204 with
an empty body; no screenshot was captured and urlscan gave no
classification. VirusTotal (19:42:29 UTC, the URL's first submission)
returned 0/92 detections, with Forcepoint ThreatSeeker categorising the
URL as a newly registered website. Because it was a submission rather than
a lookup, the full URL, including its tracking token, is now in
VirusTotal's corpus. DNS records (microsoft.com SPF and DMARC, DKIM key
for selector selector1-800sat-onmicrosoft-com at 800sat.onmicrosoft.com)
and the blacklist check of 40.93.64.64 were also checked on 2026-10-05.
Link extraction scope: the casebook's list-links.py run against
case-003.eml (one `<a href>` link), a URL regex over text/plain parts (the
message has none, so there was nothing to search), and a search of the
text/html part for `<form>` and `<area>` tags (none found). None of these
enumerate `<img src>` or other non-anchor URLs, so remotely loaded images
and tracking pixels are outside their scope. The message was
viewed in Outlook with remote images loaded. Header-only
copies of the extracted block were submitted to MxToolbox Email Header
Analyzer and Google Admin Toolbox Messageheader. MxToolbox's "DKIM
Authenticated" failure ("Body Hash Did Not Verify") is an artifact of
submitting headers without the body: its expected body hash
(47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=) is the SHA-256 of an empty
body. The receiving server's dkim=pass at delivery is the result of record.

## 1. Executive summary
On 15 September 2026, a personal Outlook.com mailbox received an email that appeared to come from Microsoft's address `office365alerts[@]microsoft[.]com` under the name "ABC News Live", presenting a weight-loss "gelatin trick" as an ABC News health story, complete with viewer comments and a link inviting the reader to see the trick. The email is assessed as malicious: it is a scam that impersonates both Microsoft and ABC News, and the whole message appears to be a single link leading through a chain of tracking redirects to a website that showed nothing when it was checked 20 days later, so what that site offers or collects could not be seen. The email passed the standard checks that confirm where a message came from, but only because it was passed through Microsoft's own mail servers; an earlier record inside the message shows those checks failing or missing for Microsoft's address when the message came from an unrelated hosting company's network. The recommended response is not to click anything in the email or reply to it, to report it as phishing in Outlook, to report the misuse of Microsoft's mail service to Microsoft and the sending network to its hosting provider, and to delete the message.

## 2. Verdict

**Classification:** Malicious

**Campaign type:** Brand-impersonation health scam (spoofed sender, link lure)

**Confidence:** Medium

**Basis:** At delivery, SPF, DMARC and Microsoft's compauth (reason 100) passed for microsoft.com, but only because the message left through Microsoft 365's shared outbound servers (40.93.64.64), which microsoft.com's SPF authorises; DKIM passed only for `800sat.onmicrosoft[.]com`, which does not align with the From domain, and an upstream X-MS-Exchange-Authentication-Results header records spf=fail, dkim=none and dmarc=fail (action=oreject) for the same From domain from 38.252.8.155, a Newline Hosting address on a network reallocated in February 2026. The From header pairs the display name "🔴 ABC News Live" with `office365alerts[@]microsoft[.]com`, the Reply-To is `hello[@]nnemipa[.]org`, an unrelated domain, and the To header holds only the label "[Brain Health Alert]" with no address. The subject, "(1) New Video Message 📩  11 pounds gone in a week?", mimics a notification count, and the message is marked high importance. The body presents a weight-loss "gelatin trick" as a "GMA | Health" story with three named "viewers", two claiming losses of 11 and 26 pounds, above an "ABC News" footer. list-links.py found one link, which appears to wrap the entire message; Safe Links had rewritten it, and it decodes to hxxps://b2yx9l-gma-health[.]posirjdating[.]site/c/[...], whose base64 token carries a campaign value (6446). On 2026-10-05, urlscan.io followed two redirects to www[.]skyresistserver[.]com, where the final request returned HTTP 204 with an empty body, VirusTotal returned 0/92, and Forcepoint ThreatSeeker categorised the URL as a newly registered website. The message is a single text/html part with no attachments or inline parts, and it contains no `<form>` or `<area>` tags. The spoofed sender and the impersonation show a clear intent to deceive, but because the destination served nothing to either scanner, whether it collects payment details or credentials or only drives traffic to an offer cannot be determined from this sample.

## 3. Email metadata
| Field | Value |
|---|---|
| Subject | (1) New Video Message 📩  11 pounds gone in a week? |
| From (display) | 🔴 ABC News Live |
| From (address) | `office365alerts[@]microsoft[.]com` |
| Return-Path | `office365alerts[@]microsoft[.]com` (same as From address) |
| Reply-To | `hello[@]nnemipa[.]org` (differs from the From address) |
| Originating IP | 40.93.64.64 (DUZPR08CU001.outbound.protection.outlook[.]com). This is Microsoft 365's outbound relay and the last external hop, recorded by the receiving Microsoft server at the trust boundary; it is shared Microsoft infrastructure, not the sender's own host. An earlier connecting IP, 38.252.8.155 (HELO anugh.meegaeth[.]com), is recorded in X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp (TenantId 91c63d2b-8dec-44db-ac0a-88b943aa465c) and X-MS-Exchange-Authentication-Results. |
| Originating ASN / Org | 40.93.64.64: Microsoft Corporation (ARIN OrgId MSFT), NetRange 40.74.0.0 - 40.125.127.255, NetName MSFT. ASN: AS8075 (MICROSOFT-CORP-MSN-AS-BLOCK), BGP prefix 40.80.0.0/12. 38.252.8.155: Newline Hosting (ARIN OrgId NHL-158), NetRange 38.252.8.0/24, NetName NEWLINE-CGNT-NET-2, reallocated from Cogent Communications (COGC) on 2026-02-24. ASN: AS40156 (THEOPT-HOU - The Optimal Link Corporation), BGP prefix 38.252.8.0/24. ARIN OriginAS is blank for both; ASNs from Team Cymru. |
| Date | Mon, 14 Sep 2026 21:04:39 -0700 (2026-09-15 04:04:39 UTC) |
| Message-ID | `<a094f979-1d7f-45d5-b411-d4bb7f2b0330@QB1PEPF00004E0F.CANPRD01.PROD.OUTLOOK.COM>` |
| X-Mailer | Not present (no X-Mailer, User-Agent or X-MimeOLE header) |

## 4. Authentication results

| Check | Result | Interpretation |
|---|---|---|
| SPF | pass | Passed for microsoft.com (`smtp.mailfrom`) from client IP 40.93.64.64, HELO DUZPR08CU001.outbound.protection.outlook.com. Aligned: the MAIL FROM and From domains are both microsoft.com. The IP is shared Microsoft 365 outbound infrastructure, authorised by microsoft.com's SPF through `_spf-a.microsoft.com`, which includes spf.protection.outlook.com (40.92.0.0/15 in the 2026-10-05 lookup), so the pass shows the message left through Microsoft 365, not that Microsoft sent it. An upstream X-MS-Exchange-Authentication-Results header records spf=fail for the same domain from 38.252.8.155. |
| DKIM | pass | Signing domain `d=800sat.onmicrosoft.com`, selector `s=selector1-800sat-onmicrosoft-com` (rsa-sha256, relaxed/relaxed). Not aligned: d= is a Microsoft 365 tenant domain under onmicrosoft.com, not microsoft.com. It is the only DKIM-Signature in the message. The upstream X-MS-Exchange-Authentication-Results records dkim=none (message not signed). |
| DMARC | pass | `header.from=microsoft.com`, action=none. Carried by SPF alone, since DKIM was not aligned. Policy recorded at an earlier Microsoft hop (ARC i=1): p=reject, sp=reject, pct=100; the receiving server's Authentication-Results does not record it. The upstream X-MS-Exchange-Authentication-Results records dmarc=fail action=oreject for the same From domain: Microsoft's "override reject", which marks a p=reject failure as spam instead of rejecting it. |
| ARC | Not evaluated (no `arc=` in Authentication-Results) | One instance, i=1, sealed by Microsoft (`d=microsoft.com`, `s=arcselector10001`, cv=pass). Its AAR from mx.microsoft.com records an earlier Microsoft 365 hop to recipient domain 8hig.org: SPF pass from 2a01:111:f403:c111::20, DMARC pass, and DKIM pass for `header.d=allnationsuniversity.onmicrosoft[.]com`, a signature no longer in the message. cv=pass on i=1 is unusual, since RFC 8617 expects cv=none on the first instance. Compauth reason is 100, not the ARC-override code 130, so ARC played no part in the outcome. |
| compauth | pass, reason=100 | Microsoft's composite authentication passed. Reason 100: SPF or DKIM passed, and the MAIL FROM and From domains are aligned (here, through SPF). |

## 5. Analysis

**Acquisition.** The sample arrived as email-1.2.eml, was renamed case-003.eml and was hashed before any parsing (SHA256 in section 0). `file` identified it as RFC 822 mail, and a MIME walk listed a single text/html part. With all whitespace removed, the extracted header block first differed from the copy pasted from Outlook's "View message source" at byte 3865: the pasted copy wraps the To: value in double quotes and capitalises Reply-to as Reply-To. Every other difference was whitespace: 22 headers had their first continuation line joined onto the header-name line, two continuation lines were indented with a tab instead of a space, and the trailing header/body separator line was missing. The .eml headers are therefore the source of record for the rest of the analysis.

**Headers.** The From header is `🔴 ABC News Live <office365alerts[@]microsoft[.]com>`: the display name names a news brand, and the address is styled as a Microsoft 365 alert mailbox. Return-Path is the same address, but Reply-To is `hello[@]nnemipa[.]org`, an unrelated domain, so replies would go there. The To header contains only the label "[Brain Health Alert]" with no address, there is no Cc, and the analysed mailbox's address appears in no header. The subject, "(1) New Video Message 📩  11 pounds gone in a week?", mimics an unread-notification count, and the message is marked Importance: high and X-Priority: 1. The Date header is Mon, 14 Sep 2026 21:04:39 -0700 (04:04:39 UTC), 63 seconds before final delivery at 04:05:42 UTC, and there is no X-Mailer, User-Agent or X-MimeOLE header. The Message-ID's host, QB1PEPF00004E0F.CANPRD01.PROD.OUTLOOK.COM, is also the first server listed in X-MS-TrafficTypeDiagnostic, which is consistent with the Message-ID being assigned inside Exchange Online rather than by the sender's software. Together, a news brand, a Microsoft address and a third domain for replies are inconsistent with genuine mail from either ABC News or Microsoft, and the recipients are not disclosed.

**Authentication.** At delivery, Microsoft recorded passes for SPF, DKIM, DMARC and compauth, reason 100 (section 4). SPF passed for microsoft.com because 40.93.64.64 is a Microsoft 365 outbound server that microsoft.com's SPF authorises through `_spf-a.microsoft.com`, which includes spf.protection.outlook.com, and DMARC passed on SPF alone, since the only DKIM signature, from `800sat.onmicrosoft.com`, does not align with microsoft.com. An upstream X-MS-Exchange-Authentication-Results header records the opposite for the same From domain: spf=fail from 38.252.8.155, dkim=none (message not signed) and dmarc=fail with action=oreject. ARC i=1 records a further Microsoft 365 hop, to recipient domain 8hig.org, where DKIM passed for `allnationsuniversity.onmicrosoft.com`, a signature no longer in the message. MxToolbox's DKIM authentication failure is an artifact of analysing the headers without the body (section 0), but its alignment failure is genuine. These results show microsoft.com was spoofed at an earlier hop, where Microsoft recorded the message arriving from 38.252.8.155, and the passes at delivery reflect its relay out through Microsoft 365's shared infrastructure rather than authentic microsoft.com mail.

**Trust boundary.** The first Received header written by the receiving side is `from DUZPR08CU001.outbound.protection.outlook.com (40.93.64.64) by DU2PEPF00028CFF.mail.protection.outlook.com (10.167.242.183)` at 04:05:40 UTC, and the three above it are Microsoft-internal, ending at MW4PR12MB7238 at 04:05:42 UTC. The connecting IP also appears in Received-SPF (client-ip, with HELO DUZPR08CU001.outbound.protection.outlook.com) and X-Sender-IP, and ARIN whois and Team Cymru place it in Microsoft's allocation (OrgId MSFT, AS8075). There are no Received headers below the boundary, so the earlier path is recorded only in Microsoft's diagnostic headers: X-MS-TrafficTypeDiagnostic lists seven Microsoft server names, and X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp attributes the message to tenant 91c63d2b-8dec-44db-ac0a-88b943aa465c, connecting from 38.252.8.155 with HELO `anugh.meegaeth[.]com`. ARIN places 38.252.8.155 in 38.252.8.0/24, reallocated by Cogent to Newline Hosting on 2026-02-24, and Team Cymru shows the prefix announced by AS40156 (The Optimal Link Corporation). Microsoft stamped SCL 1 and BCL 4, and the message was found in Inbox. DKIM's signed header list covers From, Date, Subject, Message-ID, Content-Type, MIME-Version and X-MS-Exchange-SenderADCheck but not To or Reply-To, so those two headers could have been set or changed after signing without breaking the signature. The last external hop is therefore shared Microsoft infrastructure and says nothing about the sender, and the most specific source recorded is a hosting-provider address on a network registered about seven months before delivery. That attribution comes from Microsoft's own headers rather than a Received chain, so it cannot be independently verified from this message.

**Tools.** MxToolbox's Email Header Analyzer marked DMARC compliance, SPF alignment and SPF authentication as passing, and flagged DKIM alignment and DKIM authentication as problems. Its relay table listed four hops starting at 40.93.64.64, with a received delay of 2 seconds, and marked all four IPs as not blacklisted. Google Admin Toolbox's Messageheader reported SPF, DKIM and DMARC as pass with IP and domain "Unknown" and a delivery 63 seconds after creation, but its hop table shows only two hops, omitting the trust-boundary hop from 40.93.64.64 and the DB8PR04CA0010 to DS0PR12MB9347 hop. Both tools display X-MS-Exchange-Authentication-Results, MxToolbox in its list of headers found and Google Admin Toolbox in its raw header view, but neither evaluates it. Both tools therefore confirm the delivery-time results while missing the upstream failure. Identifying the spoofing required reading Microsoft's own headers by hand.

**Body and links.** The message is a single UTF-8 text/html part with no text/plain alternative, so the URL regex over text/plain parts had nothing to search; the HTML contains no `<form>` or `<area>` tags, and list-links.py found one link. list-links.py reported the whole message text, including a title-like line and the CSS, as that link's anchor text, which indicates one link wrapping the entire message, so a click anywhere would follow it. Styled as a "GMA | Health" item with a comment thread, the text opens with the quote "My doctor couldn't believe it" and the headline "The simple gelatin trick melting belly fat", promises "No Ozempic, no gym", just a "Gelatin Trick" before bed, quotes three named "viewers", two claiming losses of 11 and 26 pounds, and ends with a "See The Gelatin Trick »" call to action above an "ABC News" footer with a New York address. Safe Links had wrapped the link, which decodes to hxxps://b2yx9l-gma-health[.]posirjdating[.]site/c/[...], whose last path segment is base64 for `usr`, `lst` and `cmp` parameters (cmp=6446). On 2026-10-05, urlscan.io followed two HTTP redirects to www[.]skyresistserver[.]com (109.73.73.228, AS20860 IOMART, United Kingdom), passing the same value as sub3=6446, and the final request returned HTTP 204 with an empty body; urlscan gave no classification, and VirusTotal returned 0/92, with Forcepoint ThreatSeeker categorising the URL as a newly registered website. The email asks the reader to click through to see the "gelatin trick", presenting a weight-loss claim as ABC News coverage to drive clicks into a tracked redirect chain. Because the destination served nothing to either scanner, the clean results show only that nothing was served on 2026-10-05, not that the destination is safe.

**Attachments.** There are no attachments or inline parts: the walk() listing shows a single text/html part with no Content-Disposition or filename. There was therefore nothing to extract, hash or look up, and the message carries no file-based payload. Any images the HTML loads remotely were not enumerated (section 0).

**Conclusion.** The message claims to come from `office365alerts[@]microsoft[.]com` under the display name "🔴 ABC News Live", but an upstream Microsoft authentication result for that address failed SPF and DMARC, with no DKIM signature, from 38.252.8.155, on a hosting network registered in February 2026. It carries traces of several Microsoft 365 tenants, was DKIM-signed by an unrelated tenant domain, and reached the analysed mailbox from Microsoft 365's shared outbound servers, which microsoft.com's SPF authorises, so SPF, DMARC and compauth passed at delivery. The Reply-To points to an unrelated domain, nnemipa[.]org, and the analysed mailbox appears in no header. The body presents a weight-loss "gelatin trick" as ABC News coverage with viewer testimonials, and the whole message appears to be one link, leading through a tracked redirect chain to www[.]skyresistserver[.]com, which served nothing to the scanners on 2026-10-05. No attachments or forms were found. Classification and confidence are recorded in section 2.

## 6. Indicators of compromise
| Type | Value (defanged) | Context |
|---|---|---|
| URL | `hxxps://b2yx9l-gma-health[.]posirjdating[.]site/c/[...]` | Original destination of the Safe Links-wrapped link, which appears to span the whole message. The path ends in a base64 token carrying `usr`, `lst` and `cmp` (6446) parameters, withheld here. |
| Domain | `b2yx9l-gma-health[.]posirjdating[.]site` | First hop of the link (apex `posirjdating[.]site`). For the full URL on 2026-10-05: Forcepoint ThreatSeeker category "newly registered websites", VirusTotal 0/92, urlscan no classification. |
| Domain | `www[.]skyresistserver[.]com` | Redirect target: `/REDACTED/REDACTED/` then `/REDACTED/REDACTED/`, passing sub3=6446; the final request returned HTTP 204 with an empty body on 2026-10-05. Sectigo DV certificate issued 2026-06-22. |
| IP address | `109.73.73[.]228` | Served www[.]skyresistserver[.]com in the urlscan scan. IOMART Cloud Services, AS20860, United Kingdom; reverse DNS antoine[.]brainwavehq[.]com. May be shared hosting. |
| Email address | `hello[@]nnemipa[.]org` | Reply-To; replies would go here instead of to the From address. |
| IP address | `38.252.8[.]155` | Connecting IP (HELO anugh[.]meegaeth[.]com) named in X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp and in an upstream X-MS-Exchange-Authentication-Results, where SPF and DMARC for microsoft.com failed. Newline Hosting, 38.252.8.0/24, reallocated 2026-02-24; announced by AS40156. |
| Microsoft 365 tenant ID | `91c63d2b-8dec-44db-ac0a-88b943aa465c` | Tenant attributed with the 38.252.8.155 connection (X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp); may help when reporting to Microsoft. |
| Domain | `800sat[.]onmicrosoft[.]com` | DKIM signing domain (selector selector1-800sat-onmicrosoft-com); a Microsoft 365 tenant domain unrelated to the From domain. May be abused rather than attacker-owned. |
| Email subject | `(1) New Video Message 📩  11 pounds gone in a week?` | Subject line, for searching other mailboxes. Two spaces follow the emoji. |
| Message-ID | `a094f979-1d7f-45d5-b411-d4bb7f2b0330@QB1PEPF00004E0F.CANPRD01.PROD.OUTLOOK.COM` | Unique to this send; finds other copies of the same message. |
| Email address (spoofed, not an IOC on its own) | `office365alerts[@]microsoft[.]com` | Spoofed From and Return-Path, display name "🔴 ABC News Live". A microsoft.com address, so blocking it outright could block legitimate Microsoft mail. |
| IP address (not an IOC) | `40.93.64[.]64` | DUZPR08CU001.outbound.protection.outlook[.]com, Microsoft (AS8075). Shared Microsoft 365 outbound relay; blocking it would block legitimate Microsoft 365 mail. |

## 7. MITRE ATT&CK mapping
| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Phishing for Information | T1598 |
| Initial Access | Phishing | T1566 |
| Stealth | Social Engineering: Email Spoofing | T1684.002 |
| Stealth | Social Engineering: Impersonation | T1684.001 |

The email's only call to action is a single link that leads through a redirect chain to www[.]skyresistserver[.]com. Both phishing rows are mapped at the technique level rather than to the Spearphishing Link sub-techniques (T1598.003, T1566.002), because ATT&CK defines spearphishing as targeted at a specific individual, company, or industry, and nothing in this email was tailored to the recipient: the To header holds only a list label, the content is generic, and the link token appears to carry list and campaign values. Both parent techniques explicitly include non-targeted phishing. ATT&CK uses T1598 when the destination collects information and T1566 when it is used to gain access to the victim's system; the destination served nothing to either scanner, so the email alone doesn't show which applies, and both rows are kept until the destination's purpose becomes known. Email Spoofing covers the From address `office365alerts@microsoft.com`, which an upstream Microsoft hop recorded failing SPF and DMARC from 38.252.8.155 before the message was relayed out through Microsoft 365. Impersonation covers the "ABC News Live" display name and the body's ABC News and GMA branding. Not mapped: User Execution: Malicious Link (T1204.001), because no click or execution was observed; and Establish Accounts or Compromise Accounts for the Microsoft 365 tenants involved, because the evidence doesn't show which applies. IDs checked at attack.mitre.org (ATT&CK v19) on 2026-10-05.

## 8. Recommended actions
**Contain:** The link was not clicked. Do not click anywhere in the message, since the whole message appears to be one link, and do not reply, since replies go to `hello[@]nnemipa[.]org` rather than to the From address. Blocking `office365alerts[@]microsoft[.]com` in Outlook.com is of little use: it would stop only mail claiming that exact address, would not cover other spoofed addresses, and could block genuine mail if Microsoft uses that address. If a DNS filter or browser blocklist is available, add posirjdating[.]site and skyresistserver[.]com. If anyone did click, check the browser's downloads for any file saved from the site, and if payment details were entered or anything was bought, contact the card issuer.

**Scope:** The To header holds only the label "[Brain Health Alert]", so no recipient can be seen from this copy, and the analyzed mailbox's address appears in no header. Search the mailbox, including Junk Email and Deleted Items, for the sender address `office365alerts[@]microsoft[.]com`, the display name "ABC News Live" and the subject text "New Video Message". Record what each search found. The link's base64 token appears to carry per-recipient and campaign values, which suggests the address is on the sender's list, so further messages from the same campaign may follow under different subjects or senders. In an organization, a message trace on the sender address, subject and Message-ID would find other recipients, and web proxy or DNS logs for posirjdating[.]site and skyresistserver[.]com would show which users visited them.

**Eradicate:** Complete the Intelligence reports first if they need the original message, then report the email in Outlook.com with Report > Report phishing. Delete any remaining copies, including from Deleted Items. The case copy is preserved as case-003.eml (SHA256 in section 0). The message has no attachments, and the link was not clicked, so no host clean-up is needed unless a click was made (see Contain).

**Intelligence:** Report the misuse of Microsoft's mail service to Microsoft through the channels listed in its ARIN whois record (https://cert.microsoft.com for malicious content sent through Microsoft online services, or `abuse@microsoft.com` for spam). Include the full headers from case-003, the tenant ID 91c63d2b-8dec-44db-ac0a-88b943aa465c and the DKIM signing domain 800sat.onmicrosoft.com. Report 38.252.8.155 to Newline Hosting's abuse contact from its ARIN whois record, `abuse@newlinehost.com`. Add the section 6 indicators to the casebook so later cases can be matched against them, especially the two domains, the redirect paths (held in the private casebook), 109.73.73.228, the Reply-To address and the campaign value 6446. Re-check the URL later by looking up the existing VirusTotal and urlscan.io reports rather than submitting it again, and if the recipient is in the US, the deceptive health claim can also be reported to the FTC at ReportFraud.ftc.gov.

## 9. Detection opportunity

Authentication and reputation controls had nothing to catch here. SPF, DMARC and compauth passed for microsoft.com because the message left through Microsoft 365's shared outbound servers, Microsoft scored the message SCL 1, and even on 2026-10-05, 20 days after delivery, the link had no malicious verdicts (VirusTotal 0/92, no urlscan classification), only Forcepoint's "newly registered websites" category. The evidence of spoofing survived in the message itself, so the rule compares the receiver's result with the upstream one:

```text
Rule: Upstream DMARC failure behind a delivery-time pass
Match when all of these are true:
  1. The receiving side's Authentication-Results records dmarc=pass
  2. An X-MS-Exchange-Authentication-Results header in the message
     records dmarc=fail for the same header.from domain
Raise the score when any of these is also true:
  3. No DKIM signature aligns with the From domain, and the signing
     domain (d=) ends in .onmicrosoft.com
  4. The Reply-To domain differs from the From domain
  5. The From domain is on a protected-brand list (microsoft.com,
     paypal.com, the organisation's own domains, ...)
Action: quarantine, or a warning banner where quarantine isn't available
```

This message meets both match conditions: the receiving side recorded `dmarc=pass action=none header.from=microsoft.com`, and the upstream header recorded `dmarc=fail action=oreject header.from=microsoft.com`. It also meets all three scoring conditions: the only DKIM signature is from 800sat.onmicrosoft.com, the Reply-To domain is nnemipa[.]org, and the From domain is microsoft.com. In Exchange Online, conditions 1 and 2 can be approximated with a mail flow rule that matches words in message headers, but checking that both results name the same domain needs a gateway or SIEM that parses the headers.

False positives: Legitimate mail can carry an upstream DMARC failure when the sender's own authentication is misconfigured and the message is then relayed or forwarded through Microsoft 365, for example a third-party application or on-premises server sending as an organisation's domain through a connector. Mailing lists and forwarding services that keep the original From can produce the same pattern. Condition 3 alone matches organizations that never set up DKIM for their custom domain and sign with their default onmicrosoft.com domain, and condition 4 matches newsletters and ticketing systems that set a separate Reply-To, which is why both only raise the score. Condition 2 also depends on a Microsoft header that other mail paths may not carry and that Microsoft could change or strip, so the rule can stop matching without warning; a periodic test message would show whether it still fires. Run the rule in report-only mode on a sample of your own mail, and allow-list known connectors, before quarantining.

## 10. Appendix

**A. Received chain (newest first)**

```
Received: from DS0PR12MB9347.namprd12.prod.outlook.com (2603:10b6:8:193::19)
 by MW4PR12MB7238.namprd12.prod.outlook.com with HTTPS; Tue, 15 Sep 2026
 04:05:42 +0000
Received: from DB8PR04CA0010.eurprd04.prod.outlook.com (2603:10a6:10:110::20)
 by DS0PR12MB9347.namprd12.prod.outlook.com (2603:10b6:8:193::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.21.406.12; Tue, 15 Sep
 2026 04:05:41 +0000
Received: from DU2PEPF00028CFF.eurprd03.prod.outlook.com
 (2603:10a6:10:110:cafe::a6) by DB8PR04CA0010.outlook.office365.com
 (2603:10a6:10:110::20) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.21.406.13 via Frontend Transport; Tue,
 15 Sep 2026 04:05:40 +0000
Received: from DUZPR08CU001.outbound.protection.outlook.com (40.93.64.64) by
 DU2PEPF00028CFF.mail.protection.outlook.com (10.167.242.183) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.21.428.7
 via Frontend Transport; Tue, 15 Sep 2026 04:05:40 +0000
```

**B. Authentication and source-attribution headers added by Microsoft (delivery and upstream hops, header order)**

```
Authentication-Results: spf=pass (sender IP is 40.93.64.64)
 smtp.mailfrom=microsoft.com; dkim=pass (signature was verified)
 header.d=800sat.onmicrosoft.com;dmarc=pass action=none
 header.from=microsoft.com;compauth=pass reason=100
Received-SPF: Pass (protection.outlook.com: domain of microsoft.com designates
 40.93.64.64 as permitted sender) receiver=protection.outlook.com;
 client-ip=40.93.64.64; helo=DUZPR08CU001.outbound.protection.outlook.com;
 pr=C
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 2a01:111:f403:c111::20) smtp.rcpttodomain=8hig.org
 smtp.mailfrom=microsoft.com; dmarc=pass (p=reject sp=reject pct=100)
 action=none header.from=microsoft.com; dkim=pass (signature was verified)
 header.d=allnationsuniversity.onmicrosoft.com; arc=pass (0 oda=0 ltdi=1)
X-MS-Exchange-Authentication-Results: spf=fail (sender IP is 38.252.8.155)
 smtp.mailfrom=microsoft.com; dkim=none (message not signed)
 header.d=none;dmarc=fail action=oreject header.from=microsoft.com;
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=91c63d2b-8dec-44db-ac0a-88b943aa465c;Ip=[38.252.8.155];Helo=[anugh.meegaeth.com]
```

**C. MIME parts and link extraction (parts listing; list-links.py, anchor text and URL shortened, URL defanged; `<form>`/`<area>` search)**

```
0 text/html None None
'Viral video: The fat melting dessert GMA Health Report body { margin: 0; padding: 0; [...] } GMA | Health "My doctor couldn\'t believe it": The simple gelatin trick melting belly fat (ABC) [...] See The Gelatin Trick » ABC News · 47 West 66th Street, New York, NY 10023' -> hxxps://na01.safelinks.protection.outlook[.]com/?url=https%3A%2F%2Fb2yx9l-gma-health.posirjdating.site%2Fc%2F[...]&data=[...]&sdata=[...]&reserved=0
[]
```

**D. Tool results summary**

| Tool | Result | Assessment |
|---|---|---|
| Google Admin Toolbox Messageheader | SPF and DKIM pass with IP and domain "Unknown"; DMARC pass; delivered after 63 sec; 2 hop rows | IP and domain not extracted; hop table misses the trust-boundary hop and the DB8PR04CA0010 to DS0PR12MB9347 hop; upstream failure not evaluated |
| MXToolbox Analyze Headers | 4 hops, all not blacklisted; DMARC compliant; DKIM alignment and DKIM body hash failed | Hop order and times correct; body hash failure caused by headers-only input; alignment failure genuine (d=800sat.onmicrosoft.com); upstream failure not evaluated |
| MXToolbox DNS lookups, 2026-10-05 | microsoft.com DMARC p=reject; SPF pass for 40.93.64.64; DKIM key for selector1-800sat-onmicrosoft-com published (2048-bit) | Current records consistent with the delivery-time results |
| ARIN whois and Team Cymru | 40.93.64.64: Microsoft (MSFT), AS8075; 38.252.8.155: Newline Hosting (NHL-158), 38.252.8.0/24 reallocated 2026-02-24, AS40156 | Final hop is shared Microsoft infrastructure; upstream source is a recently registered hosting network |
| urlscan.io, 2026-10-05 19:39:00 UTC, private | 2 HTTP redirects to www[.]skyresistserver[.]com (109.73.73.228, AS20860); final HTTP 204, empty body; no screenshot; no classification | Destination served nothing to the scanner; a clean result does not show it is safe |
| VirusTotal URL, 2026-10-05 19:42:29 UTC | 0/92; Forcepoint ThreatSeeker "newly registered websites"; status 204; first submission | URL submitted rather than looked up, so the full URL is now in VirusTotal's corpus; its redirection panel is inconsistent with its network requests |

**E. Links**

One Safe Links-wrapped link to hxxps://b2yx9l-gma-health[.]posirjdating[.]site/c/[...]; urlscan.io result `https://urlscan.io/result/.../` "(private scan, not publicly viewable)" (no screenshot captured; the final response was HTTP 204 with an empty body).