# Case 001 — Callback phishing; fake PayPal purchase order sent to 249 recipients

**Analyst:** Alex Dafoulas

**Date of analysis:** 2026-10-03

## 0. Acquisition and handling

**Source:** Personal Outlook mailbox / 2026-08-19

**Original filename:** email-1.2.eml

**Working filename:** case-001.eml

**Method:** Forwarded as an attachment to an isolated analysis mailbox. The
header block was also copied from Outlook "View message source" and pasted into the message body as a fidelity cross-check.

**Received format:** email-1.2.eml: RFC 822 mail, ASCII text, with very long lines (347)

**Header source of record:** Header block extracted directly from the
received .eml. Pasted copy compared with all whitespace removed:
identical.

**Sample SHA256:** fed733a413beb12320155f9c9031386b0dade22e763580dd42fd3549705405ff

**Attachment.** The parts listing showed five parts: two multipart containers (multipart/related and multipart/alternative), a text/plain and a text/html body, and one inline image at index 4, declared as `image/jpeg` with the filename `pay.jpg` and referenced in the HTML body as `cid:ii_mt082olm0`. The image part was extracted at index 4 of the parser's walk order to a neutral filename, and `file` identified it as JPEG image data (JFIF 1.01, progressive, 906 × 1280, 3 components), matching the declared type. Its SHA256 is `092f7044956da84b175d122dbdefa708475e8e240f202aa7fc10f29275b2c712`, the same value recorded in section 0 and listed in section 6, and the HTML displays it at 356 × 503, a proportional scaling of its actual size. The oletools and PDF tools do not apply to images, and none of the workflow's image tools apply to a JPEG, so `file`, the hash and the VirusTotal lookup are the analysis. A hash search on VirusTotal on 2026-10-03 returned no file match, and the file was not uploaded; no match or zero detections on a first-seen image is weak evidence on its own. The image content was viewed in Outlook before forwarding and shows the PayPal-branded purchase order described under Body and links, so the image is the lure itself rather than a payload.

**Environment:** Ubuntu 26.04 VM; shared folders and clipboard disabled;
static analysis only, no execution

**Known limitations:** DNS records checked on 2026-10-03, not at delivery
on 2026-08-19. 

## 1. Executive summary

On 19 August 2026, an email made to look like a PayPal purchase order was sent from a personal Gmail account to at least 249 recipients at once, asking anyone who had not placed the order to call a phone number. The order is fake: the email is assessed as malicious, a "callback phishing" phone scam designed to get recipients to call the scammers, who commonly try to obtain payment, personal details or remote access to the caller's computer. The email passed the standard checks that confirm where a message came from, because it was genuinely sent from a Gmail account, but those checks cannot show whether a sender is honest, and the email disguised its text with lookalike characters and carried the order as an image, in ways consistent with trying to get past spam filters. The recommended response is to remove the email from all mailboxes, block the sender and, where possible, the phone number, and find out whether anyone called.

## 2. Verdict

**Classification:** Malicious

**Campaign type:** Callback phishing / untargeted bulk distribution

**Confidence:** High

**Basis:** SPF, DKIM and DMARC all pass for gmail.com. This proves the message came from a real Gmail account, not that the sender is legitimate; a free-webmail account sending a purchase order is itself inconsistent with genuine order mail. There are 249 addresses visible in To; inconsistent with a genuine order confirmation and consistent with untargeted bulk distribution. The HTML body part contains one line of text and an inline image (`pay.jpg`) of a purchase order impersonating PayPal for an order the recipient never placed, urging the reader to call +1 805 663 8970 if they did not authorise it. The text line, placed in the message's signature block, says customer care can help with invoice concerns at +1 805 663 8970; its words are written with lookalike characters from other scripts (including Cyrillic and Armenian) while the phone number is in plain digits, a technique that can hide the wording from keyword-based filters while leaving the number readable.

## 3. Email metadata

| Field | Value |
|---|---|
| Subject | (empty) |
| From (display) | zero |
| From (address) | `didzkhadijahyudistira0504@gmail.com` |
| Return-Path | `didzkhadijahyudistira0504@gmail.com` |
| Reply-To | "Not present" |
| To | 249 addresses (list withheld for privacy) |
| Originating IP | 209.85.219.52 |
| Originating ASN / Org | AS15169 (from BGP routing data, bgp.he.net, checked 2026-10-03; ARIN OriginAS empty) / Google LLC |
| Date | Wed, 19 Aug 2026 21:03:20 +0530 |
| Message-ID | `<CAFTwxbX4eBBnF_cdKxGbs9CfZaX7nMWvUDvWWjqqS_CiM5PMiA@mail.gmail.com>` |
| X-Mailer | "Not present" |

## 4. Authentication results

| Check | Result | Interpretation |
|---|---|---|
| SPF | pass | pass for smtp.mailfrom=gmail.com, sender IP 209.85.219.52. Aligned: the envelope domain is exactly the From domain (header.from=gmail.com). |
| DKIM | pass | header.d=gmail.com, selector s=20251104 (from the DKIM-Signature). Aligned: d=gmail.com is exactly the From domain. Only one DKIM-Signature is present. |
| DMARC | pass | action=none. p=none sp=quarantine pct=100. SPF and DKIM both passed and both aligned, so either one alone would have satisfied DMARC. |
| ARC | pass (i=2) | Two instances. i=1, stamped mx.google.com, arc=none: added on Google's side, meaning no ARC chain existed before it. i=2, stamped mx.microsoft.com: added by Microsoft, the receiver, with arc=pass (the i=1 instance validated). The i=2 results agree with Authentication-Results. |
| compauth | pass (reason=100) | reason=100. Microsoft's header reference groups 1xx or 7xx codes as the message passing authentication (compauth=pass). |



## 5. Analysis

**Acquisition.** The message was forwarded as an attachment from new Outlook to an isolated Proton Mail analysis mailbox, where it arrived in Inbox, with the header block from Outlook's View message source pasted into the forwarding message's body as a cross-check. Proton offered only a combined zip of the .eml and its inner attachment, so after a first download the VM was reverted to a clean snapshot and the .eml was downloaded on its own; nothing from the first download was opened. The .eml was hashed before any other handling (SHA256 in section 0); `file` identified it as RFC 822 mail, and a parts listing showed 0 attachments and 1 inline part. The header block extracted from the .eml is the source of record.  The pasted copy differed from it only in whitespace and line breaks (seven Microsoft headers unfolded, trailing spaces removed from the To: header, two continuation lines starting with a tab instead of a space, and a missing final blank line), and the two were byte-identical once spaces, tabs and line breaks were removed. That check cannot detect a change consisting solely of an added or removed space within a value, but none of the changed lines belong to the Received, authentication or DKIM headers, and the evidence is intact.

**Headers.** The message was sent from the personal Gmail address `didzkhadijahyudistira0504[@]gmail[.]com` with the display name "zero", which does not match the name in the address or the company on the purchase-order image; Return-Path is the same address and no Reply-To is present. The To: header lists 249 addresses, nearly all on Microsoft consumer webmail domains and visible to every recipient, which is inconsistent with a genuine purchase confirmation and consistent with an untargeted bulk campaign; Bcc recipients would not appear, so 249 is a minimum. The Message-ID ends in `@mail.gmail.com`, consistent with Gmail; X-Mailer is absent, as are User-Agent and X-MIMEOLE, and the Subject is empty. The Date header (21:03:20 +0530, 15:33:20 UTC) is set on the sending side, so its offset reflects a time zone setting the sender controls, not the sender's location. The passing DKIM signature covers From, To, Subject, Date and Message-ID and also lists the absent Cc and Reply-To, so none of these was altered or added between Gmail signing the message and Microsoft verifying it. These headers therefore arrived as the sender's account submitted them; what is inconsistent is the combination of a personal Gmail account, an unrelated display name and a commercial purchase order sent to 249 recipients.

**Authentication.**  All results come from the Authentication-Results header added by Microsoft, the only one in the message, so no sender-side results had to be excluded. SPF passed for `gmail.com` from 209.85.219.52 and DKIM passed for `d=gmail.com`; both domains exactly match the From domain, so each is aligned and either alone would have satisfied DMARC. DMARC passed with `action=none` under the policy Microsoft recorded for gmail.com (`p=none sp=quarantine pct=100`), and compauth passed with reason 100, in Microsoft's 1xx pass range. ARC instance 1, added by Google, records no earlier chain, and Microsoft's instance 2 records `arc=pass` with results matching Authentication-Results. These results prove the message was sent through Google's servers by whoever controls the account, not that the sender is legitimate: anyone can register a Gmail account, a compromised account passes every check, and the headers cannot tell the two apart. The verdict therefore rests on the content.

**DNS records (checked 2026-10-03).** DNS lookups made on 2026-10-03, 45 days after delivery, show the records as they are now; Microsoft's results recorded at delivery remain the evidence for that date, and every lookup concerned Google's own domains and addresses. `gmail.com`'s SPF record redirects to `_spf.google.com`, which lists `ip4:209.85.128.0/17`, covering 209.85.219.52 and matching the block ARIN shows allocated to Google LLC, and ends in `~all`. `_dmarc.gmail.com` publishes `p=none; sp=quarantine` with no `pct` tag, so the default of 100 applies and the record matches the policy Microsoft recorded at delivery; with no `adkim` or `aspf` tag, relaxed alignment applies. Selector `20251104` still publishes an RSA public key, but the signature carried an expiry (`x=`) of 2026-08-26, seven days after signing, so a verifier honouring that expiry would reject it today for a reason unrelated to the message. 209.85.219.52 resolves to `mail-qv1-f52.google.com`, which resolves back to the same IP, matching the HELO name in Received-SPF.

**Trust boundary.** The message carries five Received: headers; read bottom to top, the first trustworthy one is where Microsoft's inbound server `DS2PEPF000061C7.mail.protection.outlook.com` records a TLS 1.3 connection from `mail-qv1-f52.google.com` (209.85.219.52) at 15:33:33 UTC. That IP matches `client-ip=` in Received-SPF and `sender IP is` in Authentication-Results, and falls within 209.85.128.0/17, a direct allocation to Google LLC registered with ARIN in 2006; no CIP value is present. The three Received: headers above it are Microsoft-internal handoffs, one using the loopback address `::1`, ending in delivery at 15:33:39 UTC, and Microsoft's ARC instance 2, Authentication-Results and Received-SPF also sit above it. Below it are Google's own Received: header, which Microsoft cannot verify and which is treated as sender-reported, and Google's ARC instance 1 and DKIM-Signature, which were already in the message on arrival and are relied on only because Microsoft verified them. The headers contain no IP for the sender's own device, so the originating IP identifies Google's outbound server, not the sender's location. Timestamps are consistent throughout: Date header 15:33:20 UTC, DKIM signature and Google's handoff 15:33:33, Microsoft's receipt 15:33:33, delivery 15:33:39.

**Tools.** The headers were run through Google Admin Toolbox Messageheader and MXToolbox on 2026-10-03, and each result was checked against the raw headers. Google Admin Toolbox did not handle Microsoft's format: it reported SPF and DKIM as passing with the IP and domain "Unknown", and its hop table showed three rows instead of the five Received: headers, one of them built from Google's X-Received header and none showing the trust-boundary hop into Microsoft. Its "delivered after 13 sec" ran only to the last hop it parsed (15:33:33 UTC), not to mailbox delivery at 15:33:39. MXToolbox rendered all five hops correctly but flagged two addresses as blacklisted. The loopback address `::1` was listed only on Team Cymru's IPv6 bogon list because it falls in reserved address space (`::/10`), which makes the flag meaningless; Google's shared outbound address 209.85.219.52 was listed on 1 of 60 lists (0SPAM), citing a different message received from that address on 2026-10-01, 43 days after this one was delivered. MXToolbox also reported DKIM as failing, and therefore the message as not DMARC compliant, because only headers were submitted: its expected body hash is the SHA-256 of an empty body, a limitation its own copy/paste warning acknowledges, whereas Microsoft verified the signature on delivery. Its expiry check described the signature as not expired despite the 2026-08-26 expiry date and was disregarded, and its DNS lookups returned the same SPF, DMARC and DKIM records as those made with `dig`. CyberChef was used to decode the base64-encoded HTML body part; its findings are covered under Body and links.

**Body and links.** The HTML part contains no links. The body contains several Base64 encoded blocks. The first Base64 block contains the text "If you have concerns about an invoice, our customer care team can provide assistance at +1 805 663 8970". Below the text is an image bearing the PayPal logo indicating an order was confirmed for 2 iPhones indicating that the receiver paid $1,347.84 USD from their PayPal account. There is a banner at the bottom of the image titled "Security Notice" pressing the recipient of the email to call the same number listed above if the recipient did not make the purchase.

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

**Conclusion.** The message is assessed as malicious: a callback phishing attempt designed to get recipients to phone the number it supplies. Every authentication check passed and the DKIM-signed headers were unaltered in transit; this shows the message was sent through Google's servers from a personal Gmail account, not that the sender is legitimate. The evidence of intent lies in the combination of what was sent and how: a purchase order impersonating PayPal for an order the recipient never placed, sent with an empty subject to 249 visible recipients from an account whose display name does not match its address. The message also uses two techniques consistent with an attempt to evade content filtering: the order is carried as an image, and the text in its HTML part is written with lookalike characters from other scripts while the phone number is left in plain digits. No links were found, and the only attachment is the inline image `pay.jpg`. The indicators worth acting on are the sender address, the phone number +1 805 663 8970, and the image's SHA256; the originating IP belongs to Google's shared mail infrastructure and is not one. Confidence is High, as every part shown in the parts listing was examined.

## 6. Indicators of compromise

| Type | Value (defanged) | Context |
|---|---|---|
| Email address | `didzkhadijahyudistira0504[@]gmail[.]com` | Sender (From and Return-Path). Personal Gmail account; whether attacker-created or compromised cannot be determined from the headers. |
| Phone number | `+1 805 663 8970` | Callback number in the HTML body text. Same number shown in the image |
| SHA256 | `092f7044956da84b175d122dbdefa708475e8e240f202aa7fc10f29275b2c712` | Inline image `pay.jpg` carrying the fake purchase order. |

Observables, not IOCs:

| Type | Value (defanged) | Context |
|---|---|---|
| IP address | `209.85.219[.]52` | Google outbound mail server (`mail-qv1-f52.google[.]com`), shared by many Gmail users. Listed on 1 of 60 blocklists (0SPAM), citing a different message received from that address on 2026-10-01. Do not block. |
| Message-ID | `<CAFTwxbX4eBBnF_cdKxGbs9CfZaX7nMWvUDvWWjqqS_CiM5PMiA@mail.gmail.com>` | Unique to this message; use as a search key when scoping, not for blocking. Not defanged, because it is an identifier rather than an address, and a defanged value would not match in a log search. |

## 7. MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access (TA0001) | Phishing | T1566 |

The email is non-targeted phishing: one message sent to 249 visible recipients, directing them to phone a number rather than delivering a link or malicious file. ATT&CK's Phishing technique covers non-targeted campaigns and messages that instruct victims to call a phone number. The closest sub-technique, Spearphishing Voice (T1566.004), is not used because ATT&CK defines it as a variant of spearphishing, which this message is not. No post-delivery activity was observed, so no later-stage techniques are mapped. Whether the sending account was created for the campaign (T1585.002) or compromised (T1586.002) cannot be determined from the headers, so neither is mapped.

## 8. Recommended actions

**Contain:** Purge the message from every internal mailbox, matching on the sender address and Message-ID. Block the sender address at the mail gateway. Do not block `gmail[.]com` or `209.85.219[.]52`: both serve many unrelated senders. Where the telephony platform allows it, block outbound calls to +1 805 663 8970 from corporate phones.
**Scope:** Search mail logs for messages from the sender address, with this Message-ID, or containing the phone number or the image hash, and list every internal recipient. Check corporate call records for calls to the number, and ask recipients directly whether anyone called it.

**Eradicate:** For anyone who called, check their device for remote-access software installed during or after the call and remove it, reimaging if its use cannot be ruled out. If payment details were given, contact the card issuer or bank. If credentials or MFA codes were disclosed, reset the password, revoke active sessions and review registered MFA methods.

**Intelligence:** Add the sender address, phone number and image hash to the blocklist and threat intelligence platform. Report the Gmail account to Google through `https://www.google.com/contact/`, the abuse contact in the ARIN record for the sending network.

## 9. Detection opportunity
Authentication and reputation controls had nothing to catch here. SPF, DKIM and DMARC passed for gmail.com, the connecting IP belongs to Google's shared outbound mail servers, there was no URL to check, and Microsoft scored the message SCL 1. A keyword rule like case-002's would also miss it, because the subject is empty, the purchase-order wording is inside the image, and the only lure word in the HTML body text, "invoice", is itself written in lookalike characters, so this rule targets the disguise and the mass mailing instead:

```text
Rule: Free-mail mass callback lure with mixed-script text
Match when all of these are true:
  1. From domain is a consumer free-mail domain (gmail.com, outlook.com, yahoo.com, ...)
  2. To and Cc together hold at least 50 addresses
  3. Body text contains a North American phone number:
       (?<!\d)(?:\+?1[\s.\-]?)?\(?[2-9]\d{2}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)
  4. Visible body text contains a word whose letters come from more than one
     Unicode script (for example Latin mixed with Cyrillic, Greek or Armenian)
Tuning, to separate disguised text from occasional stylised words:
  5. Require at least 3 mixed-script words
Action: warning banner or quarantine for review, not reject
```

This message meets all five conditions: a gmail.com sender, 249 addresses in To, "+1 805 663 8970" in the body text, and at least five mixed-script words. "About" and "concerns" combine Latin letters with Cyrillic and Armenian lookalikes, and "you" and "have" contain no Latin letters at all, mixing Cyrillic with Armenian and Greek. If the gateway can run OCR on images, adding a purchase-order or invoice term found in the image text would make the rule more precise, and it would also capture any number that appears only in the image.

False positives: The main cost is legitimate group mail from free-mail accounts, such as clubs, schools and family announcements, which often lists recipients in To rather than Bcc and has a phone number in the signature; that meets conditions 1 to 3 on its own, so the mixed-script conditions carry most of the rule's precision. Those can still be met by mail that repeats a stylised brand or product name using letters from another script, or by text pasted from sources that substitute lookalike characters. The phone pattern also matches order or account numbers that happen to look like phone numbers. Because legitimate mail of this shape exists, the rule should warn or queue for review rather than block, and its thresholds should be measured on a sample of your own mail before they are fixed. In the other direction, the same campaign sent with recipients in Bcc would not meet condition 2.

## 10. Appendix

**A. Received chain (newest first, recipient redacted)**

```
Received: from DS7PR12MB5765.namprd12.prod.outlook.com (::1) by
 MW4PR12MB7238.namprd12.prod.outlook.com with HTTPS; Wed, 19 Aug 2026 15:33:39
 +0000
Received: from DS1P222CA0016.NAMP222.PROD.OUTLOOK.COM (2603:10b6:8:44b::12) by
 DS7PR12MB5765.namprd12.prod.outlook.com (2603:10b6:8:74::19) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.21.292.19; Wed, 19 Aug 2026 15:33:33 +0000
Received: from DS2PEPF000061C7.namprd02.prod.outlook.com
 (2603:10b6:8:44b:cafe::40) by DS1P222CA0016.outlook.office365.com
 (2603:10b6:8:44b::12) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.21.339.8 via Frontend Transport; Wed, 19
 Aug 2026 15:33:33 +0000
Received: from mail-qv1-f52.google.com (209.85.219.52) by
 DS2PEPF000061C7.mail.protection.outlook.com (10.167.23.74) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.21.339.3
 via Frontend Transport; Wed, 19 Aug 2026 15:33:33 +0000
Received: by mail-qv1-f52.google.com with SMTP id 6a1803df08f44-8f1a8e914a9so11411676d6.1
        for <[REDACTED-RECIPIENT]>; Wed, 19 Aug 2026 08:33:33 -0700 (PDT)
```

**B. Authentication headers added by Microsoft**

```
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 209.85.219.52) [REDACTED] smtp.mailfrom=gmail.com; dmarc=pass
 (p=none sp=quarantine pct=100) action=none header.from=gmail.com; dkim=pass
 (signature was verified) header.d=gmail.com; arc=pass (0 oda=0 ltdi=1)
Authentication-Results: spf=pass (sender IP is 209.85.219.52)
 smtp.mailfrom=gmail.com; dkim=pass (signature was verified)
 header.d=gmail.com;dmarc=pass action=none header.from=gmail.com;compauth=pass
 reason=100
Received-SPF: Pass (protection.outlook.com: domain of gmail.com designates
 209.85.219.52 as permitted sender) receiver=protection.outlook.com;
 client-ip=209.85.219.52; helo=mail-qv1-f52.google.com; pr=C
```

**C. Decoded HTML body part (CyberChef, From Base64)**

```
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"><div dir="ltr"><div dir="ltr"><div><br clear="all"></div><div><br></div><span class="gmail_signature_prefix">-- </span><br><div dir="ltr" class="gmail_signature" data-smartmail="gmail_signature"><div dir="ltr">&nbsp;ꓲf уоս һаνе соոсеrոѕ аbоսt аո іոνоісе, оսr сսѕtоmеr саrе tеаm саո рrоνіdе аѕѕіѕtаոсе аt +1 805 663 8970.<br></div><img src="cid:ii_mt082olm0" alt="pay.jpg" width="356" height="503"><br></div></div>
</div>
```

**D. Tool results summary**

| Tool | Result | Assessment |
|---|---|---|
| Google Admin Toolbox Messageheader | SPF and DKIM pass with IP and domain "Unknown"; 3 hop rows | Did not parse Microsoft's format; hop table incomplete |
| MXToolbox Analyze Headers | 5 hops; DKIM body hash failed; signature "not expired" | Hops correct; DKIM failure caused by headers-only input; expiry check wrong |
| MXToolbox blacklist, 209.85.219.52 | Listed on 0SPAM (1 of 60) | Shared Google address; listing cites a different message on 2026-10-01 |
| MXToolbox blacklist, `::1` | Listed on CYMRU BOGONS IPv6 (`::/10`) | Loopback address in reserved space; meaningless |

**E. Links**

[No URLs found in the message; urlscan not applicable.]
