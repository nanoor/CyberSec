---
title: Day 06 - Email Analysis
desc: >-
  Day 6 covers topics related to analysis of and security concerns with email
  and email header section and touches on concepts of phishing emails.
---
## Introduction

Email analysis is defined as the process of extracting email headers to expose the email file details. The header contains pertinent information such as the sender, receiver, path, return address, and attachments.

Two main concerns related to email analysis are as follows:

- *Security Issues* - Identifying suspicious/abnormal/malicious patterns in emails.
- *Performance Issues* - Identifying delivery and delay issues in email.

## Email Header Analysis

The following table highlights email header structure.

| Field                          | Detail                                                                                                                                   |
|:------------------------------ |:---------------------------------------------------------------------------------------------------------------------------------------- |
| From                           | The sender's address.                                                                                                                    |
| To                             | The recipient's address, including CC and BCC.                                                                                           |
| Date                           | Timestamp of when the email was sent.                                                                                                    |
| Subject                        | The subject of the email.                                                                                                                |
| Return Path                    | The return address of the reply.                                                                                                         |
| Domain Key and DKIM Signatures | Email signatures provided by email services to identify and authenticate emails.                                                         |
| SPF                            | Shows the server used to send the email (useful to help understand if the actual server is used to send the email from specific domain). |
| Message-ID                     | Unique ID of the email.                                                                                                                  |
| MIME-Version                   | Used Multipurpose Internet Mail Extensions version (usefull for understanding the delivered "non-text" contents and attachments).        |
| X-Headers                      | The recipient's mail provider usually add these fields (information is typically experimental and varies according to mail provider).    |
| X-Received                     | Mail servers that the email went through.                                                                                                |
| X-Spam Status                  | Spam score of the email.                                                                                                                 |
| X-Mailer                       | Email client name.                                                                                                                       |

<br>A simple process of email analysis is show below.

| Questions to ask/required checks                              | Evaluation                                                                                                     |
|:------------------------------------------------------------- |:-------------------------------------------------------------------------------------------------------------- |
| Do the "From", "To", and "CC" fields contain valid addresses? | Invalid addresses are a red flag.                                                                              |
| Are the "From and "To" fields the same?                       | Same value in sender and recipient fields are a red flag.                                                      |
| Are the "From" and "Return-Path" fields the same?             | Different values in these fields is a red flag.                                                                |
| Was the email sent from the correct server?                   | Emails from non-official mail servers are a red flag.                                                          |
| Does the "Message-ID" field exist and is it valid?            | Empty and malformed values are red flags.                                                                      |
| Do the hyperlinks redirect to suspicious/abnormal sites?      | Suspicious links and redirections are red flags.                                                               |
| Do the attachments consist of or contain malware?             | Suspicious attachments are a red flag. File hashes marked as suspicious/malicious by sandboxes are a red flag. |

### OSINT Tools
<br>OSINT tools can be used to check email reputation check on sender email addresses. Following tools are commonly employed during email/attachment analysis.

| Tool                                                                    | Purpose                                                                                                                |
|:----------------------------------------------------------------------- |:---------------------------------------------------------------------------------------------------------------------- |
| [emailrep.io](https://emailrep.io/)                                     | A simple email reputation checker.                                                                                     |
| [VirusTotal](https://www.virustotal.com/gui/)                           | A service that provides a cloud-based detection toolset and sandbox environment.                                       |
| [InQuest](https://labs.inquest.net/)                                    | A service that provides network and file analysis by using threat analytics.                                           |
| [ipinfo.io](https://ipinfo.io/)                                         | A service that provides detailed information about an IP address by focusing on geolocation data and service provider. |
| [Talos Reputation](https://www.talosintelligence.com/reputation_center) | An IP reputation check service provided by Cisco Talos.                                                                |
| [urlscan.io](https://urlscan.io/)                                       | A service that analyses websites by simulating regular user behaviour.                                                 |
| [Browserling](https://www.browserling.com/)                             | A browser sandbox used to test suspicious/malicious links.                                                             |
| [Wannabrowser](https://www.wannabrowser.net/)                           | A browser sandbox used to test suspicious/malicious links.                                                             |

## CTF Questions

Analyze the `.eml` file `Urgent:.eml` using `SublimeText` on the THM `AttackBox`.

The base64-decoded value of Message-ID field can be found using following command:

```text
┌──(siachen㉿kali)-[~]
└─$ echo QW9DMjAyMl9FbWFpbF9BbmFseXNpcw== | base64 -d
AoC2022_Email_Analysis
```

`emlAnalyzer` can be used to extract the attachment from `Urgent:.eml`.

```text
ubuntu@ip-10-10-164-34:~/Desktop$ emlAnalyzer --extract-all -i Urgent\:.eml 
 =================
 ||  Structure  ||
 =================
|- multipart/mixed                       
|  |- multipart/related                  
|  |  |- text/html                       
|  |- application/msword                   [Division_of_labour-Load_share_plan.doc]

 =========================
 ||  URLs in HTML part  ||
 =========================
[+] No URLs found in the html

 ===============================================
 ||  Reloaded Content (aka. Tracking Pixels)  ||
 ===============================================
[+] No content found which will be reloaded from external resources

 ===================
 ||  Attachments  ||
 ===================
[1] Division_of_labour-Load_share_plan.doc        application/msword        attachment

 =============================
 ||  Attachment Extracting  ||
 =============================
[+] Attachment [1] "Division_of_labour-Load_share_plan.doc" extracted to eml_attachments/Division_of_labour-Load_share_plan.doc
```

Sha256 hash sum can be found for the extracted attachment using:

```text
ubuntu@ip-10-10-164-34:~/Desktop/eml_attachments$ sha256sum Division_of_labour-Load_share_plan.doc 
0827bb9a2e7c0628b82256759f0f888ca1abd6a2d903acdb8e44aca6a1a03467  Division_of_labour-Load_share_plan.doc
```

[VirusTotal](https://www.virustotal.com/gui/file/0827bb9a2e7c0628b82256759f0f888ca1abd6a2d903acdb8e44aca6a1a03467/behavior) analysis.

[InQuest](https://labs.inquest.net/dfi/sha256/0827bb9a2e7c0628b82256759f0f888ca1abd6a2d903acdb8e44aca6a1a03467) analysis.