---
title: Day 03 - OSINT
desc: Day 3 covers topics related to OSINT.
---
## Introduction

!!! note
    OSINT is gathering and analysing publicly available data for intelligence purposes, which includes information collected from the internet, mass media, specialist journals and research, photos, and geospatial information. The information can be accessed via the open internet (indexed by search engines), closed forums (not indexed by search engines) and even the deep and dark web. People tend to leave much information on the internet that is publicly available and later on results in impersonation, identity theft etc.

## OSINT Techniques

### Google Dorks
Following are the most commonly used Google dorks:

- inurl: Searches for a specified text in all indexed URLs. For example, `inurl:hacking` will fetch all URLs containing the word "hacking".

- filetype: Searches for specified file extensions. For example, `filetype:pdf "hacking"` will bring all pdf files containing the word "hacking". 

- site: Searches all the indexed URLs for the specified domain. For example, `site:tryhackme.com` will bring all the indexed URLs from  tryhackme.com.

- cache: Get the latest cached version by the Google search engine. For example, `cache:tryhackme.com`.

!!! tip
    See also: [Google Dork Cheatsheet](https://sansorg.egnyte.com/dl/f4TCYNMgN6) by SANS Institute

### WHOIS Lookup
WHOIS database stores public domain information in a centralised database. The database is publicly available and enables acquiring Personal Identifiable Information (PII) against a company.

Registrars do offer `Domain Privacy` options that allow users to keep their WHOIS information private from the general public and only accessible to certain entities like designated registrars. 

### Robots.txt
A `robots.txt` file tells search engine crawlers which URLs the crawler can access on a site. All websites have their `robots.txt` file directly accessible through the domain's main URL (ie. `www.example.com/robots.txt`).

### Breached Database Search
Databases such as `https://haveibeenpwned.com/` allow search of leaked databases often containing PII like usernames, passwords, addresses, phone numbers, and other identifiable private information regarding individuals. These databases enable successful password spraying due to tendencies of individuals to re-use passwords.

## CTF Questions

Successfully found GitHub repo [SantaGiftShop](https://github.com/muhammadthm/SantaGiftShop).

The flag ``{THM_OSINT_WORKS}` is located under the `config.php` file which also contains answers to the rest of the questions.