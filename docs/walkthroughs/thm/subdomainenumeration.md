---
title: Subdomain Enumeration
desc: 'THM: Learn the various ways of discovering subdomains to expand your attack surface of a target.'
---
## Task 1 - Brief
Subdomain enumeration is a process of finding valid subdomains for a domain. This allows us to expand our attack surface in order to discover more potential points of vulnerabilities.

This room explores three different subdomain enumeration methods:
1. Brute Force
2. OSINT
3. Virtual Host

## Task 2 - OSINT - SSL/TLS Certificates
When a Secure Sockets Layer/Transport Layer Security (SSL/TLS) certificate is created for a domain by a Certificate Authority (CA), CA's take part in what is called *Certificate Transparency (CT)* logs. These are publicly accessible logs of every SSL/TLS certificate created for a domain name. The primary purpose of CT logs is to stop malicious and accidentally made certificates from being used.

We can use CT logs to our advantage to discover subdomains belonging to a domain. The following sites offer a searchable database of certificates that shows current and historical results:
- [Certificate Search](https://crt.sh/)
- [Certificate Transparency Search](https://ui.ctsearch.entrust.com/ui/ctsearchui)

## Task 3 - OSINT - Search Engines
Using advanced search methods on websites like Google (such as `site:filter`) can help find subdomains. For example, a query such as `-site:www.domain.com site:*.domain.com` would only contain results leading to the domain name being searched.

## Task 4 - DNS Brute Force
Brute-force DNS enumeration is a method of trying multitude of different possible subdomains from a pre-defined wordlist of commonly used subdomains. Since this method requires many requests, it is typically automated to make the process quicker. One of tools commonly used for this purpose is *DNSrecon*. The following is a standard syntax for most common use case:

```console
dnsrecon -t brt -d example.com
```
## Task 5 - OSINT - Sublist3r
To speed up the process of OSINT subdomain discovery, the above methods can be automated with a handy utility called [Sublist3r](https://github.com/aboul3la/Sublist3r). *Sublist3r* is a python tool designed to enumerate subdomains of a website using OSINT.

Syntax for common use case is follows:

```console
python3 sublist3r.py -d example.com
```
## Task 6 - Virtual Hosts
Some subdomains are not hosted in publicly accessible DNS results. Examples include development versions of a web application or administrator portals. Instead, the DNS records could be kept on a private DNS server or recorded on the developer's machines in their `/etc/hosts` file (or `C:\windows\system32\drivers\etc\hosts` for Windows OS) which maps domain names to IP addresses.

Because web servers can host multiple websites from one server when a website is requested from a client, the server knows which website the client wants from the *Host* header. We can utilize this host header by making changes to it and monitoring the response to see if we discover a new website.

Like DNS brute-force, we can automate this process using a wordlist of commonly used subdomains and a utility called *ffuf*.

Syntax for a common use case for subdomain enumeration using *ffuf* is as follows:

```console
ffuff -w /usr/share/wordlists/seclists/Discover/DNS/namelists.txt -H "Host:FUZZ.example.com" -u http:www.example.com -fs {size} -v
```
In the above syntax, the parameter `FUZZ` tells *ffuf* which element we want to it to fuzz using the provided wordlist. The `-fs` switch lets us filter our results based on file size (ie: ignore any results that are of the specified size; usually the most common occurring size value).

