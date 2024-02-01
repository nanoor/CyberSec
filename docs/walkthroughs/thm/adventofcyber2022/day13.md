---
title: Day 13 - Packet Analysis
desc: >-
  Day 13 covers topics related to fundamentals of traffic analysis through
  Wireshark.
---
## Introduction

Packets are the most basic unit of the network data transferred over a network. When a message is sent from one host to another, the data is transmitted in small chunks known as packets. Packet analysis is the process of extracting, assessing and identifying network patterns such as connections, shares, commands and other network activitie from captured traffic files.

A packet capture (`PCAP`) of network events provides a rich data soruce for analysis. Capturing live data can be focused on traffice flow, which only provides statistics on the network traffic.

Identifying and investigating network patterns in-depth is done at the packet level and as a result, threat detection and real-time perfornace troubleshooting cannot be done without packet analysis.

There are various points to consider before conducting packet analysis.

| Point                                        | Details                                                                                                                                                                                                                                        |
|:--------------------------------------------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Network and standard protocols knowledge     | Knowledge of network and protocol operations is a must. An analyst must know how the protocols work and which protocol provices particular information that needs to be used for analysis. Knowning "normal" and "abnormal" behaviours is key. |
| Familiarity with attack and defence concepts | An analyst must know how attacks are conducted to identify what is happening and decide where to look. Simply put, you can't detect what you don't know.                                                                                       |
| Practical experience in analysis tools       | An analyst must know how to use the tools to extract particular information from packet bytes.                                                                                                                                                 |

Creating checklists makes the packet analysis process considerably easier. A simple process checklist for practical packet analysis is shown below.

| Required Check    | Details                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:-----------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hypothesis        | The analyst should know what to look for before starting an analysis.                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Packet Statistics | Viewing the packet statistics can show the analyst the weight of the traffic in the capture file. It helps analysts see the big picture in terms of protocols, endpoints and conversations.                                                                                                                                                                                                                                                                                                                                                       |
| Known Services    | The services used in everyday operations like web browsing, file sharing and mailing are called known services. An analyst should know which protocol is associated with which service. Sometimes adversaries use the known services for their benefit, so it is important to know what "normal" traffic looks like.<br><br>**Note:** Service is a capability/application that facilitates network operations between users and applications. The protocol is a set of rules that identify the data processing and transmission over the network. |
| Unknown Services  | Unknown services are potential red flags. Ananalyst should know how to research unknown protocols and services and quickly use them for the sake of the analysis.                                                                                                                                                                                                                                                                                                                                                                                 |
| Known patterns    | Known patterns represent the analyst's knowledge and experience. An analyst should know the most common and recent case patterns to successfully detect the anomalies at first glance.                                                                                                                                                                                                                                                                                                                                                            |
| Environment       | An analyst has to know the nature and dynamics of the working environment. This includes IP address blocks, hostname and username structure, used services, external resources, maintenance schedules, and average traffic load.                                                                                                                                                                                                                                                                                                                  |

## CTF Questions

Open the `.pcap` file in `Wireshark` and navigate to `Statistics --> Protocol Hierarchy`. Percent Packets value for HTTP is `0.3`.

Navigating to `Stastics --> Conversations` and switching to the `TCP` tab shows that port `3389` (associated typically with `RDP`) received more than 1000 packets.

In the main packet view window, apply `DNS` filter to narrow the packet view to just DNS traffic. Click on the packets and expand the `Domain Name System --> Queries` section to show the interacted domains: `bestfestivalcompany[.]thm` and `cdn[.]bandityeti[.]thm`.

Remove the DNS filter and apply `HTTP` filter to narrow the view to just HTTP packets. Looking at the HTTP packets, we can see the names of the two files requested by the client (10[.]10[.]29[.]186): `favicon[.]ico` and `mysterygift[.]exe`. The malicious file was hosted by `cdn[.]bandityeti[.]exe`.

Analyzing the `GET` packet for `favicon[.]ico` file, we can see that the user-agen used to download the file was `Nim httpclient/1.6.8`.

Let's further analyze the files. Export the files using `File --> Export Object --> HTTP` and select `Save All` option. We can calculate the SHA256 sum of `mysterygift[.]exe` and search for more information on `virustotal.com`.

```text
$ sha256 mystergift.exe
0ce160a54d10f8e81448d0360af5c2948ff6a4dbb493fe4be756fc3e2c3f900f
```

On `VirusTotal` under the `Behaviour` section we can see the contacted IP addresses associated with malicious file: `20[.]99[.]133[.]109`, `20[.]99[.]184[.]37` and `23[.]216[.]147[.]76`.