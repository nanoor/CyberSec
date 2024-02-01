---
title: Day 01 - Frameworks
desc: Day 1 covers concepts of cybersecurity frameworks.
---
## Introduction

!!! note
    Security frameworks are documented processes that define policies and procedures organisations should follow to establish and manage security controls. They are blueprints for identifying and managing the risks they may face and the weaknesses in place that may lead to an attack.

    Frameworks help organisations remove the guesswork of securing their data and infrastructure by establishing processes and structures in a strategic plan. This will also help them achieve commercial and government regulatory requirements.

Topics covered include [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) (CSF), ISO 27000 Series, [MITRE ATT&CK Framework](https://attack.mitre.org/), [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html), and Unified Kill Chain.

Unified Kill Chain can be described as a unification of the MITRE ATT&CK and Cyber Kill Chain frameworks and describes 18 phases of attack based on Tactics, Techniques, and Procedures (TTPs).  The individual phases can be combined to form overarching goals, such as gaining an initial foothold in a targeted network, navigating through the network to expand access, and performing actions on critical assets.

The phases of Unified Kill Chain are represented as follows (copied from [Advent of Cyber 2022](https://tryhackme.com/room/adventofcyber4)):

## CYCLE 1: In

The main focus of this series of phases is for an attacker to gain access to a system or networked environment. Typically, cyber-attacks are initiated by an external attacker. The critical steps they would follow are: 

- *Reconnaissance*: The attacker performs research on the target using publicly available information (OSINT).

- *Weaponisation*: The attacker sets up the necessary infrastructure to host the command and control centre (C2).

- *Delivery*: The attacker delivers payloads to the target through numerous means, such as email phishing and supply chain attacks.

- *Social Engineering*: The attacker tricks their target into performing untrusted and unsafe action against the payload they just delivered, often making their message appear to come from a trusted in-house source.

- *Exploitation*: The attacker abuses an existing vulnerability on the targets network infrastructure to trigger their payload.

- *Persistence*: The attacker leaves behind a fallback presence on the network or asset to make sure they have a point of access to their target.

- *Defence Evasion*: The attacker attempts to gain anonymity by disabling and avoiding any security defence mechanisms, including deleting evidence of their presence.

- *Command & Control*: A communication channel between the compromised system and the attacker’s infrastructure is established across the internet.

## CYCLE 2: Through

Under this phase, attackers will be interested in gaining more access and privileges to assets within the network.

The attacker may repeat this phase until the desired access is obtained.

- *Discovery*: The attacker will seek to gather as much information about the compromised system, such as available users and data. Alternatively, they may remotely discover vulnerabilities and assets within the network. This opens the way for the next phase.

- *Privilege Escalation*: Restricted access prevents the attacker from executing their mission. Therefore, they will seek higher privileges on the compromised systems by exploiting identified vulnerabilities or misconfigurations.

- *Execution*: With elevated privileges, malicious code may be downloaded and executed to extract sensitive information or cause further havoc on the system.

- *Credential Access*: Part of the extracted sensitive information would include login credentials stored in the hard disk or memory. This provides the attacker with more firepower for their attacks.

- *Lateral Movement*: Using the extracted credentials, the attacker may move around different systems or data storages within the network, for example, within a single department.

## CYCLE 3: Out

The Confidentiality, Integrity and Availability (CIA) of assets or services are compromised during this phase.

- *Collection*: The attacker will seek to aggregate all the information they need. By doing so, the assets’ confidentiality would be compromised entirely, especially when dealing with trade secrets and financial or personally identifiable information (PII) that is to be secured.

- *Exfiltration*: The attacker extract the aggregated information out of the network. Various techniques may be used to ensure they have achieved their objectives without triggering suspicion.

- *Impact*: When compromising the availability or integrity of an asset or information, the attacker will use all the acquired privileges to manipulate, interrupt, and sabotage. Imagine the reputation, financial, and social damage an organisation would have to recover from.

- *Objectives*: Attackers may have other goals to achieve that may affect the social or technical landscape that their targets operate within. Defining and understanding these objectives tends to help security teams familiarise themselves with adversarial attack tools and conduct risk assessments to defend their assets.