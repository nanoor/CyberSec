---
title: Day 18 - Sigma
desc: Day 18 covers topics related `Sigma` and threat detection.
---
## Introduction

Threat detection involves proactively pursuing and analysing abnormal activity within an ecosystem to identify malicious signs of compromise or intrusion within a network.

## Chopping Logs with Sigma Rules

`Sigma` is an open-source generic signature language to describe log events in a structured format. The format includes using markup language called `YAML` (a designed syntax that allows for quick sharing of detection methods by security analysts). Common factors to note about YAML fields include the following:

- YAML is case-sensitive.
- Files should have the `.yml` extension.
- `Spaces` are sued for indentation and not tabs.
- COmments are attributed using the `#` operator.
- Key-value pairs are denoted using the `:` operator.
- Array elements are denoted using `-` operator.

Log files are usually collected and stored in a database or a `Security Information and Event Management (SIEM)` solution for further analysis. Sigma is vendor-agnostic; therefore, the rules can be converted to a format that fits the target SIEM.

Sigma was developed to satisfy the following scenarios:

- To make detection methods and signatures shareable alongside IOCs and Yara rules.
- To write SIEM searches that avoid vendor lock-in.
- To share signatures with threat intelligence communities.
- To write custom detection rules for malicious behaviour based on specific conditions.

## Sigma Rule Syntax

Sigma rules are guided by a given order of required/optional fields and values that create the structure for mapping needed queries.

Following are examples of and tips on some fields in Sigma ruleset:

- Title: Names the rule based on what it is supposed to detect.
- ID: A globally unique identifier that the developers of Sigma mainly use to maintain the order of identification for the rules submitted to the public repository, found in UUID format.
- Status: Describes the stage in which the rule maturity is at while in use. There are five declared statuses that you can use:
    -  *Stable*: The rule may be used in production environments and dashboards.
    - *Test*: Trials are being done to the rule and could require fine-tuning.
    - *Experimental*: The rule is very generic and is being tested. It could lead to false results, be noisy, and identify exciting events.
    - *Deprecated*: The rule has been replaced and would no longer yield accurate results.
    - *Unsupported*: The rule is not usable in its current state (unique correlation log, homemade fields).
- Description: Provides more context about the rule and its intended purpose. Here, you can be as detailed as possible to provide information about the detected activity.

```yaml
title: Suspicious Local Account Creation
id: 0f06a3a5-6a09-413f-8743-e6cf35561297 
status: experimental
description: Detects the creation of a local user account on a computer.
```

- Logsource: Describes the log data to be used for the detection. It consists of other optional attributes:
    - *Product*: Selects all log outputs of a certain product. Examples are Windows, Apache
    - *Category*: Selects the log files written by the selected product. Examples are firewalls, web, and antivirus.
    - *Service*: Selects only a subset of the logs. Examples are sshd on Linux or Security on Windows.
    - *Definition*: Describes the log source and its applied configurations.

```yaml
logsource:
  product: windows
  service: security
```

- Detection:  A required field in the detection rule describes the parameters of the malicious activity we need an alert for. The parameters are divided into two main parts:
    - The search identifiers are the fields and values the detection should search for. The search identifiers can be enhanced using different modifiers appended to the field name with the pipe character `|`. The main type of modifiers are known as Transformation modifiers and comprise the values: `contains, endswith, startswith, and all`. 
    - The condition expression - sets the action to be taken on the detection, such as selection or filtering. The critical thing to look out for account creation on Windows is the Event ID associated with user accounts. In this case, Event ID: 4720 was provided for us on the IOC list, which will be our search identifier.

```yaml
detection:
  selection:
    EventID:  # This shows the search identifier value
      - 4720    # This shows the search's list value
  condition: selection
```

```yaml
detection:
  selection:
    Image|endswith:
      - '\svchost.exe'
    CommandLine|contains|all: 
      - bash.exe
      - '-c '   
  condition: selection
```

- FalsePositives: A list of known false positives that may occur based on log data.

```yaml
falsepositives: 
    - unknown
level: low
tags:
   - attack.persistence # Points to the MITRE Tactic
   - attack.T1136.001 # Points to the MITRE Technique
```

- Level: Describes the severity with which the security team should take the activity under the written rule. The attribute comprises five levels: Informational -> Low -> Medium -> High -> Critical
- Tags: Adds information that can be used to categorize the rule. Common tags are associated with tactics and techniques from the MITRE ATT&CK framework. 

!!! tip
    Sigma developers have a defined list of [predefined tags](https://github.com/SigmaHQ/sigma/wiki/Tags).

## CTF Questions

### Flag 1

```yaml
title: Suspicious Account Creation
id: 01 # UUID
status: experimental
description: Detects local account creation
author:
date:
modified:

logsource: # Outlines target source of the logs based on operating system, service being run, category of logs.
  product: windows # windows, linux, macos.
  service: security # sshd for Linux, Security for Windows, applocker, sysmon.
  category: # firewall, web, antivirus, process_creation, network_connection, file_access.
detection:
  selection:
    EventID:
      - 4720

  condition: selection # Action to be taken. Can use condition operators such as OR, AND, NOT when using multiple search identifiers.

falsepositives: # Legitimate services or use.
  - unknown

level: low # informational, low, medium, high or critical.

tags: # Associated TTPs from MITRE ATT&CK
  - attack.persistence # MITRE Tactic
  - attack.T1136.001 # MITRE Technique 
```

### Flag 2

```yaml
title: Software Discovery
id: 02 # UUID
status: experimental # experimental, test, stable, deprecated, unsupported.
description: Detect software
author:
date:
modified:

logsource: # Outlines target source of the logs based on operating system, service being run, category of logs.
  product: windows # windows, linux, macos.
  service: sysmon # sshd for Linux, Security for Windows, applocker, sysmon.
  category: process_creation # firewall, web, antivirus, process_creation, network_connection, file_access.
detection:
  selection:
    EventID: 1
    Image|endswith: reg.exe
    CommandLine|contains|all: 
    - reg
    - query
    - /v
    - svcVersion

  condition: selection # Action to be taken. Can use condition operators such as OR, AND, NOT when using multiple search identifiers.

falsepositives: unknown # Legitimate services or use.

level: low # informational, low, medium, high or critical.

tags: # Associated TTPs from MITRE ATT&CK
  - {attack.tactic} # MITRE Tactic
  - {attack.technique} # MITRE Technique 
```

### Flag 3

```yaml
title: Scheduled Task Creation
id: 03 # UUID
status: experimental # experimental, test, stable, deprecated, unsupported.
description: Detect scheduled task creation
author:
date:
modified:

logsource: # Outlines target source of the logs based on operating system, service being run, category of logs.
  product: windows # windows, linux, macos.
  service: sysmon # sshd for Linux, Security for Windows, applocker, sysmon.
  category: process_creation # firewall, web, antivirus, process_creation, network_connection, file_access.
detection:
  selection:
    EventID: 1
    Image|endswith: schtasks.exe
    ParentImage|endswith: cmd.exe
    CommandLine|contains|all:
    - schtasks
    - /create

  condition: selection # Action to be taken. Can use condition operators such as OR, AND, NOT when using multiple search identifiers.

falsepositives: # Legitimate services or use.

level:  # informational, low, medium, high or critical.

tags: # Associated TTPs from MITRE ATT&CK
  - {attack.tactic} # MITRE Tactic
  - {attack.technique} # MITRE Technique 
```