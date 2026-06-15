# Sigma Detection Rule Generator

Generates [Sigma](https://github.com/SigmaHQ/sigma) detection rules from risk-scored IOCs, bridging threat intelligence output into detection engineering.

## What it does

Takes a CSV of IOCs and their risk scores (output from [IOC Enrichment Pipeline](https://github.com/kirstensow/IOC-Enrichment-Pipeline)) and automatically generates Sigma rule `.yml` files for high-risk indicators — ready to be deployed to a SIEM.

## How it works

1. Reads `Risk_Scored_IOCs.csv` (columns: `ioc`, `risk`)
2. Filters for HIGH-risk IOCs
3. Identifies the IOC type — IP address, file hash, or domain
4. Generates a Sigma rule using the appropriate logsource and detection fields for that type:
    - **IP** → `network_connection` / `DestinationIP`
    - **Hash** → `process_creation` / `Hashes|contains`
    - **Domain** → `dns_query` / `QueryName`
5. Writes each rule as a separate `.yml` file (unrecognized IOC types are skipped)

## Usage

```bash
python rule_generator.py --input Risk_Scored_IOCs.csv
```

## Example output

**IP address:**
```yaml
title: Suspicious connection to 1.1.1.1
id: bddb9b2e-5102-46f5-8f36-a79ad5b1038a
status: experimental
description: Auto-generated rule for 1.1.1.1 flagged as HIGH
date: 2026-06-14
tags:
    - detection.threat-hunting
logsource:
    category: network_connection
detection:
    selection:
        DestinationIP:
            - 1.1.1.1
    condition: selection
level: high
```

**File hash:**
```yaml
logsource:
    category: process_creation
detection:
    selection:
        Hashes|contains:
            - <hash value>
    condition: selection
```

**Domain:**
```yaml
logsource:
    category: dns_query
detection:
    selection:
        QueryName:
            - <domain>
    condition: selection
```

## Why it matters

This connects CTI work directly to detection engineering: enrichment pipelines produce risk-scored IOCs, and this tool turns those IOCs into deployable detection logic — the foundation of a Detection-as-Code workflow.

## Current limitations

- Hash type detection is based on string length (32/64 chars) rather than verifying the algorithm; the generated rule does not prefix the hash with its algorithm (e.g. `SHA256=`).
- Domain validation uses a permissive regex rather than full TLD/format validation.

## Roadmap / Next steps

- Detect and label hash algorithm (MD5/SHA1/SHA256) and prefix accordingly
- Configurable risk threshold (currently HIGH only)
- Output directory option
- Validate generated rules with `pysigma`

## Part of a series

- [Threat Feed Cleaner](https://github.com/kirstensow/threat-feed-cleaner)
- [IOC Enrichment Pipeline](https://github.com/kirstensow/IOC-Enrichment-Pipeline)
- [Threat Report Parser](https://github.com/kirstensow/Threat-Report-Parser)
- **Sigma Detection Rule Generator** (this repo)
