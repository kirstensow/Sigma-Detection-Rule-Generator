# Sigma-Detection-Rule-Generator
Generates Sigma detection rules from risk-scored IOCs, bridging threat intelligence output into detection engineering

# What it does

Takes a CSV of IOCs and their risk scores (output from IOC Enrichment Pipeline) and automatically generates Sigma rule .yml files for high-risk indicators — ready to be deployed to a SIEM.

# How it works

1. Reads Risk_Scored_IOCs.csv (columns: ioc, risk)
2. Filters for HIGH-risk IOCs
3. Validates that the IOC is a valid IP address
4. Generates a Sigma rule matching network connections to that IP
5. Writes each rule as a separate .yml file

# Usage

python rule_generator.py --input Risk_Scored_IOCs.csv

# Example Output

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

# Why it matters

This connects CTI work directly to detection engineering: enrichment pipelines produce risk-scored IOCs, and this tool turns those IOCs into deployable detection logic — the foundation of a Detection-as-Code workflow.


# Current limitations

- Only supports IP-based IOCs. Domains and file hashes are skipped — support for these is planned (see Roadmap below).

# Next steps

- Support additional IOC types (domains, file hashes) with appropriate Sigma logsource categories and fields
- Configurable risk threshold (currently HIGH only)
- Output directory option
- Validate generated rules with pysigma

# Part of a series

- Threat Feed Cleaner
- IOC Enrichment Pipeline
- Threat Report Parser
- Sigma Detection Rule Generator (this repo)








