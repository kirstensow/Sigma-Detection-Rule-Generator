from datetime import date
import uuid
import argparse
import csv
import ipaddress
import re

parser = argparse.ArgumentParser()
parser.add_argument("--input", default= "Risk_Scored_IOCs.csv" , help="Input Risk Scored IOCs.csv")
args = parser.parse_args()

hashes = re.compile(r'^([a-fA-F0-9]{32}|[a-fA-F0-9]{64})$')
domains = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

def generate_sigma_rule(ioc, risk, ioc_type):
    rule_id = str(uuid.uuid4())
    today = date.today().isoformat()

    if ioc_type == 'IP address':

        rule= f"""title: Suspicious connection to {ioc}
id: {rule_id}
status: experimental
description: Auto-generated rule for {ioc} flagged as {risk}
date: {today}
tags:
    - detection.threat-hunting
logsource:
    category: network_connection
detection:
    selection:
        DestinationIP:
            - {ioc}
    condition: selection
level: {risk.lower()}
            """
        print(rule)

    elif ioc_type == 'Hash':
        rule= f"""title: Suspicious connection to {ioc}
id: {rule_id}
status: experimental
description: Auto-generated rule for {ioc} flagged as {risk}
date: {today}
tags:
    - detection.threat-hunting
logsource:
    category: process_creation
detection:
    selection:
        Hashes|contains:
            - {ioc}
    condition: selection
level: {risk.lower()}"""

        print(rule)



    elif ioc_type == 'Domain':
        rule= f"""title: Suspicious connection to {ioc}
id: {rule_id}
status: experimental
description: Auto-generated rule for {ioc} flagged as {risk}
date: {today}
tags:
    - detection.threat-hunting
logsource:
    category: dns_query
detection:
    selection:
        QueryName:
            - {ioc}
    condition: selection
level: {risk.lower()}"""

        print(rule)

    else:
        print (f'IOC type: {ioc}')
        rule = None

    return rule

def write_sigma_rule (ioc,rule):
        with open ( f'sigma_rule_{ioc}.yml', 'w') as file:

            file.write(rule)
        print ('Rule exported as .yml')


with open(args.input) as csvfile:
    csvreader = csv.DictReader(csvfile, delimiter=',')
    for row in csvreader:
        ioc = row['ioc']
        risk = row['risk']

        if risk.upper() != "HIGH":
            continue

        try:
            ipaddress.ip_address(ioc)
            ioc_type = 'IP address'
        except ValueError:
            if hashes.match(ioc):
                ioc_type = 'Hash'


            elif domains.match(ioc):
                ioc_type = 'Domain'

            else:
                ioc_type = 'Other'

        rule = generate_sigma_rule(ioc, risk, ioc_type)

        if ioc_type != 'Other':
            write_sigma_rule( ioc, rule)




