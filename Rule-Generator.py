from datetime import date
import uuid
import argparse
import csv
import ipaddress

parser = argparse.ArgumentParser()
parser.add_argument("--input", default= "Risk_Scored_IOCs.csv" , help="Input Risk Scored IOCs.csv")
args = parser.parse_args()

def generate_sigma_rule(ioc, risk):
	rule_id = str(uuid.uuid4())
	today = date.today().isoformat()

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
	return rule

def write_sigma_rule (ioc, rule):

	with open ( f'sigma_rule_{ioc}.yml', 'w') as file:

		file.write (rule)

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
		except ValueError:
			continue #Not an IP, skip for now

		rule = generate_sigma_rule(ioc, risk)
		print(rule)
		write_sigma_rule(ioc, rule)


