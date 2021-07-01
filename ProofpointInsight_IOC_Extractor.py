#This script is to extract IOCs from a Proofpoint Threat Insight Blogpost and write to a csv file. 
#The list of IOCs can be used for threat hunting in your environment. 
#Ex from CLI: ProofpointInsight_IOC_Extractor.py -u 'https://www.proofpoint.com/us/blog/threat-insight/jssloader-recoded-and-reloaded' -f 'jssloader.csv'

import urllib.request, urllib.parse, urllib.error
from bs4 import BeautifulSoup
import ssl
import csv
import argparse


#Handle SSL certification error
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def iocparser (url, filename):
	html = urllib.request.urlopen(url, context=ctx).read().decode('utf-8')
	soup = BeautifulSoup(html, 'html.parser')
	rows = []
	for table in soup.find_all('table'):
		data = table.get_text().split('\n')
		for item in data:
			#Extract threat URL
			if ('\.') in item or ('[.]') in item:
				rows.append(item.strip())
			#Extract threat hash
			elif len(item)==65:
				rows.append(item.strip())

	with open(filename, 'w', encoding='utf-8') as f:
		csv_writer = csv.writer(f)
		csv_writer.writerow(['IOC'])
		for item in rows:
			csv_writer.writerow([item])
			
def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-u', '--url', dest = 'url', type=str)
	parser.add_argument('-f', '--filename', dest ='filename', type=str)

	args = parser.parse_args()
	return iocparser(args.url, args.filename)

if __name__ == '__main__':
	main()