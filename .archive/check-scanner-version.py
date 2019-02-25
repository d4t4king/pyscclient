#!/usr/bin/python3

import re
import json
import pprint
import urllib3
import pyscclient
from bs4 import BeautifulSoup
from termcolor import cprint, colored

def get_tenable_version():
	pp = pprint.PrettyPrinter(indent=4)
	url_address = "https://docs.tenable.com/releasenotes/nessus/"
	page = urllib3.urlopen(url_address)
	soup = BeautifulSoup(page.read(), 'lxml')
	listitems = soup.find_all('li', {'value' : 1})
	#pp.pprint(listitems)
	match = re.search(r'<a href=".*">Nessus\s+([0-9.]+)\s+Release Notes - ([0-9/]+)</a>', str(listitems[0]))
	if match:
		print("Version: {0}, Date Released: {1}".format(match.group(1), match.group(2)))
	else:
		print("Didn't match.")

	cark = 'cark_conf.json'
	with open(cark, 'r') as f:
		cark_conf = json.load(f)
		passwd = pyscclient.Utils.get_cark_creds(cark_conf)
	conn = pyscclient.Connection(cark_conf['schost'], cark_conf['username'], passwd)
	for s in conn.list_scanners():
		print("Name: {0}, Version: {1}".format(s.name, s.version))

def main():
	get_tenable_version()

if __name__=='__main__':
	main()
