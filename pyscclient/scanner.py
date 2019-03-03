#!/usr/bin/end python

import json
import time
import pprint
import datetime
import subprocess
from termcolor import colored, cprint
from securitycenter import SecurityCenter5

class Scanner(object):
	def __init__(self, _id, _name, descr, **args):
		self.id = _id
		self.name = _name
		self.description = descr
		self.status = ''
		# handle extra args in here somewhere
		# instantiate some default values
		self.ip = ''
		self.port = ''
		self.useProxy = False
		self.enabled = True
		self.verifyHost = False
		self.managePlugins = True
		self.authType = ''
		self.cert = ''
		self.username = ''
		self.password = ''
		self.agentCapable = False
		self.version = 0
		self.webVersion = 0
		self.admin = ''
		self.msp = ''
		self.numScans = 0
		self.numTCPSessions = 0
		self.loadAvg = 0
		self.uptime = 0
		self.pluginSet = ''
		self.loadedPluginSet = ''
		self.serverUUID = ''
		self.createdTime = ''
		self.modifiedTime = ''
		self.zones = []					# a list of Zones (scan zones) associated with the scanner
		self.nessusManagerOrgs = []		# not sure if this should be an array just yet.

	def __repr__(self):
		my_str = "id:%s; name:%s; status:%s; ip:%s; port:%s; \
enabled:%s; agentCapable:%s; version:%s; webVersion:%s; \
uptime:%s; loadedPluginSet:%s; createdTime:%s; zoneCount:%s;" % \
			(self.id, self.name, self.status, self.ip, self.port, \
				self.enabled, \
				self.agentCapable, self.version, self.webVersion, \
				self.uptime, self.loadedPluginSet, self.createdTime, \
				len(self.zones))
		return my_str

	@staticmethod
	def load(sc, scanner_id):
		# load the scanner info from the console
		# fields = ["id", "name", "description", "status", \
		#	"ip", "port", "useProxy", "enabled", "verifyHost", \
		#	"managePlugins", "authType", "cert", "username", \
		#	"password", "agentCapable", "version"]
		pp = pprint.PrettyPrinter(indent=4)
		resp = sc.get('scanner', params={"id":scanner_id})
		scn = Scanner(scanner_id, resp.json()['response']['name'], \
						resp.json()['response']['description'])
		scn.status = resp.json()['response']['status']
		scn.ip = resp.json()['response']['ip']
		if resp.json()['response']['port'] is not None:
			scn.port = int(resp.json()['response']['port'])
		scn.useProxy = resp.json()['response']['useProxy']
		scn.enabled = resp.json()['response']['enabled']
		scn.verifyHost = resp.json()['response']['verifyHost']
		scn.managePlugins = resp.json()['response']['managePlugins']
		scn.authType = resp.json()['response']['authType']
		scn.cert = resp.json()['response']['cert']
		scn.username = resp.json()['response']['username']
		scn.password = resp.json()['response']['password']
		scn.agentCapable = resp.json()['response']['agentCapable']
		scn.version = resp.json()['response']['version']
		scn.webVersion = resp.json()['response']['webVersion']
		scn.admin = resp.json()['response']['admin']
		scn.msp = resp.json()['response']['msp']
		if resp.json()['response']['numScans'] is not None:
			scn.numScans = int(resp.json()['response']['numScans'])
		if resp.json()['response']['numHosts'] is not None:
			scn.numHosts = int(resp.json()['response']['numHosts'])
		if resp.json()['response']['numSessions'] is not None:
			scn.numSessions = int(resp.json()['response']['numSessions'])
		if resp.json()['response']['numTCPSessions'] is not None:
			scn.numTCPSessions = int(resp.json()['response']['numTCPSessions'])
		if resp.json()['response']['loadAvg'] is not None:
			scn.loadAvg = float(resp.json()['response']['loadAvg'])
		if resp.json()['response']['uptime'] is not None:
			scn.uptime = int(resp.json()['response']['uptime'])
		scn.pluginSet = resp.json()['response']['pluginSet']
		scn.loadedPluginSet = resp.json()['response']['loadedPluginSet']
		scn.serverUUID = resp.json()['response']['serverUUID']
		if resp.json()['response']['createdTime'] is not None:
			scn.createdTime = int(resp.json()['response']['createdTime'])
		if resp.json()['response']['modifiedTime'] is not None:
			scn.modifiedTime = int(resp.json()['response']['modifiedTime'])
		for ele in resp.json()['response']['zones']:
			z = Zone.load(sc, ele['id'])
			scn.zones.append(z)
		#scn.zones = resp.json()['response']['zones']
		scn.nessusManagerOrgs = resp.json()['response']['nessusManagerOrgs']
		#print colored("=", "red") * 65
		#print("ID: {0}, Name: {1}, Desc: {2}, Status: {3}".format( \
		#	colored(scn.id, "green"), colored(scn.name, "green"), \
		#	colored(scn.description, "green"), colored(scn.status, "green")))
		#print colored("=", "red") * 65
		return scn

	def save(self, sc):
		# save the Scanner object to the console
		# this can be a new scanner object, or a modified, existing one
		pass
