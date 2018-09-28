#!/usr/bin/env python

#######################################################################
#	pyscclient
#
#	This module is a wrapper for SteveMcGrath's pySecurityCenter.
#	It is intended to abstract the API one layer further, objectifying
#	most of the objects available in the API
#
#######################################################################
#	THIS SCRIPT USES TABS
#######################################################################
#	INDEX
#######################################################################
#	Connection Object: (line) 	47
#	Asset:						439
#	Organization:				367
#	Scanner:					208
#	Zone:						321
#	Repository:					473
#	PluginFamily:				530
#	Plugin:						660
#	Scan						662
#######################################################################

import json
import time
import pprint
import datetime
import subprocess
#import securitycenter
from termcolor import colored, cprint
from securitycenter import SecurityCenter5
#import securitycenter

__name__ = "pyscclient"
__version__ = '0.1'

class APIError(Exception):
	def __init__(self, code, msg):
		self.code = code
		self.message = msg

	def __str__(self):
		return repr('[%s]: %s' % (self.code, self.message))

class Connection(object):
	def __init__(self, host, user, passwd):
		self.host = host
		self.user = user
		self.passwd = passwd
		self.sc = SecurityCenter5(self.host)
		self.sc.login(self.user, self.passwd)

	def getStatus(self, verbose=False):
		"""
			Gets a collection of status information, including license.
		"""
		response = self.sc.get('status')
		rh = response.json()['response']
		if verbose:
			print("""
jobd:					%s
licenseStatus:				%s
PluginSubscriptionStatus:		%s
LCEPluginSubscriptionStatus:		%s
PassivePluginSubscriptionStatus:	%s """ % (rh['jobd'], \
						rh['licenseStatus'], rh['PluginSubscriptionStatus'], \
						rh['LCEPluginSubscriptionStatus'], \
						rh['PassivePluginSubscriptionStatus']))
			print("pluginUpdates:")
			for k in rh['pluginUpdates']:
				print("	{0}: ".format(k))
				for e in rh['pluginUpdates'][k]:
					print("		{0}: {1}".format(e, rh['pluginUpdates'][k][e]))
			print("feedUpdates:")
			for k in rh['feedUpdates']:
				print("	{0}: {1}".format(k, rh['feedUpdates'][k]))
			print("""
activeIPs:				%s
licensedIPs				%s """ % (rh['activeIPs'], rh['licensedIPs']))
		else:
			print("""
jobd:		%s
licenseStatus:	%s
activeIPs:	%s
licensedIPs:	%s """ % (rh['jobd'], rh['licenseStatus'], \
				rh['activeIPs'], rh['licensedIPs']))


	def list_scanners(self):
		"""
			Iterable list of scanners.
			This is where my lack f python experience comes in....
			maybe an array is just as iterable as this generator?
		"""
		pp = pprint.PrettyPrinter(indent=4)
		fields = ["id"]
		response = self.sc.get('scanner', params={"fields": ",".join(fields)})
		for _id in response.json()['response']:
			scn = Scanner.load(self.sc, _id['id'])
			yield scn

	def scanners(self):
		"""
			This is mainly a test to see about iterating lists
			over generators.
		"""
		pp = pprint.PrettyPrinter(indent=4)
		fields = ['id']
		response = self.sc.get('scanner', params={'fields': ",".join(fields)})
		scanners = []
		for _id in response.json()['response']:
			scn = Scanner.load(self.sc, _id['id'])
			scanners.append(scn)
		return scanners

	def list_zones(self):
		"""
			Iterable list of scan zones
		"""
		pp = pprint.PrettyPrinter(indent=4)
		fields = ['id']
		response = self.sc.get('zone', params={'fields': ",".join(fields)})
		for _id in response.json()['response']:
			zn = Zone.load(self.sc, _id['id'])
			yield zn

	def list_orgs(self):
		"""
			Iterable list of Organizations.
		"""
		pp = pprint.PrettyPrinter(indent=4)
		fields = ['id']
		response = self.sc.get('organization', params={"fields": ",".join(fields)})
		#pp.pprint(response.json())
		for org in response.json()['response']:
			org_obj = Organization.load(self.sc, org['id'])
			yield org_obj

	def list_repositories(self):
		"""
			Iterable list of Repository's.
		"""
		pp = pprint.PrettyPrinter(indent=4)
		fields = ['id']
		response = self.sc.get('repository', params={"fields": ",".join(fields)})
		for repo in response.json()['response']:
			repo_obj = Repository.load(self.sc, repo['id'])
			yield repo_obj

	def plugins(self):
		"""
			Returns a list of all plugins.
			This *should* be iterable.  (Note above comments.)
		"""
		pp = pprint.PrettyPrinter(indent=4)
		plugins = []
		fields = ['id']
		response = self.sc.get('plugin', params={'fields': ",".join(fields), 'endOffset':'110000'})
		for p in response.json()['response']:
			plug = Plugin.load(self.sc, p['id'])
			plugins.append(plug)
		return plugins

	def list_plugins(self):
		"""
			Returns a list of all plugins.
			This *should* be iterable.  (Note above comments.)
		"""
		pp = pprint.PrettyPrinter(indent=4)
		plugins = []
		fields = ['id']
		response = self.sc.get('plugin', params={'fields': ",".join(fields), 'endOffset':'110000'})
		for p in response.json()['response']:
			plug = Plugin.load(self.sc, p['id'])
			yield plug

	def get_plugins_since(self, start_date):
		"""
			Returns a list of plugins since the
			specified start_date in seconds.
			Defaults to the last 90 days:
			(60 (seconds) * 60 (minutes) * 24 (hours) * 90 (days))
		"""
		plugins = []
		#params = {}
		#params['fields'] = "id"
		#params['endOffset'] = 10000
		#params['since'] = start_date
		response = self.sc.get('plugin', params={'fields':['id'], \
			'endOffset':'100', 'since':start_date})
		for p in response.json()['response']:
			plug = Plugin.load(self.sc, p['id'])
			yield plug
		#	plugins.append(plug)
		#return plugins

	def list_plugin_families(self):
		"""
			Generator object that returns the list of
			plugin families
		"""
		fields = ['id']
		response = self.sc.get('pluginFamily', params={'fields':",".join(fields)})
		for pf in response.json()['response']:
			pf_obj = PluginFamily.load(self.sc, pf['id'])
			yield pf_obj

class BasicAPIObject(object):
	def __init__(self):
		self.id = 0
		self.name = ''
		self.description = ''

class Alert(BasicAPIObject):
	def __init__(self):
		super(BasicAPIObject, self).__init__()
		self.status = ''
		self.owner = ''
		self.ownerGroup = ''
		self.triggerName = ''
		self.triggerOperator = ''
		self.triggerValue = ''
		self.modifiedTime = 0
		self.createdTime = 0
		self.lastTriggered = 0
		self.lastEvaluated = 0
		self.executeOnEveryTrigger = False
		self.didTriggerLastEvaluation = False
		self.schedule = None
		self.action = ''
		self.query = ''
		self.canUse = False
		self.canManage = False

	@staticmethod
	def load(sc, _id):
		# get the data from the REST API
		resp = sc.get('alert', params={'id':['id']})
		rb = resp.json()['response']
		# instantiate the empty object
		alert = Alert()
		alert.id = _id
		alert.__dict__.update(rb)
		return alert

class Asset(BasicAPIObject):
	# represents an Asset in object form
	def __init__(self, **kwargs):
		self.status = ''
		self.creator = ''
		self.owner = ''
		self.ownerGroup = ''
		self.targetGroup = ''
		self.groups = 0					# This might be an array.
		self.template = ''
		self.typeFields = ''			# This might be an array or hash.
		self.type = ''
		self.tags = ''
		self.context = ''
		self.createdTime = 0			# This might could be a DateTime type object.
		self.modifiedTime = 0			# This might could be a DateTime type object.
		self.respositories = []			# This is likely an array.
		self.ipCount = 0
		self.assetDataFields = []		# This is likely an array or hash.
		self.viewableIPs = []			# Probably an array; may cause slow processing, i.e. a lot of data.

		# should probably set filter parameters
		# usable, managable, excludeAllDefined, excludeWatchlists

		return self

	@staticmethod
	def load(sc, id):
		# load the Asset from the console in object form
		print("This class method is not yet implemented.")
		pass

class AuditFile(BasicAPIObject):
	def __init__(self):
		self.type = ''
		self.status = ''
		self.groups = list()
		self.creator = ''
		self.version = ''
		self.context = ''
		self.filename = ''
		self.originalFilesname = ''
		self.modifiedTime = 0
		self.createTime = 0
		self.lastRefreshedTime = 0
		self.canUse = False
		self.canManage = False
		self.auditFileTemplate = ''
		self.typeFields = ''
		self.ownerGroup = ''
		self.targetGroup = ''

	@staticmethod
	def load(_id, *args):
		print('NYI')
		pass

class Credential(BasicAPIObject):
	def __init__(self, **kwargs):
		super(BasicAPIObject, self).__init__()
		self.type = ''
		self.creator = ''
		self.target = ''
		self.groups = list()
		self.typeFields = None
		self.tags = list()
		self.createdTime = 0
		self.modifiedTime = 0
		self.canUse = False
		self.canManage = False
		self.owner = ''
		self.ownerGroup = ''
		self.targetGroup = ''

	@staticmethod
	def load(_id, *args):
		print('NYI')
		pass

class CurrentUser(BasicAPIObject):
	def __init__(self, _id):
		self.id = _id
		self.name = ''
		self.description = ''
		self.type = ''
		self.creator = ''
		self.target = ''
		self.groups = ''
		self.typeFields = None
		self.tags = list()
		self.createdTime = 0
		self.modifiedTime = 0
		self.canUse = False
		self.canManage = False
		self.owner = ''
		self.ownerGroup = ''
		self.targetGroup = ''

	@staticmethod
	def load(self, _id):
		print('NYI')
		pass

class Group(BasicAPIObject):
	def __init__(self, _id):
		self.id = _id
		self.name = ''
		self.description = ''
		self.createdTime = 0
		self.modifiedTime = 0
		self.lces = list()								# list of LCEs
		self.repositories = list()						# list of Repositories
		self.definingAssets = list()					# list of Assets
		self.userCount = 0
		self.users = list()
		self.assets = list()
		self.policies = list()
		self.queries = list()
		self.credentials = list()
		self.dashboardTabs = list()
		self.arcs = list()
		self.auditFiles = list()

	@staticmethod
	def load(self, _id):
		print('FYI')
		pass

class IPInfo(BasicAPIObject):
	def __init__(self, _ip):
		self.ip = _ip
		self.repositoryID = 0
		self.repositories = list()
		self.repository = ''
		self.score = 0
		self.total = 0
		self.severityInfo = ''
		self.severityLow = ''
		self.severityMedium = ''
		self.severityHigh = ''
		self.severityCritical = ''
		self.macAddress = ''
		self.policyName = ''
		self.pluginSet = ''
		self.netbiosName = ''
		self.dnsName = ''
		self.osCPE = ''
		self.biosGUID = ''
		self.tpmID = ''
		self.mcafeeGUID = ''
		self.lastAuthRun = 0
		self.lastUnauthRun = 0
		self.severityAll = 0
		self.os = ''
		self.hasPassive = False
		self.hasCompliance = False
		self.lastScan = 0
		self.links = list()

	def load(self, _ip):
		print('NYI')
		pass

class Organization(BasicAPIObject):
	# represents the Organization in SC
	def __init__(self):
		super(BasicAPIObject, self).__init__()
		self.email = ''
		self.address = ''
		self.city = ''
		self.state = ''
		self.country = ''
		self.phone = ''
		self.fax = ''
		self.ipInfoLinks = list()
		self.zoneSelection = ''
		self.restrictedIPs = ''
		self.vulnScoreLow = 0
		self.vulnScoreMedium = 0
		self.vulnScoreHigh = 0
		self.vulnScoreCritical = 0
		self.createdTime = 0
		self.modifiedTime = 0
		self.userCount = 0
		self.lces = list()					# an array of LCE objects
		self.repositories = list()			# as array of Respository objects
		self.zones = list()					# an array of Zone objects
		self.nessusManagers = list()
		self.pubSites = list()
		self.ldaps = list()

	def __repr__(self):
		mystr = """
id=%s, name=%s, description=%s, email=%s, address=%s, city=%s, 
state=%s, country=%s, phone=%s, fax=%s, ipInfoLinks=%s, 
zoneSelection=%s, restrictedIPs=%s, vulnScoreLow=%s
vulnScoreMedium=%s, vulnScoreHigh=%s, vulnScoreCritical=%s
createdTime=%s, modifiedTime=%s, userCount=%s, lces=%s, 
repositories=%s, zones=%s, nessusManagers=%s, pubSites=%s, 
ldaps=%s""" % (self.id, self.name, self.description, \
self.email, self.address, self.city, self.state, self.country, \
self.phone, self.fax, self.ipInfoLinks, self.zoneSelection, \
self.restrictedIPs, self.vulnScoreLow, self.vulnScoreMedium, \
self.vulnScoreHigh, self.vulnScoreCritical, self.createdTime, \
self.modifiedTime, self.userCount, self.lces, self.repositories, \
self.zones, self.nessusManagers, self.pubSites, self.ldaps)
		return mystr

	@staticmethod
	def load(sc, org_id):
		# loads the Organization object with the specified ID from the console
		resp = sc.get('organization', params={'id': org_id})
		rb = resp.json()['response']
		org = Organization()
		org.__dict__.update(rb)
		return org

class Plugin(BasicAPIObject):
	def __init__(self, _id, _name=None):
		self.id = _id
		self.name = _name
		self.description = ''
		self.family = ''			# this should be a PluginFamily object
		self.type = ''
		self.copyright = ''
		self.version = ''
		self.sourceFile = ''
		self.source = ''
		self.dependencies = ''
		self.requiredPorts = ''
		self.requiredUDPPorts = ''
		self.cpe = ''
		self.srcPort = 0
		self.dstPort = 0
		self.protocol = ''
		self.riskFactor = ''
		self.solution = ''
		self.seeAlso = ''
		self.synopsis = ''
		self.checkType = ''
		self.exploitEase = ''
		self.exploitAvailable = ''
		self.exploitFrameworks = ''
		self.cvssVector = ''
		self.cvssVectorBF = ''
		self.baseScore = 0
		self.temporalScore = 0
		self.stigSeverity = 0
		self.pluginPubDate = 0
		self.pluginModDate = 0
		self.patchPubDate = 0
		self.patchModDate = 0
		self.vulnPubDate = 0
		self.modifiedTime = 0
		self.md5 = ''
		self.xrefs = []

	def __repr__(self):
		my_str = "id:%s; name:%s; familyName:%s; type:%s; \
riskFactor:%s; baseScore:%s; pluginPubDate:%s; \
pluginModDate:%s; vulnPubDate:%s; modifiedTime:%s;" % (
			self.id, self.name, self.family.name, self.type, \
			self.riskFactor, self.baseScore, \
			time.strftime("%x %X", time.localtime(float(self.pluginPubDate))), \
			time.strftime("%x %X", time.localtime(float(self.pluginModDate))), \
			time.strftime("%x %X", time.localtime(float(self.vulnPubDate))), \
			time.strftime("%x %X", time.localtime(float(self.modifiedTime))))
		return my_str

	@staticmethod
	def load(sc, _id):
		pp = pprint.PrettyPrinter(indent=4)
		response = sc.get('plugin', params={'id': _id})
		p = Plugin(_id, response.json()['response']['name'])
		p.description = response.json()['response']['description']
		pfam = PluginFamily.load(sc, response.json()['response']['family']['id'])
		p.family = pfam
		p.type = response.json()['response']['type']
		p.copyright = response.json()['response']['copyright']
		p.version = response.json()['response']['version']
		p.sourceFile = response.json()['response']['sourceFile']
		p.source = response.json()['response']['source']
		p.dependencies = response.json()['response']['dependencies']
		p.requiredPorts = response.json()['response']['requiredPorts']
		p.requiredUDPPorts = response.json()['response']['requiredUDPPorts']
		p.cpe = response.json()['response']['cpe']
		if response.json()['response']['srcPort'] is not None:
			p.srcPort = int(response.json()['response']['srcPort'])
		if response.json()['response']['dstPort'] is not None:
			p.dstPort = int(response.json()['response']['dstPort'])
		p.protocol = response.json()['response']['protocol']
		p.riskFactor = response.json()['response']['riskFactor']
		p.solution = response.json()['response']['solution']
		p.seeAlso = response.json()['response']['seeAlso']
		p.synopsis = response.json()['response']['synopsis']
		p.checkType = response.json()['response']['checkType']
		p.exploitEase = response.json()['response']['exploitEase']
		p.exploitAvailable = response.json()['response']['exploitAvailable']
		p.exploitFrameworks = response.json()['response']['exploitFrameworks']
		p.cvssVector = response.json()['response']['cvssVector']
		p.cvssVectorBF = response.json()['response']['cvssVectorBF']
		if response.json()['response']['baseScore'] is not None:
			p.baseScore = float(response.json()['response']['baseScore'])
		if response.json()['response']['temporalScore'] is not None:
			p.temporalScore = float(response.json()['response']['temporalScore'])
		p.stigSeverity = response.json()['response']['stigSeverity']
		if response.json()['response']['pluginPubDate'] is not None:
			p.pluginPubDate = int(response.json()['response']['pluginPubDate'])
		if response.json()['response']['pluginModDate'] is not None:
			p.pluginModDate = int(response.json()['response']['pluginModDate'])
		if response.json()['response']['patchPubDate'] is not None:
			p.patchPubDate = int(response.json()['response']['patchPubDate'])
		if response.json()['response']['patchModDate'] is not None:
			p.patchModDate = int(response.json()['response']['patchModDate'])
		if response.json()['response']['vulnPubDate'] is not None:
			p.vulnPubDate = int(response.json()['response']['vulnPubDate'])
		if response.json()['response']['modifiedTime'] is not None:
			p.modifiedTime = int(response.json()['response']['modifiedTime'])
		p.md5 = response.json()['response']['md5']
		for x in response.json()['response']['xrefs']:
			p.xrefs.append(x)
		return p

class PluginFamily(BasicAPIObject):
	def __init__(self, _id, _name):
		self.id = _id
		self.name = _name
		self.type = ''
		self.count = 0

	def __repr__(self):
		return "id:{0}; name:{1}; type:{2}; count:{3};".format( \
				self.id, self.name, self.type, self.count)

	@staticmethod
	def load(sc, _id):
		pp = pprint.PrettyPrinter(indent=4)
		response = sc.get('pluginFamily', params={'id': _id})
		pf = PluginFamily(_id, response.json()['response']['name'])
		pf.type = response.json()['response']['type']
		pf.count = int(response.json()['response']['count'])
		return pf

	def to_string(self):
		return "id: {0} name: {1} type: {2} count: {3}".format( \
				self.id, self.name, self.type, self.count)

class Query(BasicAPIObject):
	def __init__(self):
		self.id = 0
		self.name = ''
		self.description = ''
		self.creator = ''
		self.owner = ''
		self.ownerGroup = ''
		self.targetGroup = ''
		self.tool = ''
		self.type = ''
		self.tags = list()
		self.context = ''
		self.browseColumns = list()
		self.browseSortColumns = ''
		self.browseSortDirection = ''
		self.createdTime = 0
		self.modifiedTime = 0
		self.status = ''
		self.filters = list()
		self.canManage = False
		self.canUse = False
		self.groups = list()

	@staticmethod
	def load(self, _id):
		print('NYI')
		pass

class Repository(BasicAPIObject):
	# represents a Repository in object form
	TYPE_ALL = 'All'
	TYPE_LOCAL = 'Local'
	TYPE_REMOTE = 'Remote'
	TYPE_OFFLINE = 'Offline'

	def __init__(self, _id, _name, descr):
		self.id = _id
		self.name = _name
		self.description = descr
		self.type = ''
		self.dataFormat = ''
		self.vulnCount = 0
		self.remoteID = 0
		self.remoteIP = ''
		self.running = False
		self.downloadFormat = ''
		self.lastSyncTime = 0
		self.lastVulnUpdate = 0
		self.createdTime = 0
		self.modifiedTime = 0
		self.transfer = ''
		self.typeFields = ''
		self.remoteSchedule = ''
		self.organizations = list()

	@staticmethod
	def load(sc, repo_id):
		pp = pprint.PrettyPrinter(indent=4)
		response = sc.get('repository', params={'id': repo_id})
		#pp.pprint(response.json()['response'])
		repo = Repository(repo_id, response.json()['response']['name'], \
					response.json()['response']['description'])
		repo.type = response.json()['response']['type']
		repo.dataFormat = response.json()['response']['dataFormat']
		if response.json()['response']['vulnCount'] is not None:
			repo.vulnCount = int(response.json()['response']['vulnCount'])
		repo.remoteID = response.json()['response']['remoteID']
		repo.remoteIP = response.json()['response']['remoteIP']
		repo.running = response.json()['response']['running']
		repo.downloadFormat = response.json()['response']['downloadFormat']
		repo.lastSynceTime = int(response.json()['response']['lastSyncTime'])
		repo.lastVulnUpdate = int(response.json()['response']['lastVulnUpdate'])
		repo.createdTime = int(response.json()['response']['createdTime'])
		repo.modifiedTime = int(response.json()['response']['modifiedTime'])
		# in the documentation not returned (unless possibly specified)
		#repo.transfer = response.json()['response']['transfer']
		repo.typeFields = response.json()['response']['typeFields']
		# in the documentation not returned (unless possibly specified)
		#repo.remoteSchedule = response.json()['response']['remoteSchedule']
		# seems to cause some crazy recursion.  removeing to verify
		#for o in response.json()['response']['organizations']:
		#	org = Organization.load(sc, o['id'])
		#	repo.organizations.append(o)
		return repo

class Role(BasicAPIObject):
	def __init__(self):
		self.id = 0
		self.name = ''
		self.description = ''

class Scan(BasicAPIObject):
	def __init__(self, _id):
		self.id = _id
		self.name = ''
		self.description = ''
		self.status = ''
		self.ipList = list()
		self.type = ''
		self.policy = ''		# policy is listed twice in the API docs.  Why?  Typo?
		self.plugin = ''
		self.repository = ''
		self.zone = ''
		self.dhcpTracking = ''
		self.classifyMitigatedAge = ''
		self.emailOnLaunch = False
		self.emailOnFinish = False
		self.timeoutAction = ''
		self.scanningVirtualHosts = ''
		self.rolloverType = ''
		self.createdTime = 0
		self.modifiedTime = 0
		self.ownerGroup = ''
		self.creator = ''
		self.owner = ''
		self.reports = ''
		self.assets = list()		# should this be a list()?  A dict()?  An Object()?
		self.credentials = list()
		self.numDependents = 0
		self.schedule = None
		self.policyPrefs = ''
		self.maxScanTime = 0

	@staticmethod
	def load(sc, _id):
		pp = pprint.PrettyPrinter(indent=4)
		response = sc.get('scan', params={'id': _id})

class Scanner(BasicAPIObject):
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
		#fields = ["id", "name", "description", "status", \
		#	"ip", "port", "useProxy", "enabled", "verifyHost", \
		#	"managePlugins", "authType", "cert", "username", \
		#	"password", "agentCapable", "version"]
		pp = pprint.PrettyPrinter(indent=4)
		resp = sc.get('scanner', params={"id":scanner_id})
		#pp.pprint(resp.json())
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
			#print("Element: {0}".format(ele))
			#print("ID: {0}".format(ele['id']))
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

class Utils(object):
	def __init__(self):
		pass

	@staticmethod
	def get_cark_creds(config):
		p = subprocess.Popen(["ssh", "root@{0}".format(config['aimproxy']), \
"/opt/CARKaim/sdk/clipasswordsdk", "GetPassword", "-p", \
"AppDescs.AppID={0}".format(config['appid']), "-p", \
"\"Query=safe={0};Folder={1};Object={2}\"".format(
config['safe'], config['folder'], config['objectname']), "-o", \
"Password"], stdout=subprocess.PIPE)
		tup_pass = p.communicate()
		p = tup_pass[0].decode('ascii')
		p = p.strip()
		return p

class Zone(BasicAPIObject):
	# represents the scan Zone in SC in object form
	def __init__(self, _id, _name, description):
		self.id = _id
		self.name = _name
		self.description = description
		self.ipList = []
		self.createdTime = 0
		self.modifiedTime = 0
		self.organizations = []			# a list of Organization objects
		self.activeScanners = 0
		self.totalScanners = 0
		self.scanners = []				# a list of Scanner objects

	def __repr__(self):
		my_str = "id:%s; name:%s; ipList:[%s]; createdTime:%s; \
modifiedTime:%s; orgCount:%s; activeScanners:%s; \
totalScanners:%s;" % (self.id, self.name, self.ipList, \
						self.createdTime, self.modifiedTime, \
						len(self.organizations), self.activeScanners, \
						self.totalScanners)
		return my_str

	@staticmethod
	def load(sc, zone_id):
		# loads an existing Zone from the console
		response = sc.get('zone', params={'id': zone_id})
		zn = Zone(zone_id, response.json()['response']['name'], \
						response.json()['response']['description'])
		zn.ipList = response.json()['response']['ipList']
		if response.json()['response']['createdTime'] is not None:
			zn.createdTime = int(response.json()['response']['createdTime'])
		if response.json()['response']['modifiedTime'] is not None:
			zn.modifiedTime = int(response.json()['response']['modifiedTime'])
		zn.organizations = response.json()['response']['organizations']
		if response.json()['response']['activeScanners'] is not None:
			zn.activeScanners = int(response.json()['response']['activeScanners'])
		if response.json()['response']['totalScanners'] is not None:
			zn.totalScanners = int(response.json()['response']['totalScanners'])
		zn.scanners = response.json()['response']['scanners']
		return zn

	def save(self, sc):
		# adds a new scan zone to the console
		pass
