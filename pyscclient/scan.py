#!/usr/bin/env python

class Scan(object):
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
		s = Scan(response.json()['response']['id'])
		s.name = response.json()['response']['name']
		s.description = response.json()['response']['description']
		s.status = response.json()['response']['status']
		s.ipList = response.json()['response']['ipList']
		s.type = response.json()['response']['type']
		s.policy = response.json()['response']['policy']
		s.plugin = response.json()['response']['plugin']
		s.repository = response.json()['response']['repository']
		s.zone = response.json()['response']['zone']
		s.dhcpTracking = response.json()['response']['dhcpTracking']
		s.classifyMitigatedAge = response.json()['response']['classifyMitigatedAge']
		s.emailOnLaunch = response.json()['response']['emailOnLaunch']
		s.emailOnFinish = response.json()['response']['emailOnFinish']
		s.timeoutAction = response.json()['response']['timeoutAction']
		s.scanningVirtualHosts = response.json()['response']['scanningVirtualHosts']
		s.rolloverType = response.json()['response']['rolloverType']
		s.createdTime = int(response.json()['response']['createdTime'])
		s.modifiedTime = int(response.json()['response']['modifiedTime'])
		s.ownerGroup = response.json()['response']['ownerGroup']
		s.creator = response.json()['response']['creator']
		s.owner = response.json()['response']['owner']
		s.reports = response.json()['response']['reports']
		for ar in response.json()['response']['assets']:
			a = Asset.load(sc, ar['id'])
			s.assets.append(a)
		#s.assets = response.json()['response']['assets']
		s.credentials = response.json()['response']['credentials']
		s.numDependents = int(response.json()['response']['numDependents'])
		s.schedule = response.json()['response']['schedule']
		s.policyPrefs = response.json()['response']['policyPrefs']
		s.maxScanTime = response.json()['response']['maxScanTime']
		return s
