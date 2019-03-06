#!/usr/bin/env python

from .repository import Repository

class Organization(object):
	# represents the Organization in SC
	def __init__(self, _id, _name, descr):
		self.id = _id
		self.name = _name
		self.description = descr
		self.email = ''
		self.address = ''
		self.city = ''
		self.state = ''
		self.country = ''
		self.phone = ''
		self.fax = ''
		self.ipInfoLinks = []
		self.zoneSelection = ''
		self.restrictedIPs = ''
		self.vulnScoreLow = 0
		self.vulnScoreMedium = 0
		self.vulnScoreHigh = 0
		self.vulnScoreCritical = 0
		self.createdTime = 0
		self.modifiedTime = 0
		self.userCount = 0
		self.lces = []					# an array of LCE objects
		self.repositories = []			# as array of Respository objects
		self.zones = []					# an array of Zone objects
		self.nessusManagers = []
		self.pubSites = []
		self.ldaps = []

	def to_json(self):
		# need to replace the lists of objects with JSON
		jrepos = list()
		for r in self.repositories:
			jrepos.append(r.__dict__)
		self.repositories = jrepos
		return json.dumps(self.__dict__)

	@staticmethod
	def update(sc, org_id, **kwargs):
		pp = pprint.PrettyPrinter(indent=4)
		#pp.pprint(kwargs)
		#print("============")
		#pp.pprint(json.dumps(kwargs))
		#for k,v in kwargs.items():
		#	print("k'{0}' is type {1}".format(k, type(v)))
		resp = sc.sc.patch('organization/{0}'.format(org_id), \
			params=kwargs)
		return resp.json()['error_code']

	@staticmethod
	def load(sc, org_id):
		#print("DEBUG: In Organization.load()")
		# loads the Organization object with the specified ID from the console
		resp = sc.get('organization', params={'id': org_id})
		org = Organization(org_id, resp.json()['response']['name'], \
							resp.json()['response']['description'])
		org.email = resp.json()['response']['email']
		org.address = resp.json()['response']['address']
		org.city = resp.json()['response']['city']
		org.state = resp.json()['response']['state']
		org.country = resp.json()['response']['country']
		org.phone = resp.json()['response']['phone']
		org.fax = resp.json()['response']['fax']
		for ele in resp.json()['response']['ipInfoLinks']:
			org.ipInforLinks.append(ele)
		org.zoneSelection = resp.json()['response']['zoneSelection']
		org.restrictedIPs = resp.json()['response']['restrictedIPs']
		if resp.json()['response']['vulnScoreLow'] is not None:
			org.vulnScoreLow = int(resp.json()['response']['vulnScoreLow'])
		if resp.json()['response']['vulnScoreMedium'] is not None:
			org.vulnScoreMedium = int(resp.json()['response']['vulnScoreMedium'])
		if resp.json()['response']['vulnScoreHigh'] is not None:
			org.vulnScoreHigh = int(resp.json()['response']['vulnScoreHigh'])
		if resp.json()['response']['vulnScoreCritical'] is not None:
			org.vulnScoreCritical = int(resp.json()['response']['vulnScoreCritical'])
		if resp.json()['response']['createdTime'] is not None:
			org.createdTime = int(resp.json()['response']['createdTime'])
		if resp.json()['response']['modifiedTime'] is not None:
			org.modifiedTime = int(resp.json()['response']['modifiedTime'])
		if resp.json()['response']['userCount'] is not None:
			org.userCount = int(resp.json()['response']['userCount'])
		for ele in resp.json()['response']['lces']:
			lce = LCE.load(sc, ele['id'])
			org.lces.append(lce)
		for ele in resp.json()['response']['repositories']:
			repo = Repository.load(sc, ele['id'])
			org.repositories.append(repo)
		for ele in resp.json()['response']['zones']:
			z = Zone.load(sc, ele['id'])
			org.zones.append(z)
		return org
