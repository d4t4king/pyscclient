#!/usr/bin/env python

class Zone(object):
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
