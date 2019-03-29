
import pprint

from .pluginfamily import PluginFamily

class Plugin(object):
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
