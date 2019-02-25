#!/usr/bin/env python

import pprint
from termcolor import cprint,colored
import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import pyscclient

def main():
	pp = pprint.PrettyPrinter(indent=4)
	conn = pyscclient.Connection("nessussc***REMOVED***", "sv-apiuser", "##Sempra01")
	for p in conn.plugins():
		#pp.pprint(p)
		print """
id:			%s
name:		%s
description:	%s
family:		%s
type:		%s
copyright:	%s
version:	%s
sourceFile:	%s
source:		%s
dependencies:	%s
requiredPorts:	%s
requiredUDPPorts:	%s
cpe:		%s
srcPort:	%s
dstPort:	%s
protocol:	%s
riskFactor:	%s
solution:	%s
seeAlso:	%s
synopsis:	%s
checkType:	%s
exploitEase:	%s
exploitAvailable:	%s
cvssVector:	%s
cvssVectorBF:	%s
baseScore:	%s
temporalScore:	%s
stgSeverity:	%s
pluginPubDate:	%s
pluginModDate:	%s
patchPubDate:	%s
patchModDate:	%s
vulnPubDate:	%s
modifiedTime:	%s
md5:			%s
xrefs:		%s """ % (p.id, p.name, p.description, p.family.to_string(), \
					p.type, p.copyright, p.version, p.sourceFile, \
					p.source, p.dependencies, p.requiredPorts, \
					p.requiredUDPPorts, p.cpe, p.srcPort, p.dstPort, \
					p.protocol, p.riskFactor, p.solution, p.seeAlso, \
					p.synopsis, p.checkType, p.exploitEase, \
					p.exploitAvailable, p.cvssVector, p.cvssVectorBF, \
					p.baseScore, p.temporalScore, p.stigSeverity, \
					p.pluginPubDate, p.pluginModDate, p.patchPubDate, \
					p.patchModDate, p.vulnPubDate, p.modifiedTime, \
					p.md5, p.xrefs)

if __name__ == '__main__':
	main()
