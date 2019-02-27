#!/usr/bin/env python3

from setuptools import setup

with open("README.md", "r") as fh:
	log_description = fh.read()

setup(name='pyscclient',
	version='0.1',
	description='python classes to simplify working with the Tenable.SC API',
	long_description=long_description,
	long_description_content_type="text/markdown",
	url='https://github.com/d4t4king/pyscclient',
	author='Charles Heselton',
	author_email='dataking@gmail.com',
	license='GPL v3.0',
	packages=['pyscclient'],
	install_requires=[
		'SecurityCenter'
	],
	zip_safe=False)

