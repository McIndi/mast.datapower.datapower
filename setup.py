#!/usr/bin/env python

from setuptools import setup

setup(name='mast.datapower.datapower',
      version='2.3.2',
      description='A library to interact with IBM DataPower appliances '
                  'XML Management Interface and CLI Management Interface',
      author='Clifford Bressette IV',
      author_email='cliffordbressette@mcindi.com',
      maintainer="Clifford Bressette",
      url='https://github.com/mcindi/mast.datapower.datapower',
      namespace_packages=["mast", "mast.datapower"],
      packages=['mast',
                'mast.datapower',
                'mast.datapower.datapower',
                'mast.datapower.datapower.et'],
      license="GPL v2",
      install_requires=[])
