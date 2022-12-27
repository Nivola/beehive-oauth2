#!/usr/bin/env python
# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2022 CSI-Piemonte

from sys import version_info
from setuptools import setup
from setuptools.command.install import install as _install


class install(_install):
    def pre_install_script(self):
        pass

    def post_install_script(self):
        pass

    def run(self):
        self.pre_install_script()

        _install.run(self)

        self.post_install_script()


def load_requires():
    with open('./MANIFEST.md') as f:
        requires = f.read()
    return requires


def load_version():
    with open('./beehive_oauth2/VERSION') as f:
        version = f.read()
    return version


if __name__ == '__main__':
    version = load_version()
    setup(
        name='beehive_oauth2',
        version=version,
        description='Nivola oauth2 authorization package',
        long_description='Nivola oauth2 authorization package',
        author='CSI Piemonte',
        author_email='nivola.engineering@csi.it',
        license='EUPL-1.2',
        url='',
        scripts=[],
        packages=[
            'beehive_oauth2',
            'beehive_oauth2.static',
            'beehive_oauth2.static.css',
            'beehive_oauth2.templates',
            'beehive_oauth2.tests',
            'beehive_oauth2.tests.client',
            'beehive_oauth2.tests.client.webapp',
            'beehive_oauth2.tests.client.webapp.static',
            'beehive_oauth2.tests.client.webapp.templates',
            'beehive_oauth2.tests.regression',
            'beehive_oauth2.tests.resource',
            'beehive_oauth2.tests.resource.static',
            'beehive_oauth2.tests.resource.templates'
        ],
        namespace_packages=[],
        py_modules=[
            'beehive_oauth2.controller',
            'beehive_oauth2.__init__',
            'beehive_oauth2.jwtgrant',
            'beehive_oauth2.model',
            'beehive_oauth2.mod',
            'beehive_oauth2.validator',
            'beehive_oauth2.view'
        ],
        classifiers=[
            'Development Status :: %s' % version,
            'Programming Language :: Python'
        ],
        entry_points={},
        data_files=[
        ],
        package_data={
            'beehive_oauth2': ['VERSION']
        },
        install_requires=load_requires(),
        dependency_links=[],
        zip_safe=True,
        cmdclass={'install': install},
        keywords='',
        python_requires='',
        obsoletes=[]
    )




