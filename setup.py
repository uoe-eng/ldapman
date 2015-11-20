import setuptools
from setuptools.command import easy_install
import os
import errno
import re
import subprocess
import sys

# Change the following to represent your package:
pkg_name = 'ldapman'
pkg_url = 'http://www.github.com/mrichar1/ldapman'
pkg_license = 'AGPL 3'
pkg_description = "."
pkg_author = 'Matthew Richardson, Bruce Duncan'

# List of python module dependencies
# pip format: 'foo', 'foo==1.2', 'foo>=1.2' etc
install_requires = ['python-ldap', 'shellac']

pkg_classifiers = [
    'Development Status :: 5 - Production/Stable',
    'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
    'Programming Language :: Python',
    ]

def call_git_describe():
    try:
        p = subprocess.Popen(['git', 'describe'],
                             stdout=subprocess.PIPE)
        return p.communicate()[0].decode().strip()
    except Exception as e:
        print("HERE", e)
        return None


def read_release_version():
    try:
        with open("RELEASE-VERSION") as f:
            return f.readlines()[0].strip()
    except Exception:
        return None


def write_release_version(version):
    with open("RELEASE-VERSION", "w") as f:
        f.write("%s\n" % version)


def get_git_version():
    version = call_git_describe()
    release_version = read_release_version()
    if version is None:
        version = release_version

    if version is None:
        raise ValueError("Unable to determine the version number!")

    if version != release_version:
        write_release_version(version)

    return version

def main():

    setuptools.setup(
        name=pkg_name,
        version=get_git_version(),
        url=pkg_url,
        license=pkg_license,
        description=pkg_description,
        author=pkg_author,
        packages=setuptools.find_packages('src'),
        package_dir={'': 'src'},
        include_package_data=True,
        package_data = {'': ['LICENSE']},
        install_requires=install_requires,
        scripts=['src/bin/ldapman'],
	data_files=[('/etc', ['src/etc/ldapman.conf'])],
        )

if __name__ == "__main__":
    main()
