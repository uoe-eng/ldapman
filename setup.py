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
install_requires = ['python-ldap']

# Do not edit below this line! #

build_dir = "build/"
dist_dir = "dist/"
cur_dir = os.getcwd()

def get_git_version(abbrev=4):
    try:
        p = subprocess.Popen(['git', 'describe'],
                             stdout=subprocess.PIPE)
        return p.communicate()[0].split('\n')[0].strip()
    except Exception as e:
        print e
        return None

def main():
    curdir = os.getcwd()
    try:
        os.mkdir(dist_dir)
        os.mkdir(build_dir)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise

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
        scripts=['bin/ldapman'],
        )


if __name__ == "__main__":
    main()
