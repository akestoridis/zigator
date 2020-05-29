# Copyright (C) 2020 Dimitrios-Georgios Akestoridis
#
# This file is part of Zigator.
#
# Zigator is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 only,
# as published by the Free Software Foundation.
#
# Zigator is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Zigator. If not, see <https://www.gnu.org/licenses/>.

"""
Setup script for the zigator package
"""

import importlib
import os
import setuptools
import sys


top_dirpath = os.path.dirname(os.path.abspath(__file__))
pkg_dirpath = os.path.join(top_dirpath, "zigator")

about = {}
with open(os.path.join(pkg_dirpath, "__about__.py"), "r") as fp:
    exec(fp.read(), about)

long_description = ""
with open(os.path.join(top_dirpath, "README.md"), "r") as fp:
    long_description = fp.read()

getversion_spec = importlib.util.spec_from_file_location(
    "__getversion__", os.path.join(pkg_dirpath, "__getversion__.py"))
getversion_module = importlib.util.module_from_spec(getversion_spec)
sys.modules["__getversion__"] = getversion_module
getversion_spec.loader.exec_module(getversion_module)

setuptools.setup(
    name=about["__title__"],
    version=getversion_module.getversion(pkg_dirpath),
    author=about["__author__"],
    author_email=about["__author_email__"],
    description=about["__description__"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    license=about["__license__"],
    url=about["__url__"],
    keywords=about["__keywords__"],
    classifiers=about["__classifiers__"],
    install_requires=about["__install_requires__"],
    python_requires=about["__python_requires__"],
    entry_points=about["__entry_points__"],
    include_package_data=True,
    zip_safe=False,
    packages=setuptools.find_packages()
)
