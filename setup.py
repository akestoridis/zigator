#!/usr/bin/env python3

# Copyright (C) 2020-2021 Dimitrios-Georgios Akestoridis
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
Setup script for the ``zigator`` package.
"""

import importlib
import os
import sys

import setuptools


def setup():
    """
    Customize the setup process of the ``zigator`` package.
    """
    top_dirpath = os.path.dirname(os.path.abspath(__file__))
    pkg_dirpath = os.path.join(top_dirpath, "zigator")

    metadata = {}
    with open(
        os.path.join(pkg_dirpath, "_metadata.py"),
        mode="r",
        encoding="utf-8",
    ) as fp:
        exec(fp.read(), metadata)

    long_description = ""
    with open(
        os.path.join(top_dirpath, "README.md"),
        mode="r",
        encoding="utf-8",
    ) as fp:
        comment_counter = 0
        for line in fp:
            if line == "<!-- START OF BADGES -->\n":
                comment_counter += 1
            elif line == "<!-- END OF BADGES -->\n":
                comment_counter -= 1
            elif comment_counter == 0:
                long_description += line

    version_spec = importlib.util.spec_from_file_location(
        "_version",
        os.path.join(pkg_dirpath, "_version.py"),
    )
    version_module = importlib.util.module_from_spec(version_spec)
    sys.modules["_version"] = version_module
    version_spec.loader.exec_module(version_module)

    setuptools.setup(
        name=metadata["__title__"],
        version=version_module.get_version(pkg_dirpath),
        author=metadata["__author__"],
        author_email=metadata["__author_email__"],
        description=metadata["__description__"],
        long_description=long_description,
        long_description_content_type="text/markdown",
        license=metadata["__license__"],
        url=metadata["__url__"],
        keywords=metadata["__keywords__"],
        classifiers=metadata["__classifiers__"],
        install_requires=metadata["__install_requires__"],
        python_requires=metadata["__python_requires__"],
        entry_points=metadata["__entry_points__"],
        include_package_data=True,
        zip_safe=False,
        packages=setuptools.find_packages(),
    )


if __name__ == "__main__":
    setup()
