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
Metadata for the zigator package
"""

__title__ = "zigator"
__version__ = "0.0.dev1"
__author__ = "Dimitrios-Georgios Akestoridis"
__author_email__ = "akestoridis@cmu.edu"
__description__ = "Security analysis tool for Zigbee networks"
__license__ = "GPL-2.0-only"
__copyright__ = "Copyright (C) 2020 Dimitrios-Georgios Akestoridis"
__url__ = "https://github.com/akestoridis/zigator"
__keywords__ = [
    "wireless",
    "network",
    "traffic",
    "security",
    "analysis",
    "Zigbee",
    "IEEE 802.15.4"
]
__classifiers__ = [
    "Intended Audience :: Science/Research",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
    "Operating System :: POSIX :: Linux",
    "Programming Language :: Python :: 3",
    "Topic :: Security"
]
__install_requires__ = [
    "graphviz>=0.13.2",
    "pycrc>=0.9.2",
    "pycryptodomex>=3.9.4",
    "scapy===2.4.3-zigator"
]
__python_requires__ = ">=3.5.3"
__entry_points__ = {
    "console_scripts": [
        "zigator=zigator.main:main"
    ]
}
__all__ = [
    "__title__",
    "__version__",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__copyright__",
    "__url__",
    "__keywords__",
    "__classifiers__",
    "__install_requires__",
    "__python_requires__",
    "__entry_points__"
]
