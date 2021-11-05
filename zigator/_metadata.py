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
Metadata for the ``zigator`` package.
"""

__title__ = "zigator"
__author__ = "Dimitrios-Georgios Akestoridis"
__author_email__ = "akestoridis@cmu.edu"
__description__ = "Zigator: Security analysis tool for Zigbee networks"
__license__ = "GPL-2.0-only"
__copyright__ = "Copyright (C) 2020-2021 Dimitrios-Georgios Akestoridis"
__url__ = "https://github.com/akestoridis/zigator"
__keywords__ = [
    "wireless",
    "network",
    "traffic",
    "security",
    "analysis",
    "Zigbee",
    "IEEE 802.15.4",
]
__classifiers__ = [
    "Intended Audience :: Science/Research",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
    "Operating System :: POSIX :: Linux",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Topic :: Security",
]
__install_requires__ = [
    "CherryPy>=18.6.1, <19",
    "graphviz>=0.17, <1",
    "numpy>=1.21.2, <2",
    "psutil>=5.8.0, <6",
    "pycrc>=0.9.2, <1",
    "pycryptodomex>=3.10.1, <4",
    "scapy @ git+https://github.com/secdev/scapy@6ad83c513648fc1b4199a4b2d7b74b8a8c2ae0ce#egg=scapy",
    "scikit-learn>=0.24.2, <1",
]
__python_requires__ = ">=3.7, <4"
__entry_points__ = {
    "console_scripts": ["zigator=zigator.entry_point:entry_point"],
}
