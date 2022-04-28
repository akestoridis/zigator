# Copyright (C) 2020-2022 Dimitrios-Georgios Akestoridis
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
__description__ = (
    "Zigator: A security analysis tool for Zigbee and Thread networks"
)
__license__ = "GPL-2.0-only"
__copyright__ = "Copyright (C) 2020-2022 Dimitrios-Georgios Akestoridis"
__url__ = "https://github.com/akestoridis/zigator"
__keywords__ = [
    "wireless",
    "network",
    "traffic",
    "security",
    "analysis",
    "Zigbee",
    "Thread",
    "IEEE 802.15.4",
]
__classifiers__ = [
    "Intended Audience :: Science/Research",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
    "Operating System :: POSIX :: Linux",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Topic :: Security",
]
__install_requires__ = [
    # direct dependencies
    "CherryPy==18.6.1",
    "graphviz==0.20",
    "numpy==1.21.6",
    "psutil==5.9.0",
    "pycrc==0.9.2",
    "pycryptodomex==3.14.1",
    "scapy @ git+https://github.com/akestoridis/scapy@lowpan-enhancements#egg=scapy",
    "scikit-learn==1.0.2",
    # indirect dependencies
    "cheroot==8.5.2",
    "jaraco.classes==3.2.1",
    "jaraco.collections==3.3.0",
    "jaraco.functools==3.3.0",
    "jaraco.text==3.5.0",
    "joblib==1.1.0",
    "more-itertools==8.8.0",
    "portend==2.7.1",
    "pytz==2021.1",
    "scipy==1.7.3",
    "six==1.16.0",
    "tempora==4.1.1",
    "threadpoolctl==3.1.0",
    "zc.lockfile==2.0",
]
__python_requires__ = ">=3.7, <3.11"
__entry_points__ = {
    "console_scripts": ["zigator=zigator.entry_point:entry_point"],
}
