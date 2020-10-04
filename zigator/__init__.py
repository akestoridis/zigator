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
Security analysis tool for Zigbee networks
"""

import os

from .__about__ import __author__
from .__about__ import __author_email__
from .__about__ import __classifiers__
from .__about__ import __copyright__
from .__about__ import __description__
from .__about__ import __entry_points__
from .__about__ import __install_requires__
from .__about__ import __keywords__
from .__about__ import __license__
from .__about__ import __python_requires__
from .__about__ import __title__
from .__about__ import __url__

from .__getversion__ import getversion

from .main import main

from . import cli
from . import config

__version__ = getversion(os.path.dirname(os.path.abspath(__file__)))
__all__ = ["main"]

cli.init(__version__)
config.init(__version__)
