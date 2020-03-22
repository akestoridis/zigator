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

from .beacon import beacon
from .orphan_notification import orphan_notification


def main(pkt_type, parameter):
    """Inject forged packets."""
    if pkt_type.lower() == "beacon":
        beacon(parameter)
    elif pkt_type.lower() == "orphan":
        orphan_notification(parameter)
    else:
        raise ValueError("Unknown packet type \"{}\"".format(pkt_type))
