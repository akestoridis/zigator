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

from scapy.all import *

from .. import config


def phy_fields(pkt):
    """Parse IEEE 802.15.4 PHY fields."""
    if (len(pkt) != 5 and len(pkt) < 9) or len(pkt) > 127:
        config.entry["error_msg"] = (
            "Invalid frame length: {}".format(len(pkt))
        )
        return

    config.entry["phy_length"] = len(pkt)

    if pkt.haslayer(Dot15d4FCS):
        # TODO: Replace `return` with `mac_fields(pkt)`
        return
    else:
        config.entry["error_msg"] = (
            "It does not contain IEEE 802.15.4 MAC fields"
        )
