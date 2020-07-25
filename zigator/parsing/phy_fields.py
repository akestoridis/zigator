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

from scapy.all import Dot15d4FCS

from .. import config
from .mac_fields import mac_fields


def phy_fields(pkt, msg_queue):
    """Parse IEEE 802.15.4 PHY fields."""
    if (len(pkt) != 5 and len(pkt) < 9) or len(pkt) > 127:
        config.entry["error_msg"] = "Invalid packet length"
        return

    # Frame Length field (7 bits)
    config.entry["phy_length"] = len(pkt)

    # PHY Payload field (variable)
    if pkt.haslayer(Dot15d4FCS):
        mac_fields(pkt, msg_queue)
        return
    else:
        config.entry["error_msg"] = "There are no IEEE 802.15.4 MAC fields"
        return
