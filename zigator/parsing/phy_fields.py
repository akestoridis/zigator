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

from scapy.all import Dot15d4FCS

from .. import config
from .mac_fields import mac_fields


def phy_fields(pkt, msg_queue):
    """Parse IEEE 802.15.4 PHY fields."""
    if pkt.haslayer(Dot15d4FCS):
        # Frame Length field (7 bits)
        config.entry["phy_length"] = len(pkt[Dot15d4FCS])
        if (
            config.entry["phy_length"] > 127
            or (
                config.entry["phy_length"] < 9
                and config.entry["phy_length"] != 5
            )
        ):
            config.entry["error_msg"] = "PE101: Invalid packet length"
            return

        # PHY Payload field (variable)
        config.entry["phy_payload"] = bytes(pkt[Dot15d4FCS]).hex()
        mac_fields(pkt, msg_queue)
    else:
        config.entry["error_msg"] = (
            "PE102: There are no IEEE 802.15.4 MAC fields"
        )
        return
