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

from scapy.all import (
    CookedLinux,
    Dot15d4FCS,
)

from .. import config
from .phy_fields import phy_fields


SLL_PKT_TYPES = {
    0: "0x0000: The packet was sent to us by another host",
    1: "0x0001: The packet was broadcasted by another host",
    2: "0x0002: The packet was multicasted by another host",
    3: "0x0003: The packet was sent to another host by another host",
    4: "0x0004: The packet was sent by us",
}


def sll_fields(pkt, msg_queue):
    """Parse SLL fields."""
    # Packet Type field (2 bytes)
    if not (
        config.set_entry(
            "sll_pkttype",
            pkt[CookedLinux].pkttype,
            SLL_PKT_TYPES,
        )
    ):
        config.entry["error_msg"] = "PE003: Unknown SLL packet type"
        return

    # ARPHRD Type field (2 bytes)
    config.entry["sll_arphrdtype"] = pkt[CookedLinux].lladdrtype
    if config.entry["sll_arphrdtype"] != 0x0325:
        config.entry["error_msg"] = "PE002: Unsupported ARPHRD type"
        return

    # Address Length field (2 bytes)
    config.entry["sll_addrlength"] = pkt[CookedLinux].lladdrlen

    # Address field (8 bytes)
    config.entry["sll_addr"] = pkt[CookedLinux].src.hex()

    # Protocol Type field (2 bytes)
    config.entry["sll_protocoltype"] = pkt[CookedLinux].proto
    if config.entry["sll_protocoltype"] != 0x00f6:
        config.entry["error_msg"] = "PE001: Unsupported protocol type"
        return

    # SLL Payload field (variable)
    phy_fields(Dot15d4FCS(bytes(pkt[CookedLinux].payload)), msg_queue)
