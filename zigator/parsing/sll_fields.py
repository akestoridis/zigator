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

from scapy.all import CookedLinux
from scapy.all import Dot15d4FCS

from .. import config
from .phy_fields import phy_fields
from .sll_getters import get_sll_pkttype


def sll_fields(pkt, msg_queue):
    """Parse SLL fields."""
    # SLL Header fields (16 bytes)
    config.entry["sll_pkttype"] = get_sll_pkttype(pkt)
    config.entry["sll_arphrdtype"] = pkt[CookedLinux].lladdrtype
    config.entry["sll_addrlength"] = pkt[CookedLinux].lladdrlen
    config.entry["sll_addr"] = pkt[CookedLinux].src.hex()
    config.entry["sll_protocoltype"] = pkt[CookedLinux].proto
    if config.entry["sll_protocoltype"] != 0x00f6:
        config.entry["error_msg"] = "PE001: Unsupported protocol type"
        return
    elif config.entry["sll_arphrdtype"] != 0x0325:
        config.entry["error_msg"] = "PE002: Unsupported ARPHRD type"
        return

    # SLL Payload field (variable)
    phy_fields(Dot15d4FCS(bytes(pkt[CookedLinux].payload)), msg_queue)
