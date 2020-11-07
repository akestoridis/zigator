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


def get_sll_pkttype(pkt):
    sll_pkttypes = {
        0: "The packet was sent to us by another host",
        1: "The packet was broadcasted by another host",
        2: "The packet was multicasted by another host",
        3: "The packet was sent to another host by another host",
        4: "The packet was sent by us"
    }
    pkttype_id = pkt[CookedLinux].pkttype
    return sll_pkttypes.get(pkttype_id, "Unknown SLL packet type")
