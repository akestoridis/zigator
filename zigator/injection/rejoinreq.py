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

from scapy.all import Dot15d4Data
from scapy.all import Dot15d4FCS
from scapy.all import ZigbeeNWK
from scapy.all import ZigbeeNWKCommandPayload


def rejoinreq(mac_seqnum, panid, dstshortaddr, srcshortaddr, nwk_seqnum,
              srcextendedaddr, devtype, powsrc, rxidle):
    # Forge a rejoin request
    forged_pkt = (
        Dot15d4FCS(
            fcf_frametype=1,
            fcf_security=0,
            fcf_pending=0,
            fcf_ackreq=1,
            fcf_panidcompress=True,
            fcf_destaddrmode=2,
            fcf_framever=0,
            fcf_srcaddrmode=2,
            seqnum=mac_seqnum)
        / Dot15d4Data(
            dest_panid=panid,
            dest_addr=dstshortaddr,
            src_addr=srcshortaddr)
        / ZigbeeNWK(
            frametype=1,
            proto_version=2,
            discover_route=0,
            flags=0b010000,
            destination=dstshortaddr,
            source=srcshortaddr,
            radius=1,
            seqnum=nwk_seqnum,
            ext_src=srcextendedaddr)
        / ZigbeeNWKCommandPayload(
            cmd_identifier=6,
            alternate_pan_coordinator=0,
            device_type=devtype,
            power_source=powsrc,
            receiver_on_when_idle=rxidle,
            security_capability=0,
            allocate_address=1)
    )

    return forged_pkt
