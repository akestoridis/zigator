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

from scapy.all import Dot15d4Cmd
from scapy.all import Dot15d4FCS


def beaconreq(mac_seqnum):
    # Forge a beacon request
    forged_pkt = (
        Dot15d4FCS(
            fcf_frametype=3,
            fcf_security=0,
            fcf_pending=0,
            fcf_ackreq=0,
            fcf_panidcompress=False,
            fcf_destaddrmode=2,
            fcf_framever=0,
            fcf_srcaddrmode=0,
            seqnum=mac_seqnum)
        / Dot15d4Cmd(
            dest_panid=0xffff,
            dest_addr=0xffff,
            cmd_id=7)
    )

    return forged_pkt
