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


def orphannotif(mac_seqnum, mac_srcextendedaddr):
    # Sanity checks
    if mac_seqnum < 0 or mac_seqnum > 255:
        raise ValueError("Invalid MAC sequence number")
    elif mac_srcextendedaddr < 0 or mac_srcextendedaddr.bit_length() > 64:
        raise ValueError("Invalid extended source MAC address")

    # Forge an orphan notification
    forged_pkt = (
        Dot15d4FCS(
            fcf_frametype=3,
            fcf_security=0,
            fcf_pending=0,
            fcf_ackreq=0,
            fcf_panidcompress=False,
            fcf_destaddrmode=2,
            fcf_framever=0,
            fcf_srcaddrmode=3,
            seqnum=mac_seqnum)
        / Dot15d4Cmd(
            dest_panid=0xffff,
            dest_addr=0xffff,
            src_panid=0xffff,
            src_addr=mac_srcextendedaddr,
            cmd_id=6)
    )

    return forged_pkt
