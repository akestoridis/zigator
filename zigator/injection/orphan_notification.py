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

import socket

from scapy.all import *


def orphan_notification(srcextendedaddr):
    # Forge the injection packet
    injection_pkt = (
        Dot15d4FCS(
            fcf_frametype=3,
            fcf_security=0,
            fcf_pending=0,
            fcf_ackreq=0,
            fcf_panidcompress=False,
            fcf_destaddrmode=2,
            fcf_framever=0,
            fcf_srcaddrmode=3,
            seqnum=137)
        / Dot15d4Cmd(
            dest_panid=0xffff,
            dest_addr=0xffff,
            src_panid=0xffff,
            src_addr=int(srcextendedaddr, 16),
            cmd_id=6)
    )

    # Send the forged packet to a SDR that is listening on a UDP port
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx_sock:
        tx_sock.sendto(bytes(injection_pkt), ("127.0.0.1", 52001))
