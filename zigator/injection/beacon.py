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


def beacon(panid):
    # Forge the injection packet
    injection_pkt = (
        Dot15d4FCS(
            fcf_frametype=0,
            fcf_security=0,
            fcf_pending=0,
            fcf_ackreq=0,
            fcf_panidcompress=False,
            fcf_destaddrmode=0,
            fcf_framever=0,
            fcf_srcaddrmode=2,
            seqnum=137)
        / Dot15d4Beacon(
            src_panid=int(panid, 16),
            src_addr=0xdead,
            sf_beaconorder=15,
            sf_sforder=15,
            sf_finalcapslot=15,
            sf_battlifeextend=0,
            sf_pancoord=0,
            sf_assocpermit=0,
            gts_spec_desccount=0,
            gts_spec_permit=0,
            pa_num_short=0,
            pa_num_long=0)
        / ZigBeeBeacon(
            proto_id=0,
            nwkc_protocol_version=2,
            stack_profile=2,
            router_capacity=1,
            device_depth=2,
            end_device_capacity=1,
            extended_pan_id=0xfacefeedbeefcafe,
            tx_offset=16777215,
            update_id=0)
    )

    # Send the forged packet to a SDR that is listening on a UDP port
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx_sock:
        tx_sock.sendto(bytes(injection_pkt), ("127.0.0.1", 52001))
