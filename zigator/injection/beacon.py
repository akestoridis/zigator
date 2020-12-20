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

from scapy.all import Dot15d4Beacon
from scapy.all import Dot15d4FCS
from scapy.all import ZigBeeBeacon


def beacon(mac_seqnum, panid, srcshortaddr, pancoord, assocpermit, devdepth,
           epid, updateid):
    # Sanity checks
    if mac_seqnum < 0 or mac_seqnum > 255:
        raise ValueError("Invalid MAC sequence number")
    elif panid < 0 or panid.bit_length() > 16:
        raise ValueError("Invalid PAN ID")
    elif srcshortaddr < 0 or srcshortaddr.bit_length() > 16:
        raise ValueError("Invalid short source address")
    elif pancoord not in {0, 1}:
        raise ValueError("Invalid PAN Coordinator field value")
    elif assocpermit not in {0, 1}:
        raise ValueError("Invalid Association Permit field value")
    elif devdepth < 0 or devdepth > 15:
        raise ValueError("Invalid Device Depth field value")
    elif epid < 0 or epid.bit_length() > 64:
        raise ValueError("Invalid Extended PAN ID")
    elif updateid < 0 or updateid > 255:
        raise ValueError("Invalid Update ID field value")

    # Forge a beacon
    forged_pkt = (
        Dot15d4FCS(
            fcf_frametype=0,
            fcf_security=0,
            fcf_pending=0,
            fcf_ackreq=0,
            fcf_panidcompress=False,
            fcf_destaddrmode=0,
            fcf_framever=0,
            fcf_srcaddrmode=2,
            seqnum=mac_seqnum)
        / Dot15d4Beacon(
            src_panid=panid,
            src_addr=srcshortaddr,
            sf_beaconorder=15,
            sf_sforder=15,
            sf_finalcapslot=15,
            sf_battlifeextend=0,
            sf_pancoord=pancoord,
            sf_assocpermit=assocpermit,
            gts_spec_desccount=0,
            gts_spec_permit=0,
            pa_num_short=0,
            pa_num_long=0)
        / ZigBeeBeacon(
            proto_id=0,
            stack_profile=2,
            nwkc_protocol_version=2,
            router_capacity=1,
            device_depth=devdepth,
            end_device_capacity=1,
            extended_pan_id=epid,
            tx_offset=16777215,
            update_id=updateid)
    )

    return forged_pkt
