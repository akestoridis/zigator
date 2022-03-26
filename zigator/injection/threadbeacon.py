# Copyright (C) 2022 Dimitrios-Georgios Akestoridis
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
    Dot15d4Beacon,
    Dot15d4FCS,
    Raw,
    ThreadBeacon,
)


def threadbeacon(
    mac_seqnum,
    mac_srcpanid,
    mac_srcextendedaddr,
    thr_beacon_version,
    thr_beacon_native,
    thr_beacon_joining,
    thr_beacon_networkname,
    thr_beacon_epid,
    thr_beacon_payload,
):
    # Sanity checks
    if mac_seqnum < 0 or mac_seqnum > 255:
        raise ValueError("Invalid MAC sequence number")
    elif mac_srcpanid < 0 or mac_srcpanid.bit_length() > 16:
        raise ValueError("Invalid source PAN ID")
    elif mac_srcextendedaddr < 0 or mac_srcextendedaddr.bit_length() > 64:
        raise ValueError("Invalid extended source MAC address")
    elif thr_beacon_version < 0 or thr_beacon_version > 15:
        raise ValueError("Invalid Version beacon field value")
    elif thr_beacon_native not in {0, 1}:
        raise ValueError("Invalid Native beacon field value")
    elif thr_beacon_joining not in {0, 1}:
        raise ValueError("Invalid Joining beacon field value")
    elif len(thr_beacon_networkname) > 16:
        raise ValueError("Invalid Network Name beacon field value")
    elif thr_beacon_epid < 0 or thr_beacon_epid.bit_length() > 64:
        raise ValueError("Invalid Extended PAN ID beacon field value")
    elif len(thr_beacon_payload) > 82:
        raise ValueError("Invalid length of additional raw beacon payload")

    # Forge a Thread beacon
    forged_pkt = (
        Dot15d4FCS(
            fcf_frametype=0,
            fcf_security=0,
            fcf_pending=0,
            fcf_ackreq=0,
            fcf_panidcompress=False,
            fcf_destaddrmode=0,
            fcf_framever=0,
            fcf_srcaddrmode=3,
            seqnum=mac_seqnum,
        )
        / Dot15d4Beacon(
            src_panid=mac_srcpanid,
            src_addr=mac_srcextendedaddr,
            sf_beaconorder=15,
            sf_sforder=15,
            sf_finalcapslot=15,
            sf_battlifeextend=0,
            sf_pancoord=0,
            sf_assocpermit=0,
            gts_spec_desccount=0,
            gts_spec_permit=0,
            pa_num_short=0,
            pa_num_long=0,
        )
        / ThreadBeacon(
            protocol_id=3,
            version=thr_beacon_version,
            native=thr_beacon_native,
            joining=thr_beacon_joining,
            network_name=thr_beacon_networkname,
            extended_pan_id=thr_beacon_epid,
        )
        / Raw(
            thr_beacon_payload,
        )
    )

    return forged_pkt
