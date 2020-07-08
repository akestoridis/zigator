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

import logging

from .beacon import beacon
from .beaconreq import beaconreq
from .orphannotif import orphannotif
from .rejoinreq import rejoinreq


DEFAULT_RAW = "418889aa990000adde5241576e7f"
DEFAULT_PANID = int("0x99aa", 16)
DEFAULT_DSTSHORTADDR = int("0x0000", 16)
DEFAULT_SRCSHORTADDR = int("0xdead", 16)
DEFAULT_SRCEXTENDEDADDR = int("1122334455667788", 16)
DEFAULT_EPID = int("facefeedbeefcafe", 16)


def main(pkt_type, ipaddr, portnum, raw, mac_seqnum, panid, dstshortaddr,
         srcshortaddr, srcextendedaddr, pancoord, assocpermit, devdepth, epid,
         updateid, nwk_seqnum, devtype, powsrc, rxidle):
    """Inject a forged packet."""
    # Sanity checks
    if mac_seqnum < 0 or mac_seqnum > 255:
        raise ValueError("Invalid MAC sequence number")
    elif pancoord not in {0, 1}:
        raise ValueError("Invalid PAN Coordinator field value")
    elif assocpermit not in {0, 1}:
        raise ValueError("Invalid Association Permit field value")
    elif devdepth < 0 or devdepth > 15:
        raise ValueError("Invalid Device Depth field value")
    elif updateid < 0 or updateid > 255:
        raise ValueError("Invalid Update ID field value")
    elif nwk_seqnum < 0 or nwk_seqnum > 255:
        raise ValueError("Invalid NWK sequence number")
    elif devtype not in {0, 1}:
        raise ValueError("Invalid Device Type field value")
    elif powsrc not in {0, 1}:
        raise ValueError("Invalid Power Source field value")
    elif rxidle not in {0, 1}:
        raise ValueError("Invalid Receiver On When Idle field value")

    # Forge a packet based on the provided parameter values
    if pkt_type.lower() == "mpdu":
        # Process some of the provided parameter values
        if raw is None:
            raw = DEFAULT_RAW
            logging.warning("Unspecified raw bytes; defaulted "
                            "to \"{}\"".format(raw))
        # Forge the packet
        forged_pkt = bytes.fromhex(raw)
        # Sanity check
        if len(forged_pkt) < 1 or len(forged_pkt) > 127:
            raise ValueError("Invalid MPDU length")
    elif pkt_type.lower() == "beacon":
        # Process some of the provided parameter values
        if panid is None:
            panid = DEFAULT_PANID
            logging.warning("Unspecified PAN ID; defaulted "
                            "to \"0x{:04x}\"".format(panid))
        else:
            panid = int(panid, 16)
            if panid < 0 or panid.bit_length() > 16:
                raise ValueError("Invalid PAN ID")
        if srcshortaddr is None:
            srcshortaddr = DEFAULT_SRCSHORTADDR
            logging.warning("Unspecified short source address; "
                            "defaulted to \"0x{:04x}\"".format(srcshortaddr))
        else:
            srcshortaddr = int(srcshortaddr, 16)
            if srcshortaddr < 0 or srcshortaddr.bit_length() > 16:
                raise ValueError("Invalid short source address")
        if epid is None:
            epid = DEFAULT_EPID
            logging.warning("Unspecified EPID; defaulted "
                            "to \"{:016x}\"".format(epid))
        else:
            epid = int(epid, 16)
            if panid < 0 or panid.bit_length() > 64:
                raise ValueError("Invalid PAN ID")
        # Forge the packet
        forged_pkt = beacon(mac_seqnum, panid, srcshortaddr, pancoord,
                            assocpermit, devdepth, epid, updateid)
    elif pkt_type.lower() == "beaconreq":
        # Forge the packet
        forged_pkt = beaconreq(mac_seqnum)
    elif pkt_type.lower() == "orphannotif":
        # Process some of the provided parameter values
        if srcextendedaddr is None:
            srcextendedaddr = DEFAULT_SRCEXTENDEDADDR
            logging.warning("Unspecified extended source address; defaulted "
                            "to \"{:016x}\"".format(srcextendedaddr))
        else:
            srcextendedaddr = int(srcextendedaddr, 16)
            if srcextendedaddr < 0 or srcextendedaddr.bit_length() > 64:
                raise ValueError("Invalid extended source address")
        # Forge the packet
        forged_pkt = orphannotif(mac_seqnum, srcextendedaddr)
    elif pkt_type.lower() == "rejoinreq":
        # Process some of the provided parameter values
        if panid is None:
            panid = DEFAULT_PANID
            logging.warning("Unspecified PAN ID; defaulted "
                            "to \"0x{:04x}\"".format(panid))
        else:
            panid = int(panid, 16)
            if panid < 0 or panid.bit_length() > 16:
                raise ValueError("Invalid PAN ID")
        if dstshortaddr is None:
            dstshortaddr = DEFAULT_DSTSHORTADDR
            logging.warning("Unspecified short destination address; "
                            "defaulted to \"0x{:04x}\"".format(dstshortaddr))
        else:
            dstshortaddr = int(dstshortaddr, 16)
            if dstshortaddr < 0 or dstshortaddr.bit_length() > 16:
                raise ValueError("Invalid short destination address")
        if srcshortaddr is None:
            srcshortaddr = DEFAULT_SRCSHORTADDR
            logging.warning("Unspecified short source address; "
                            "defaulted to \"0x{:04x}\"".format(srcshortaddr))
        else:
            srcshortaddr = int(srcshortaddr, 16)
            if srcshortaddr < 0 or srcshortaddr.bit_length() > 16:
                raise ValueError("Invalid short source address")
        if srcextendedaddr is None:
            srcextendedaddr = DEFAULT_SRCEXTENDEDADDR
            logging.warning("Unspecified extended source address; defaulted "
                            "to \"{:016x}\"".format(srcextendedaddr))
        else:
            srcextendedaddr = int(srcextendedaddr, 16)
            if srcextendedaddr < 0 or srcextendedaddr.bit_length() > 64:
                raise ValueError("Invalid extended source address")
        # Forge the packet
        forged_pkt = rejoinreq(mac_seqnum, panid, dstshortaddr, srcshortaddr,
                               nwk_seqnum, srcextendedaddr, devtype, powsrc,
                               rxidle)
    else:
        raise ValueError("Unknown packet type \"{}\"".format(pkt_type))

    # Send the forged packet to an SDR over a UDP connection
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx_sock:
        tx_sock.sendto(bytes(forged_pkt), (ipaddr, portnum))
    logging.info("Sent the following packet over UDP: "
                 "{}".format(bytes(forged_pkt).hex()))
