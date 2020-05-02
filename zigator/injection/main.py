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
from .orphannotif import orphannotif


DEFAULT_PANID = int("0x99aa", 16)
DEFAULT_SRCSHORTADDR = int("0xdead", 16)
DEFAULT_SRCEXTENDEDADDR = int("0102030405060708", 16)
DEFAULT_EPID = int("facefeedbeefcafe", 16)


def main(pkt_type, ipaddr, portnum, mac_seqnum, panid, srcshortaddr,
         srcextendedaddr, pancoord, assocpermit, devdepth, epid, updateid):
    """Inject a forged packet."""
    if pkt_type.lower() == "beacon":
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
        else:
            srcshortaddr = int(srcshortaddr, 16)
            if srcshortaddr < 0 or srcshortaddr.bit_length() > 16:
                raise ValueError("Invalid short source address")
        if epid is None:
            epid = DEFAULT_EPID
        else:
            epid = int(epid, 16)
            if panid < 0 or panid.bit_length() > 64:
                raise ValueError("Invalid PAN ID")
        # Forge the packet
        forged_pkt = beacon(mac_seqnum, panid, srcshortaddr, pancoord,
                            assocpermit, devdepth, epid, updateid)
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
    else:
        raise ValueError("Unknown packet type \"{}\"".format(pkt_type))

    # Send the forged packet to an SDR over a UDP connection
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx_sock:
        tx_sock.sendto(bytes(forged_pkt), (ipaddr, portnum))
