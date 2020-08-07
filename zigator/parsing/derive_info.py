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

from .. import config


def map_epids_to_panids():
    if config.entry["mac_frametype"] == "MAC Beacon":
        panid = config.entry["mac_srcpanid"]
        epid = config.entry["nwk_beacon_epid"]

        config.map_networks(epid, panid)


def compare_short_addresses():
    # Check whether the MAC and NWK Destination is the same or not
    if (config.entry["error_msg"] is None
        and config.entry["mac_frametype"] == "MAC Data"
        and config.entry["mac_panidcomp"]
            == "The source PAN ID is the same as the destination PAN ID"
        and config.entry["mac_dstaddrmode"]
            == "Short destination MAC address"
        and config.entry["nwk_dstshortaddr"] is not None):
        config.entry["der_same_macnwkdst"] = "Same MAC/NWK Dst: {}".format(
            config.entry["mac_dstshortaddr"]
                == config.entry["nwk_dstshortaddr"])

    # Check whether the MAC and NWK Source is the same or not
    if (config.entry["error_msg"] is None
        and config.entry["mac_frametype"] == "MAC Data"
        and config.entry["mac_panidcomp"]
            == "The source PAN ID is the same as the destination PAN ID"
        and config.entry["mac_srcaddrmode"]
            == "Short source MAC address"
        and config.entry["nwk_srcshortaddr"] is not None):
        config.entry["der_same_macnwksrc"] = "Same MAC/NWK Src: {}".format(
            config.entry["mac_srcshortaddr"]
                == config.entry["nwk_srcshortaddr"])


def infer_transmission_type():
    # Check whether this is a single-hop or a multi-hop transmission
    if (config.entry["mac_frametype"]
        in {"MAC Acknowledgment", "MAC Beacon", "MAC Command"}):
        config.entry["der_tx_type"] = "Single-Hop Transmission"
    elif config.entry["nwk_radius"] is not None:
        if config.entry["nwk_radius"] > 1:
            config.entry["der_tx_type"] = "Multi-Hop Transmission"
        elif config.entry["nwk_radius"] == 1:
            if (config.entry["der_same_macnwksrc"]
                == "Same MAC/NWK Src: True"):
                config.entry["der_tx_type"] = "Single-Hop Transmission"
            elif (config.entry["der_same_macnwksrc"]
                  == "Same MAC/NWK Src: False"):
                config.entry["der_tx_type"] = "Multi-Hop Transmission"


def record_short_address_pairs():
    if config.entry["mac_frametype"] != "MAC Data":
        # Examine only MAC Data packets
        return
    elif (config.entry["mac_panidcomp"]
            != "The source PAN ID is the same as the destination PAN ID"):
        # Ignore Inter-PAN packets
        return

    # Update the stored information about this pair of short addresses
    srcaddr = config.entry["mac_srcshortaddr"]
    dstaddr = config.entry["mac_dstshortaddr"]
    panid = config.entry["mac_dstpanid"]
    time = config.entry["pkt_time"]
    if None not in {srcaddr, dstaddr, panid, time}:
        config.update_pairs(srcaddr, dstaddr, panid, time)


def record_extended_addresses():
    if config.entry["mac_dstextendedaddr"] is not None:
        config.update_devices(config.entry["mac_dstextendedaddr"], None, None)

    if config.entry["mac_srcextendedaddr"] is not None:
        config.update_devices(config.entry["mac_srcextendedaddr"], None, None)

    if config.entry["nwk_dstextendedaddr"] is not None:
        config.update_devices(config.entry["nwk_dstextendedaddr"], None, None)

    if config.entry["nwk_srcextendedaddr"] is not None:
        config.update_devices(config.entry["nwk_srcextendedaddr"], None, None)

    if config.entry["nwk_aux_srcaddr"] is not None:
        config.update_devices(config.entry["nwk_aux_srcaddr"], None, None)

    if (config.entry["aps_aux_srcaddr"] is not None
            and config.entry["nwk_security"] == "NWK Security Disabled"):
        config.update_devices(config.entry["aps_aux_srcaddr"], None, None)


def map_short_to_extended_addresses():
    if config.entry["mac_frametype"] == "MAC Data":
        if (config.entry["mac_panidcomp"]
                != "The source PAN ID is the same as the destination PAN ID"):
            # Ignore Inter-PAN packets
            return

        # Map the short address of the source to its extended address
        panid = config.entry["mac_dstpanid"]
        shortaddr = config.entry["nwk_srcshortaddr"]
        extendedaddr = config.entry["nwk_srcextendedaddr"]
        if None not in {shortaddr, panid, extendedaddr}:
            config.map_addresses(shortaddr, panid, extendedaddr)

        # Map the short address of the destination to its extended address
        panid = config.entry["mac_dstpanid"]
        shortaddr = config.entry["nwk_dstshortaddr"]
        extendedaddr = config.entry["nwk_dstextendedaddr"]
        if None not in {shortaddr, panid, extendedaddr}:
            config.map_addresses(shortaddr, panid, extendedaddr)

        # All the packets that are secured on the NWK layer include
        # the extended address of the transmitter in the auxiliary header
        if config.entry["nwk_security"] == "NWK Security Enabled":
            panid = config.entry["mac_dstpanid"]
            shortaddr = config.entry["mac_srcshortaddr"]
            extendedaddr = config.entry["nwk_aux_srcaddr"]
            if None not in {shortaddr, panid, extendedaddr}:
                config.map_addresses(shortaddr, panid, extendedaddr)
    elif config.entry["mac_cmd_id"] == "MAC Association Response":
        if config.entry["mac_assocrsp_status"] != "Association successful":
            # Ignore unsuccessful associations
            return

        # Map the short address of the receiver to its extended address
        panid = config.entry["mac_dstpanid"]
        shortaddr = config.entry["mac_assocrsp_shortaddr"]
        extendedaddr = config.entry["mac_dstextendedaddr"]
        if None not in {shortaddr, panid, extendedaddr}:
            config.map_addresses(shortaddr, panid, extendedaddr)
    elif config.entry["mac_cmd_id"] == "MAC Coordinator Realignment":
        # Map the short address of the transmitter to its extended address
        panid = config.entry["mac_realign_panid"]
        shortaddr = config.entry["mac_realign_coordaddr"]
        extendedaddr = config.entry["mac_srcextendedaddr"]
        if None not in {shortaddr, panid, extendedaddr}:
            config.map_addresses(shortaddr, panid, extendedaddr)

        # Map the short address of the receiver to its extended address
        panid = config.entry["mac_realign_panid"]
        shortaddr = config.entry["mac_realign_shortaddr"]
        extendedaddr = config.entry["mac_dstextendedaddr"]
        if None not in {shortaddr, panid, extendedaddr}:
            config.map_addresses(shortaddr, panid, extendedaddr)


def derive_logical_device_types():
    if config.entry["mac_frametype"] == "MAC Beacon":
        # Only FFDs transmit beacons
        panid = config.entry["mac_srcpanid"]
        shortaddr = None
        extendedaddr = None
        if config.entry["mac_srcaddrmode"] == "Short source MAC address":
            shortaddr = config.entry["mac_srcshortaddr"]
            if (shortaddr, panid) in config.addresses.keys():
                if config.addresses[(shortaddr, panid)] != "Conflicting Data":
                    extendedaddr = config.addresses[(shortaddr, panid)]
        elif config.entry["mac_srcaddrmode"] == "Extended source MAC address":
            extendedaddr = config.entry["mac_srcextendedaddr"]
        macdevtype = "Full-Function Device"
        nwkdevtype = None
        if ((config.entry["nwk_beacon_devdepth"] == 0)
            and (config.entry["mac_beacon_pancoord"]
                 == "The sender is the PAN coordinator")):
            # Zigbee Coordinators are always PAN Coordinators with zero depth
            nwkdevtype = "Zigbee Coordinator"
        elif ((config.entry["nwk_beacon_devdepth"] > 0)
              and (config.entry["mac_beacon_pancoord"]
                   == "The sender is not the PAN coordinator")):
            # Zigbee Routers transmit beacons with depth greater than zero
            nwkdevtype = "Zigbee Router"
        if extendedaddr is not None:
            config.update_devices(extendedaddr, macdevtype, nwkdevtype)
    elif config.entry["mac_cmd_id"] == "MAC Association Request":
        # The receivers of Association Requests are always FFDs
        panid = config.entry["mac_dstpanid"]
        shortaddr = None
        extendedaddr = None
        if (config.entry["mac_dstaddrmode"]
                == "Short destination MAC address"):
            shortaddr = config.entry["mac_dstshortaddr"]
            if (shortaddr, panid) in config.addresses.keys():
                if config.addresses[(shortaddr, panid)] != "Conflicting Data":
                    extendedaddr = config.addresses[(shortaddr, panid)]
        elif (config.entry["mac_dstaddrmode"]
                == "Extended destination MAC address"):
            extendedaddr = config.entry["mac_dstextendedaddr"]
        macdevtype = "Full-Function Device"
        nwkdevtype = None
        if shortaddr is not None:
            if shortaddr == "0x0000":
                nwkdevtype = "Zigbee Coordinator"
            else:
                nwkdevtype = "Zigbee Router"
        if extendedaddr is not None:
            config.update_devices(extendedaddr, macdevtype, nwkdevtype)

        # The transmitters of Association Requests always include
        # their extended address as well as their MAC device type
        panid = config.entry["mac_dstpanid"]
        shortaddr = None
        extendedaddr = config.entry["mac_srcextendedaddr"]
        macdevtype = config.entry["mac_assocreq_devtype"]
        nwkdevtype = None
        if macdevtype == "Full-Function Device":
            # Zigbee Coordinators do not transmit association requests
            nwkdevtype = "Zigbee Router"
        elif macdevtype == "Reduced-Function Device":
            # All RFDs are Zigbee End Devices
            nwkdevtype = "Zigbee End Device"
        if extendedaddr is not None:
            config.update_devices(extendedaddr, macdevtype, nwkdevtype)
    elif config.entry["mac_cmd_id"] == "MAC Association Response":
        # The transmitters of Association Responses are always FFDs
        panid = config.entry["mac_dstpanid"]
        shortaddr = None
        extendedaddr = None
        if config.entry["mac_srcaddrmode"] == "Short source MAC address":
            shortaddr = config.entry["mac_srcshortaddr"]
            if (shortaddr, panid) in config.addresses.keys():
                if config.addresses[(shortaddr, panid)] != "Conflicting Data":
                    extendedaddr = config.addresses[(shortaddr, panid)]
        elif config.entry["mac_srcaddrmode"] == "Extended source MAC address":
            extendedaddr = config.entry["mac_srcextendedaddr"]
        macdevtype = "Full-Function Device"
        nwkdevtype = None
        if shortaddr is not None:
            if shortaddr == "0x0000":
                nwkdevtype = "Zigbee Coordinator"
            else:
                nwkdevtype = "Zigbee Router"
        if extendedaddr is not None:
            config.update_devices(extendedaddr, macdevtype, nwkdevtype)
    elif config.entry["mac_cmd_id"] == "MAC Data Request":
        # The receivers of Data Requests are always FFDs
        panid = config.entry["mac_dstpanid"]
        shortaddr = None
        extendedaddr = None
        if (config.entry["mac_dstaddrmode"]
                == "Short destination MAC address"):
            shortaddr = config.entry["mac_dstshortaddr"]
            if (shortaddr, panid) in config.addresses.keys():
                if config.addresses[(shortaddr, panid)] != "Conflicting Data":
                    extendedaddr = config.addresses[(shortaddr, panid)]
        elif (config.entry["mac_dstaddrmode"]
                == "Extended destination MAC address"):
            extendedaddr = config.entry["mac_dstextendedaddr"]
        macdevtype = "Full-Function Device"
        nwkdevtype = None
        if shortaddr is not None:
            if shortaddr == "0x0000":
                nwkdevtype = "Zigbee Coordinator"
            else:
                nwkdevtype = "Zigbee Router"
        if extendedaddr is not None:
            config.update_devices(extendedaddr, macdevtype, nwkdevtype)

        # Only RFDs use their short addresses to transmit Data Requests
        if config.entry["mac_srcaddrmode"] == "Short source MAC address":
            panid = config.entry["mac_dstpanid"]
            shortaddr = config.entry["mac_srcshortaddr"]
            extendedaddr = None
            if (shortaddr, panid) in config.addresses.keys():
                if config.addresses[(shortaddr, panid)] != "Conflicting Data":
                    extendedaddr = config.addresses[(shortaddr, panid)]
            macdevtype = "Reduced-Function Device"
            nwkdevtype = "Zigbee End Device"
            if extendedaddr is not None:
                config.update_devices(extendedaddr, macdevtype, nwkdevtype)
    elif config.entry["mac_cmd_id"] == "MAC Coordinator Realignment":
        # The transmitter of the Coordinator Realignment is always an FFD
        panid = config.entry["mac_realign_panid"]
        shortaddr = config.entry["mac_realign_coordaddr"]
        extendedaddr = config.entry["mac_srcextendedaddr"]
        macdevtype = "Full-Function Device"
        nwkdevtype = None
        if shortaddr is not None:
            if shortaddr == "0x0000":
                nwkdevtype = "Zigbee Coordinator"
            else:
                nwkdevtype = "Zigbee Router"
        if extendedaddr is not None:
            config.update_devices(extendedaddr, macdevtype, nwkdevtype)

        # The receiver of the Coordinator Realignment is always an RFD
        panid = config.entry["mac_realign_panid"]
        shortaddr = config.entry["mac_realign_shortaddr"]
        extendedaddr = config.entry["mac_dstextendedaddr"]
        macdevtype = "Reduced-Function Device"
        nwkdevtype = "Zigbee End Device"
        if extendedaddr is not None:
            config.update_devices(extendedaddr, macdevtype, nwkdevtype)
    elif config.entry["nwk_frametype"] == "NWK Command":
        if (config.entry["nwk_dstshortaddr"] == "0xfffc"
            and config.entry["der_tx_type"] == "Single-Hop Transmission"):
            # Only Zigbee Routers and the Zigbee Coordinator transmit Link
            # Status commands, which are the only single-hop NWK commands that
            # are broadcasted to all Zigbee Routers and the Zigbee Coordinator
            # according to the Zigbe PRO 2015 specification
            panid = config.entry["mac_dstpanid"]
            shortaddr = config.entry["nwk_srcshortaddr"]
            extendedaddr = config.entry["nwk_srcextendedaddr"]
            macdevtype = "Full-Function Device"
            nwkdevtype = None
            if shortaddr is not None:
                if shortaddr == "0x0000":
                    nwkdevtype = "Zigbee Coordinator"
                else:
                    nwkdevtype = "Zigbee Router"
            if extendedaddr is not None:
                config.update_devices(extendedaddr, macdevtype, nwkdevtype)
        elif (config.entry["nwk_cmd_payloadlength"] == 3
            and config.entry["der_tx_type"] == "Single-Hop Transmission"):
            # Only Zigbee Routers and the Zigbee Coordinator transmit Rejoin
            # Responses, which are the only single-hop NWK commands that can
            # have a payload length of 3 bytes according to the Zigbee PRO
            # 2015 specification
            panid = config.entry["mac_dstpanid"]
            shortaddr = config.entry["nwk_srcshortaddr"]
            extendedaddr = config.entry["nwk_srcextendedaddr"]
            macdevtype = "Full-Function Device"
            nwkdevtype = None
            if shortaddr is not None:
                if shortaddr == "0x0000":
                    nwkdevtype = "Zigbee Coordinator"
                else:
                    nwkdevtype = "Zigbee Router"
            if extendedaddr is not None:
                config.update_devices(extendedaddr, macdevtype, nwkdevtype)


def derive_address_types():
    if (config.entry["mac_frametype"] == "MAC Data"
        and config.entry["mac_panidcomp"]
                != "The source PAN ID is the same as the destination PAN ID"):
            # Ignore Inter-PAN packets
            return

    # Derive the MAC Destination Type
    if config.entry["mac_dstaddrmode"] == "Short destination MAC address":
        panid = config.entry["mac_dstpanid"]
        shortaddr = config.entry["mac_dstshortaddr"]
        extendedaddr = None
        if (shortaddr, panid) in config.addresses.keys():
            extendedaddr = config.addresses[(shortaddr, panid)]
        if shortaddr == "0xffff":
            config.entry["der_mac_dsttype"] = (
                "MAC Dst Type: Broadcast"
            )
        elif extendedaddr is None:
            config.entry["der_mac_dsttype"] = (
                "MAC Dst Type: None"
            )
        elif extendedaddr == "Conflicting Data":
            config.entry["der_mac_dsttype"] = (
                "MAC Dst Type: Conflicting Data"
            )
        else:
            config.entry["der_mac_dsttype"] = (
                "MAC Dst Type: {}".format(
                    config.devices[extendedaddr]["nwkdevtype"])
            )
        config.entry["der_mac_dstpanid"] = panid
        config.entry["der_mac_dstshortaddr"] = shortaddr
        config.entry["der_mac_dstextendedaddr"] = extendedaddr

    # Derive the MAC Source Type
    if config.entry["mac_srcaddrmode"] == "Short source MAC address":
        if (config.entry["mac_panidcomp"]
                == "The source PAN ID is the same as the destination PAN ID"):
            panid = config.entry["mac_dstpanid"]
        else:
            panid = config.entry["mac_srcpanid"]
        shortaddr = config.entry["mac_srcshortaddr"]
        extendedaddr = None
        if (shortaddr, panid) in config.addresses.keys():
            extendedaddr = config.addresses[(shortaddr, panid)]
        if extendedaddr is None:
            config.entry["der_mac_srctype"] = (
                "MAC Src Type: None"
            )
        elif extendedaddr == "Conflicting Data":
            config.entry["der_mac_srctype"] = (
                "MAC Src Type: Conflicting Data"
            )
        else:
            config.entry["der_mac_srctype"] = (
                "MAC Src Type: {}".format(
                    config.devices[extendedaddr]["nwkdevtype"])
            )
        config.entry["der_mac_srcpanid"] = panid
        config.entry["der_mac_srcshortaddr"] = shortaddr
        config.entry["der_mac_srcextendedaddr"] = extendedaddr

    # Derive the NWK Destination Type
    panid = config.entry["mac_dstpanid"]
    shortaddr = config.entry["nwk_dstshortaddr"]
    extendedaddr = config.entry["nwk_dstextendedaddr"]
    if shortaddr is not None:
        if extendedaddr is None:
            if (shortaddr, panid) in config.addresses.keys():
                extendedaddr = config.addresses[(shortaddr, panid)]
        if shortaddr == "0xffff":
            config.entry["der_nwk_dsttype"] = (
                "NWK Dst Type: All devices"
            )
        elif shortaddr == "0xfffd":
            config.entry["der_nwk_dsttype"] = (
                "NWK Dst Type: All active receivers"
            )
        elif shortaddr == "0xfffc":
            config.entry["der_nwk_dsttype"] = (
                "NWK Dst Type: All routers and coordinator"
            )
        elif shortaddr == "0xfffb":
            config.entry["der_nwk_dsttype"] = (
                "NWK Dst Type: All low-power routers"
            )
        elif extendedaddr is None:
            config.entry["der_nwk_dsttype"] = (
                "NWK Dst Type: None"
            )
        elif extendedaddr == "Conflicting Data":
            config.entry["der_nwk_dsttype"] = (
                "NWK Dst Type: Conflicting Data"
            )
        else:
            config.entry["der_nwk_dsttype"] = (
                "NWK Dst Type: {}".format(
                    config.devices[extendedaddr]["nwkdevtype"])
            )
        config.entry["der_nwk_dstpanid"] = panid
        config.entry["der_nwk_dstshortaddr"] = shortaddr
        config.entry["der_nwk_dstextendedaddr"] = extendedaddr

    # Derive the NWK Source Type
    panid = config.entry["mac_dstpanid"]
    shortaddr = config.entry["nwk_srcshortaddr"]
    extendedaddr = config.entry["nwk_srcextendedaddr"]
    if shortaddr is not None:
        if extendedaddr is None:
            if (shortaddr, panid) in config.addresses.keys():
                extendedaddr = config.addresses[(shortaddr, panid)]
        if extendedaddr is None:
            config.entry["der_nwk_srctype"] = (
                "NWK Src Type: None"
            )
        elif extendedaddr == "Conflicting Data":
            config.entry["der_nwk_srctype"] = (
                "NWK Src Type: Conflicting Data"
            )
        else:
            config.entry["der_nwk_srctype"] = (
                "NWK Src Type: {}".format(
                    config.devices[extendedaddr]["nwkdevtype"])
            )
        config.entry["der_nwk_srcpanid"] = panid
        config.entry["der_nwk_srcshortaddr"] = shortaddr
        config.entry["der_nwk_srcextendedaddr"] = extendedaddr


def derive_info():
    """Derive additional information from the parsed packet."""
    map_epids_to_panids()
    compare_short_addresses()
    infer_transmission_type()
    record_short_address_pairs()
    record_extended_addresses()
    map_short_to_extended_addresses()
    derive_logical_device_types()
    derive_address_types()
