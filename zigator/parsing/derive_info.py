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


def examine_extended_addresses():
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


def examine_network_ids():
    if config.entry["mac_frametype"] == "MAC Beacon":
        panid = config.entry["mac_srcpanid"]
        epid = config.entry["nwk_beacon_epid"]

        config.map_networks(epid, panid)


def examine_short_addresses():
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


def examine_device_types():
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
                else:
                    return
            else:
                return
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

        config.update_devices(extendedaddr, macdevtype, nwkdevtype)
    elif config.entry["mac_cmd_id"] == "MAC Association Request":
        # The receivers of association requests are always FFDs
        panid = config.entry["mac_dstpanid"]

        shortaddr = None
        extendedaddr = None
        if (config.entry["mac_dstaddrmode"]
                == "Short destination MAC address"):
            shortaddr = config.entry["mac_dstshortaddr"]
            if (shortaddr, panid) in config.addresses.keys():
                if config.addresses[(shortaddr, panid)] != "Conflicting Data":
                    extendedaddr = config.addresses[(shortaddr, panid)]
                else:
                    return
            else:
                return
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

        config.update_devices(extendedaddr, macdevtype, nwkdevtype)

        # The transmitters of association requests always include
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

        config.update_devices(extendedaddr, macdevtype, nwkdevtype)
    elif config.entry["mac_cmd_id"] == "MAC Data Request":
        # The receivers of data requests are always FFDs
        panid = config.entry["mac_dstpanid"]

        shortaddr = None
        extendedaddr = None
        if (config.entry["mac_dstaddrmode"]
                == "Short destination MAC address"):
            shortaddr = config.entry["mac_dstshortaddr"]
            if (shortaddr, panid) in config.addresses.keys():
                if config.addresses[(shortaddr, panid)] != "Conflicting Data":
                    extendedaddr = config.addresses[(shortaddr, panid)]
                else:
                    return
            else:
                return
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

        config.update_devices(extendedaddr, macdevtype, nwkdevtype)
    elif config.entry["mac_cmd_id"] == "MAC Coordinator Realignment":
        # The transmitter of the Coordinator Realignment is always an FFD
        panid = config.entry["mac_realign_panid"]

        shortaddr = config.entry["mac_realign_coordaddr"]
        extendedaddr = config.entry["mac_srcextendedaddr"]

        macdevtype = "Full-Function Device"
        nwkdevtype = None
        if shortaddr == "0x0000":
            nwkdevtype = "Zigbee Coordinator"
        else:
            nwkdevtype = "Zigbee Router"

        # The receiver of the Coordinator Realignment is always an RFD
        panid = config.entry["mac_realign_panid"]

        shortaddr = config.entry["mac_realign_shortaddr"]
        extendedaddr = config.entry["mac_dstextendedaddr"]

        macdevtype = "Reduced-Function Device"
        nwkdevtype = "Zigbee End Device"


def examine_address_pairs():
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


def derive_info():
    """Derive information about the devices from unencrypted packet fields."""
    # Try to keep a record of all extended addresses
    examine_extended_addresses()

    # Try to map EPIDs to PAN IDs
    examine_network_ids()

    # Try to map short addresses to extended addresses
    examine_short_addresses()

    # Try to derive logical device types
    examine_device_types()

    # Try to keep a record of all short address pairs that exchange packets
    examine_address_pairs()
