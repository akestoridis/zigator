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


def beacon_info():
    # Beacon transmitters always include their PAN ID
    panid = config.entry["mac_srcpanid"]

    # Zigbee devices always include their EPID in their beacons
    epid = config.entry["nwk_beacon_epid"]

    # The beacon transmitters always include one of their addresses
    shortaddr = None
    extendedaddr = None
    if config.entry["mac_srcaddrmode"] == "Short source MAC address":
        shortaddr = config.entry["mac_srcshortaddr"]
    elif config.entry["mac_srcaddrmode"] == "Extended source MAC address":
        extendedaddr = config.entry["mac_srcextendedaddr"]

    # Only FFDs transmit beacons
    macdevtype = "Full-Function Device"

    # We can derive the NWK device type from multiple packet fields
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

    # Update the devices table in the database
    config.db.update_dev(panid, epid,
                         shortaddr, extendedaddr,
                         macdevtype, nwkdevtype)

    return


def assoc_req():
    # The destination is always an FFD
    panid = config.entry["mac_dstpanid"]
    epid = None
    shortaddr = None
    extendedaddr = None
    if (config.entry["mac_dstaddrmode"]
            == "Short destination MAC address"):
        shortaddr = config.entry["mac_dstshortaddr"]
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

    # Update the devices table in the database
    config.db.update_dev(panid, epid,
                         shortaddr, extendedaddr,
                         macdevtype, nwkdevtype)

    # The source always includes their extended address and MAC device type
    # TODO
    return


def assoc_rsp():
    # TODO
    return


def data_req():
    # TODO
    return


def orphan_notif():
    # TODO
    return


def beacon_req():
    # TODO
    return


def coord_realign():
    # The transmitter of the Coordinator Realignment is always an FFD
    panid = config.entry["mac_realign_panid"]
    epid = None
    shortaddr = config.entry["mac_realign_coordaddr"]
    extendedaddr = config.entry["mac_srcextendedaddr"]
    macdevtype = "Full-Function Device"
    nwkdevtype = None
    if shortaddr == "0x0000":
        nwkdevtype = "Zigbee Coordinator"
    else:
        nwkdevtype = "Zigbee Router"

    # Update the devices table in the database
    config.db.update_dev(panid, epid,
                         shortaddr, extendedaddr,
                         macdevtype, nwkdevtype)

    # The receiver of the Coordinator Realignment is always an RFD
    panid = config.entry["mac_realign_panid"]
    epid = None
    shortaddr = config.entry["mac_realign_shortaddr"]
    extendedaddr = config.entry["mac_dstextendedaddr"]
    macdevtype = "Reduced-Function Device"
    nwkdevtype = "Zigbee End Device"


    # Update the devices table in the database
    config.db.update_dev(panid, epid,
                         shortaddr, extendedaddr,
                         macdevtype, nwkdevtype)
    return


def mac_command_info():
    if config.entry["mac_cmd_id"] == "MAC Association Request":
        assoc_req()
        return
    elif config.entry["mac_cmd_id"] == "MAC Association Response":
        assoc_rsp()
        return
    elif config.entry["mac_cmd_id"] == "MAC Disassociation Notification":
        # Not used by Zigbee devices
        return
    elif config.entry["mac_cmd_id"] == "MAC Data Request":
        data_req()
        return
    elif config.entry["mac_cmd_id"] == "MAC PAN ID Conflict Notification":
        # Not used by Zigbee devices
        return
    elif config.entry["mac_cmd_id"] == "MAC Orphan Notification":
        orphan_notif()
        return
    elif config.entry["mac_cmd_id"] == "MAC Beacon Request":
        beacon_req()
        return
    elif config.entry["mac_cmd_id"] == "MAC Coordinator Realignment":
        coord_realign()
        return
    elif config.entry["mac_cmd_id"] == "MAC GTS Request":
        # Not used by Zigbee devices
        return


def dev_info():
    """Derive information about the devices from parsed packet fields."""
    if config.entry["mac_frametype"] == "MAC Acknowledgment":
        # MAC Acknowledgments do not contain anything useful
        return
    elif config.entry["mac_frametype"] == "MAC Beacon":
        # MAC Beacons contain valuable information
        beacon_info()
        return
    elif config.entry["mac_frametype"] == "MAC Command":
        # Some MAC Commands contain valuable information
        mac_command_info()
        return
    elif config.entry["mac_frametype"] == "MAC Data":
        # TODO
        return
    else:
        # Ignore unknown MAC frame types
        return
