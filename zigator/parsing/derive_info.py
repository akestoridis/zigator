# Copyright (C) 2020-2021 Dimitrios-Georgios Akestoridis
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


def extract_network_identifiers():
    if config.entry["mac_frametype"].startswith("0b000:"):
        config.update_networks(
            config.entry["mac_srcpanid"],
            {
                config.entry["nwk_beacon_epid"],
            },
            config.entry["pkt_time"],
            config.entry["pkt_time"],
        )
    else:
        if config.entry["mac_dstpanid"] is not None:
            config.update_networks(
                config.entry["mac_dstpanid"],
                set(),
                None,
                None,
            )
        if config.entry["mac_srcpanid"] is not None:
            config.update_networks(
                config.entry["mac_srcpanid"],
                set(),
                None,
                None,
            )
        if config.entry["mac_realign_panid"] is not None:
            config.update_networks(
                config.entry["mac_realign_panid"],
                set(),
                None,
                None,
            )


def extract_short_addresses():
    if config.entry["mac_dstaddrmode"].startswith("0b10:"):
        config.update_short_addresses(
            config.entry["mac_dstpanid"],
            config.entry["mac_dstshortaddr"],
            set(),
            set(),
            set(),
            None,
            None,
        )
    if config.entry["mac_srcaddrmode"].startswith("0b10:"):
        if config.entry["mac_panidcomp"].startswith("0b0:"):
            config.update_short_addresses(
                config.entry["mac_srcpanid"],
                config.entry["mac_srcshortaddr"],
                set(),
                set(),
                set(),
                config.entry["pkt_time"],
                config.entry["pkt_time"],
            )
        else:
            config.update_short_addresses(
                config.entry["mac_dstpanid"],
                config.entry["mac_srcshortaddr"],
                set(),
                set(),
                set(),
                config.entry["pkt_time"],
                config.entry["pkt_time"],
            )
    if config.entry["mac_frametype"].startswith("0b011:"):
        if config.entry["mac_cmd_id"].startswith("0x02:"):
            if config.entry["mac_assocrsp_status"].startswith("0x00:"):
                config.update_short_addresses(
                    config.entry["mac_dstpanid"],
                    config.entry["mac_assocrsp_shortaddr"],
                    set(),
                    set(),
                    set(),
                    None,
                    None,
                )
        elif config.entry["mac_cmd_id"].startswith("0x08:"):
            config.update_short_addresses(
                config.entry["mac_realign_panid"],
                config.entry["mac_realign_coordaddr"],
                set(),
                set(),
                set(),
                None,
                None,
            )
            config.update_short_addresses(
                config.entry["mac_realign_panid"],
                config.entry["mac_realign_shortaddr"],
                set(),
                set(),
                set(),
                None,
                None,
            )
    if (
        config.entry["mac_frametype"].startswith("0b001:")
        and config.entry["mac_panidcomp"].startswith("0b1:")
    ):
        config.update_short_addresses(
            config.entry["mac_dstpanid"],
            config.entry["nwk_dstshortaddr"],
            set(),
            set(),
            set(),
            None,
            None,
        )
        config.update_short_addresses(
            config.entry["mac_dstpanid"],
            config.entry["nwk_srcshortaddr"],
            set(),
            set(),
            set(),
            None,
            None,
        )


def extract_extended_addresses():
    if config.entry["mac_dstextendedaddr"] is not None:
        config.update_extended_addresses(
            config.entry["mac_dstextendedaddr"],
            set(),
            set(),
            set(),
            None,
            None,
        )
    if config.entry["mac_srcextendedaddr"] is not None:
        config.update_extended_addresses(
            config.entry["mac_srcextendedaddr"],
            set(),
            set(),
            set(),
            config.entry["pkt_time"],
            config.entry["pkt_time"],
        )
    if config.entry["nwk_dstextendedaddr"] is not None:
        config.update_extended_addresses(
            config.entry["nwk_dstextendedaddr"],
            set(),
            set(),
            set(),
            None,
            None,
        )
    if config.entry["nwk_srcextendedaddr"] is not None:
        config.update_extended_addresses(
            config.entry["nwk_srcextendedaddr"],
            set(),
            set(),
            set(),
            None,
            None,
        )
    if config.entry["nwk_aux_srcaddr"] is not None:
        config.update_extended_addresses(
            config.entry["nwk_aux_srcaddr"],
            set(),
            set(),
            set(),
            None,
            None,
        )
    if (
        config.entry["aps_aux_srcaddr"] is not None
        and config.entry["nwk_security"].startswith("0b0:")
    ):
        config.update_extended_addresses(
            config.entry["aps_aux_srcaddr"],
            set(),
            set(),
            set(),
            None,
            None,
        )


def map_addresses():
    if config.entry["mac_frametype"].startswith("0b001:"):
        if not config.entry["mac_panidcomp"].startswith("0b1:"):
            # Ignore Inter-PAN packets
            return

        # Map the short address of the source to its extended address
        config.update_alternative_addresses(
            config.entry["mac_dstpanid"],
            config.entry["nwk_srcshortaddr"],
            config.entry["nwk_srcextendedaddr"],
        )

        # Map the short address of the destination to its extended address
        config.update_alternative_addresses(
            config.entry["mac_dstpanid"],
            config.entry["nwk_dstshortaddr"],
            config.entry["nwk_dstextendedaddr"],
        )

        # All the packets that are secured on the NWK layer include
        # the extended address of the transmitter in the auxiliary header
        if config.entry["nwk_security"].startswith("0b1:"):
            config.update_alternative_addresses(
                config.entry["mac_dstpanid"],
                config.entry["mac_srcshortaddr"],
                config.entry["nwk_aux_srcaddr"],
            )
    elif config.entry["mac_frametype"].startswith("0b011:"):
        if config.entry["mac_cmd_id"].startswith("0x02:"):
            if not config.entry["mac_assocrsp_status"].startswith("0x00:"):
                # Ignore unsuccessful associations
                return

            # Map the short address of the receiver to its extended address
            config.update_alternative_addresses(
                config.entry["mac_dstpanid"],
                config.entry["mac_assocrsp_shortaddr"],
                config.entry["mac_dstextendedaddr"],
            )
        elif config.entry["mac_cmd_id"].startswith("0x08:"):
            # Map the short address of the transmitter to its extended address
            config.update_alternative_addresses(
                config.entry["mac_realign_panid"],
                config.entry["mac_realign_coordaddr"],
                config.entry["mac_srcextendedaddr"],
            )

            # Map the short address of the receiver to its extended address
            config.update_alternative_addresses(
                config.entry["mac_realign_panid"],
                config.entry["mac_realign_shortaddr"],
                config.entry["mac_dstextendedaddr"],
            )


def extract_pairs():
    if not config.entry["mac_frametype"].startswith("0b001:"):
        # Examine only MAC Data packets
        return
    elif not config.entry["mac_panidcomp"].startswith("0b1:"):
        # Ignore Inter-PAN packets
        return
    elif not config.entry["mac_dstaddrmode"].startswith("0b10:"):
        # Ignore packets without a short MAC destination address
        return
    elif not config.entry["mac_srcaddrmode"].startswith("0b10:"):
        # Ignore packets without a short MAC source address
        return

    # Update the stored information about this pair of short addresses
    panid = config.entry["mac_dstpanid"]
    srcaddr = config.entry["mac_srcshortaddr"]
    dstaddr = config.entry["mac_dstshortaddr"]
    time = config.entry["pkt_time"]
    if None not in {panid, srcaddr, dstaddr, time}:
        config.update_pairs(panid, srcaddr, dstaddr, time, time)


def compare_short_addresses():
    # Check whether the MAC and NWK Destination is the same or not
    if (
        config.entry["mac_frametype"].startswith("0b001:")
        and config.entry["mac_panidcomp"].startswith("0b1:")
        and config.entry["mac_dstaddrmode"].startswith("0b10:")
        and config.entry["nwk_dstshortaddr"] is not None
    ):
        config.entry["der_same_macnwkdst"] = "Same MAC/NWK Dst: {}".format(
            config.entry["mac_dstshortaddr"]
            == config.entry["nwk_dstshortaddr"],
        )

    # Check whether the MAC and NWK Source is the same or not
    if (
        config.entry["mac_frametype"].startswith("0b001:")
        and config.entry["mac_panidcomp"].startswith("0b1:")
        and config.entry["mac_srcaddrmode"].startswith("0b10:")
        and config.entry["nwk_srcshortaddr"] is not None
    ):
        config.entry["der_same_macnwksrc"] = "Same MAC/NWK Src: {}".format(
            config.entry["mac_srcshortaddr"]
            == config.entry["nwk_srcshortaddr"],
        )


def derive_transmission_type():
    # Check whether this is a single-hop or a multi-hop transmission
    if (
        config.entry["mac_frametype"].startswith("0b010:")
        or config.entry["mac_frametype"].startswith("0b000:")
        or config.entry["mac_frametype"].startswith("0b011:")
    ):
        config.entry["der_tx_type"] = "Single-Hop Transmission"
    elif config.entry["nwk_radius"] is not None:
        if config.entry["nwk_radius"] > 1:
            config.entry["der_tx_type"] = "Multi-Hop Transmission"
        elif config.entry["nwk_radius"] == 1:
            if (
                config.entry["der_same_macnwksrc"]
                == "Same MAC/NWK Src: True"
            ):
                config.entry["der_tx_type"] = "Single-Hop Transmission"
            elif (
                config.entry["der_same_macnwksrc"]
                == "Same MAC/NWK Src: False"
            ):
                config.entry["der_tx_type"] = "Multi-Hop Transmission"


def derive_logical_device_types():
    if config.entry["mac_frametype"].startswith("0b000:"):
        # Only FFDs transmit beacons
        panid = config.entry["mac_srcpanid"]
        shortaddr = None
        extendedaddr = None
        if config.entry["mac_srcaddrmode"].startswith("0b10:"):
            shortaddr = config.entry["mac_srcshortaddr"]
        elif config.entry["mac_srcaddrmode"].startswith("0b11:"):
            extendedaddr = config.entry["mac_srcextendedaddr"]
        macdevtype = "Full-Function Device"
        nwkdevtype = None
        if (
            config.entry["nwk_beacon_devdepth"] == 0
            and config.entry["mac_beacon_pancoord"].startswith("0b1:")
        ):
            # Zigbee Coordinators are always PAN Coordinators with zero depth
            nwkdevtype = "Zigbee Coordinator"
        elif (
            config.entry["nwk_beacon_devdepth"] > 0
            and config.entry["mac_beacon_pancoord"].startswith("0b0:")
        ):
            # Zigbee Routers transmit beacons with depth greater than zero
            nwkdevtype = "Zigbee Router"
        # Update the stored device types
        config.update_devtypes(
            panid,
            shortaddr,
            extendedaddr,
            macdevtype,
            nwkdevtype,
        )
    elif config.entry["mac_frametype"].startswith("0b011:"):
        if config.entry["mac_cmd_id"].startswith("0x01:"):
            # The receivers of Association Requests are always FFDs
            panid = config.entry["mac_dstpanid"]
            shortaddr = None
            extendedaddr = None
            if config.entry["mac_dstaddrmode"].startswith("0b10:"):
                shortaddr = config.entry["mac_dstshortaddr"]
            elif config.entry["mac_dstaddrmode"].startswith("0b11:"):
                extendedaddr = config.entry["mac_dstextendedaddr"]
            macdevtype = "Full-Function Device"
            nwkdevtype = None
            if shortaddr is not None:
                if shortaddr == "0x0000":
                    nwkdevtype = "Zigbee Coordinator"
                else:
                    nwkdevtype = "Zigbee Router"
            # Update the stored device types
            config.update_devtypes(
                panid,
                shortaddr,
                extendedaddr,
                macdevtype,
                nwkdevtype,
            )

            # The transmitters of Association Requests always include
            # their extended address as well as their MAC device type
            panid = config.entry["mac_dstpanid"]
            shortaddr = None
            extendedaddr = config.entry["mac_srcextendedaddr"]
            macdevtype = None
            nwkdevtype = None
            if config.entry["mac_assocreq_devtype"].startswith("0b1:"):
                # Zigbee Coordinators do not transmit association requests
                macdevtype = "Full-Function Device"
                nwkdevtype = "Zigbee Router"
            elif config.entry["mac_assocreq_devtype"].startswith("0b0:"):
                # All RFDs are Zigbee End Devices
                macdevtype = "Reduced-Function Device"
                nwkdevtype = "Zigbee End Device"
            # Update the stored device types
            config.update_devtypes(
                panid,
                shortaddr,
                extendedaddr,
                macdevtype,
                nwkdevtype,
            )
        elif config.entry["mac_cmd_id"].startswith("0x02:"):
            # The transmitters of Association Responses are always FFDs
            panid = config.entry["mac_dstpanid"]
            shortaddr = None
            extendedaddr = None
            if config.entry["mac_srcaddrmode"].startswith("0b10:"):
                shortaddr = config.entry["mac_srcshortaddr"]
            elif config.entry["mac_srcaddrmode"].startswith("0b11:"):
                extendedaddr = config.entry["mac_srcextendedaddr"]
            macdevtype = "Full-Function Device"
            nwkdevtype = None
            if shortaddr is not None:
                if shortaddr == "0x0000":
                    nwkdevtype = "Zigbee Coordinator"
                else:
                    nwkdevtype = "Zigbee Router"
            # Update the stored device types
            config.update_devtypes(
                panid,
                shortaddr,
                extendedaddr,
                macdevtype,
                nwkdevtype,
            )
        elif config.entry["mac_cmd_id"].startswith("0x04:"):
            # The receivers of Data Requests are always FFDs
            panid = config.entry["mac_dstpanid"]
            shortaddr = None
            extendedaddr = None
            if config.entry["mac_dstaddrmode"].startswith("0b10:"):
                shortaddr = config.entry["mac_dstshortaddr"]
            elif config.entry["mac_dstaddrmode"].startswith("0b11:"):
                extendedaddr = config.entry["mac_dstextendedaddr"]
            macdevtype = "Full-Function Device"
            nwkdevtype = None
            if shortaddr is not None:
                if shortaddr == "0x0000":
                    nwkdevtype = "Zigbee Coordinator"
                else:
                    nwkdevtype = "Zigbee Router"
            # Update the stored device types
            config.update_devtypes(
                panid,
                shortaddr,
                extendedaddr,
                macdevtype,
                nwkdevtype,
            )

            # Only RFDs use their short addresses to transmit Data Requests
            if config.entry["mac_srcaddrmode"].startswith("0b10:"):
                if config.entry["mac_panidcomp"].startswith("0b0:"):
                    panid = config.entry["mac_srcpanid"]
                else:
                    panid = config.entry["mac_dstpanid"]
                shortaddr = config.entry["mac_srcshortaddr"]
                extendedaddr = None
                macdevtype = "Reduced-Function Device"
                nwkdevtype = "Zigbee End Device"
                # Update the stored device types
                config.update_devtypes(
                    panid,
                    shortaddr,
                    extendedaddr,
                    macdevtype,
                    nwkdevtype,
                )
        elif config.entry["mac_cmd_id"].startswith("0x08:"):
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
            # Update the stored device types
            config.update_devtypes(
                panid,
                shortaddr,
                extendedaddr,
                macdevtype,
                nwkdevtype,
            )

            # The receiver of the Coordinator Realignment is always an RFD
            panid = config.entry["mac_realign_panid"]
            shortaddr = config.entry["mac_realign_shortaddr"]
            extendedaddr = config.entry["mac_dstextendedaddr"]
            macdevtype = "Reduced-Function Device"
            nwkdevtype = "Zigbee End Device"
            # Update the stored device types
            config.update_devtypes(
                panid,
                shortaddr,
                extendedaddr,
                macdevtype,
                nwkdevtype,
            )
    elif (
        config.entry["mac_frametype"].startswith("0b001:")
        and config.entry["mac_panidcomp"].startswith("0b1:")
    ):
        if (
            config.entry["nwk_frametype"].startswith("0b01:")
            and config.entry["nwk_dstshortaddr"] == "0xfffc"
            and config.entry["der_tx_type"] == "Single-Hop Transmission"
        ):
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
            # Update the stored device types
            config.update_devtypes(
                panid,
                shortaddr,
                extendedaddr,
                macdevtype,
                nwkdevtype,
            )
        elif (
            config.entry["nwk_frametype"].startswith("0b01:")
            and config.entry["nwk_cmd_payloadlength"] == 3
            and config.entry["der_tx_type"] == "Single-Hop Transmission"
        ):
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
            # Update the stored device types
            config.update_devtypes(
                panid,
                shortaddr,
                extendedaddr,
                macdevtype,
                nwkdevtype,
            )
        elif (
            config.entry["nwk_srcshortaddr"] == "0x0000"
            or config.entry["nwk_dstshortaddr"] == "0x0000"
        ):
            # Zigbee Coordinators always use 0x0000 as their short address
            panid = config.entry["mac_dstpanid"]
            shortaddr = "0x0000"
            extendedaddr = None
            macdevtype = "Full-Function Device"
            nwkdevtype = "Zigbee Coordinator"
            # Update the stored device types
            config.update_devtypes(
                panid,
                shortaddr,
                extendedaddr,
                macdevtype,
                nwkdevtype,
            )


def derive_address_types():
    if (
        config.entry["mac_frametype"].startswith("0b001:")
        and not config.entry["mac_panidcomp"].startswith("0b1:")
    ):
        # Ignore Inter-PAN packets
        return

    # Derive the MAC Destination Type
    if config.entry["mac_dstaddrmode"].startswith("0b10:"):
        panid = config.entry["mac_dstpanid"]
        shortaddr = config.entry["mac_dstshortaddr"]
        extendedaddr = config.get_extendedaddr(panid, shortaddr)
        if shortaddr == "0xffff":
            config.entry["der_mac_dsttype"] = "MAC Dst Type: Broadcast"
        else:
            config.entry["der_mac_dsttype"] = "MAC Dst Type: {}".format(
                config.get_nwkdevtype(panid, shortaddr, extendedaddr),
            )
        config.entry["der_mac_dstpanid"] = panid
        config.entry["der_mac_dstshortaddr"] = shortaddr
        config.entry["der_mac_dstextendedaddr"] = extendedaddr

    # Derive the MAC Source Type
    if config.entry["mac_srcaddrmode"].startswith("0b10:"):
        if config.entry["mac_panidcomp"].startswith("0b1:"):
            panid = config.entry["mac_dstpanid"]
        else:
            panid = config.entry["mac_srcpanid"]
        shortaddr = config.entry["mac_srcshortaddr"]
        extendedaddr = config.get_extendedaddr(panid, shortaddr)
        config.entry["der_mac_srctype"] = "MAC Src Type: {}".format(
            config.get_nwkdevtype(panid, shortaddr, extendedaddr),
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
            extendedaddr = config.get_extendedaddr(panid, shortaddr)
        if shortaddr == "0xffff":
            config.entry["der_nwk_dsttype"] = "NWK Dst Type: All devices"
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
        else:
            config.entry["der_nwk_dsttype"] = "NWK Dst Type: {}".format(
                config.get_nwkdevtype(panid, shortaddr, extendedaddr),
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
            extendedaddr = config.get_extendedaddr(panid, shortaddr)
        config.entry["der_nwk_srctype"] = "NWK Src Type: {}".format(
            config.get_nwkdevtype(panid, shortaddr, extendedaddr),
        )
        config.entry["der_nwk_srcpanid"] = panid
        config.entry["der_nwk_srcshortaddr"] = shortaddr
        config.entry["der_nwk_srcextendedaddr"] = extendedaddr


def derive_info():
    """Derive additional information from the parsed packet."""
    extract_network_identifiers()
    extract_short_addresses()
    extract_extended_addresses()
    map_addresses()
    extract_pairs()
    compare_short_addresses()
    derive_transmission_type()
    derive_logical_device_types()
    derive_address_types()
