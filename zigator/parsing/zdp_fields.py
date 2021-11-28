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

from scapy.all import (
    ZDPActiveEPReq,
    ZDPDeviceAnnce,
    ZigbeeDeviceProfile,
)

from .. import config


APC_STATES = {
    0: "0b0: The sender is not capable of becoming a PAN coordinator",
    1: "0b1: The sender is capable of becoming a PAN coordinator",
}

DEVICE_TYPES = {
    0: "0b0: Reduced-Function Device",
    1: "0b1: Full-Function Device",
}

POWER_SOURCES = {
    0: "0b0: The sender is not a mains-powered device",
    1: "0b1: The sender is a mains-powered device",
}

RXIDLE_STATES = {
    0: "0b0: Disables the receiver to conserve power when idle",
    1: "0b1: Does not disable the receiver to conserve power",
}

SECURITY_CAPABILITIES = {
    0: "0b0: Cannot transmit and receive secure MAC frames",
    1: "0b1: Can transmit and receive secure MAC frames",
}

ALLOCADDR_STATES = {
    0: "0b0: Does not request a short address",
    1: "0b1: Requests a short address",
}


def zdp_activeepreq(pkt):
    # NWK Address field (2 bytes)
    config.entry["zdp_activeepreq_nwkaddr"] = "0x{:04x}".format(
        pkt[ZDPActiveEPReq].nwk_addr,
    )

    # ZDP Active_EP_req commands do not contain any other fields
    if len(bytes(pkt[ZDPActiveEPReq].payload)) != 0:
        config.entry["error_msg"] = "Unexpected payload"
        return


def zdp_deviceannce(pkt):
    # NWK Address field (2 bytes)
    config.entry["zdp_deviceannce_nwkaddr"] = "0x{:04x}".format(
        pkt[ZDPDeviceAnnce].nwk_addr,
    )

    # IEEE Address field (8 bytes)
    config.entry["zdp_deviceannce_ieeeaddr"] = format(
        pkt[ZDPDeviceAnnce].ieee_addr,
        "016x",
    )

    # Capability Information field (1 byte)
    # Alternate PAN Coordinator subfield (1 bit)
    if not (
        config.set_entry(
            "zdp_deviceannce_apc",
            pkt[ZDPDeviceAnnce].alternate_pan_coordinator,
            APC_STATES,
        )
    ):
        config.entry["error_msg"] = "Unknown APC state"
        return
    # Device Type subfield (1 bit)
    if not (
        config.set_entry(
            "zdp_deviceannce_devtype",
            pkt[ZDPDeviceAnnce].device_type,
            DEVICE_TYPES,
        )
    ):
        config.entry["error_msg"] = "Unknown device type"
        return
    # Power Source subfield (1 bit)
    if not (
        config.set_entry(
            "zdp_deviceannce_powsrc",
            pkt[ZDPDeviceAnnce].power_source,
            POWER_SOURCES,
        )
    ):
        config.entry["error_msg"] = "Unknown power source"
        return
    # Receiver On When Idle subfield (1 bit)
    if not (
        config.set_entry(
            "zdp_deviceannce_rxidle",
            pkt[ZDPDeviceAnnce].receiver_on_when_idle,
            RXIDLE_STATES,
        )
    ):
        config.entry["error_msg"] = "Unknown RX state when idle"
        return
    # Security Capability subfield (1 bit)
    if not (
        config.set_entry(
            "zdp_deviceannce_seccap",
            pkt[ZDPDeviceAnnce].security_capability,
            SECURITY_CAPABILITIES,
        )
    ):
        config.entry["error_msg"] = "Unknown MAC security capability"
        return
    # Allocate Address subfield (1 bit)
    if not (
        config.set_entry(
            "zdp_deviceannce_allocaddr",
            pkt[ZDPDeviceAnnce].allocate_address,
            ALLOCADDR_STATES,
        )
    ):
        config.entry["error_msg"] = "Unknown address allocation"
        return

    # ZDP Device_annce commands do not contain any other fields
    if len(bytes(pkt[ZDPDeviceAnnce].payload)) != 0:
        config.entry["error_msg"] = "Unexpected payload"
        return


def zdp_fields(pkt):
    """Parse Zigbee Device Profile fields."""
    # Transaction Sequence Number field (1 byte)
    config.entry["zdp_seqnum"] = pkt[ZigbeeDeviceProfile].trans_seqnum

    # Transaction Data field (variable)
    if config.entry["aps_cluster_id"].startswith("0x0005:"):
        if pkt.haslayer(ZDPActiveEPReq):
            zdp_activeepreq(pkt)
        else:
            config.entry["error_msg"] = (
                "There are no ZDP Active_EP_req fields"
            )
            return
    elif config.entry["aps_cluster_id"].startswith("0x0013:"):
        if pkt.haslayer(ZDPDeviceAnnce):
            zdp_deviceannce(pkt)
        else:
            config.entry["error_msg"] = "There are no ZDP Device_annce fields"
            return
    else:
        config.entry["warning_msg"] = "Unknown ZDP transaction data"
