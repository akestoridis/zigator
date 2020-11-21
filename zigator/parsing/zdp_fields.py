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

from scapy.all import ZigbeeDeviceProfile

from .. import config


def zdp_fields(pkt):
    """Parse Zigbee Device Profile fields."""
    # Transaction Sequence Number field (1 byte)
    config.entry["zdp_seqnum"] = pkt[ZigbeeDeviceProfile].trans_seqnum

    # Transaction Data field (variable)
    # TODO
