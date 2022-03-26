# Copyright (C) 2021-2022 Dimitrios-Georgios Akestoridis
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

"""
Enumerations for the ``zigator`` package.
"""

from enum import (
    Enum,
    IntEnum,
    auto,
)


class Message(IntEnum):
    RETURN = auto()
    DEBUG = auto()
    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    CRITICAL = auto()
    PCAP = auto()
    PKT = auto()
    NETWORK_KEYS = auto()
    LINK_KEYS = auto()
    NETWORKS = auto()
    SHORT_ADDRESSES = auto()
    EXTENDED_ADDRESSES = auto()
    PAIRS = auto()


class Protocol(str, Enum):
    ZIGBEE = "zigbee"
    THREAD = "thread"
    UDP = "udp"
    SLL = "sll"


class Subcommand(str, Enum):
    PRINT_CONFIG = "print-config"
    ADD_CONFIG_ENTRY = "add-config-entry"
    RM_CONFIG_ENTRY = "rm-config-entry"
    PARSE = "parse"
    ANALYZE = "analyze"
    VISUALIZE = "visualize"
    TRAIN = "train"
    INJECT = "inject"
    ATUSB = "atusb"
    WIDS = "wids"


class Table(str, Enum):
    ZIGBEE_PACKETS = "zigbee_packets"
    THREAD_PACKETS = "thread_packets"
    BASIC_INFORMATION = "basic_information"
    BATTERY_PERCENTAGES = "battery_percentages"
    EVENTS = "events"
