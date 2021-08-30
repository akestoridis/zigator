# Copyright (C) 2021 Dimitrios-Georgios Akestoridis
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

import cherrypy
import glob
import logging
import os
import psutil
import sqlite3
import string
import time

from datetime import datetime

from .. import config

SENSOR_ID = None
OUTPUT_DIRECTORY = None
DB_FILEPATH = None


@cherrypy.expose
class NetworkKeysService(object):
    @cherrypy.tools.json_out()
    def GET(self):
        return [
            key.hex() for key in config.network_keys.values()
        ]

    @cherrypy.tools.json_in()
    def POST(self):
        post_time = time.time()
        for key_index, key_hex in enumerate(cherrypy.request.json):
            if not (len(key_hex) == 32
                    and all(d in string.hexdigits for d in key_hex)):
                raise cherrypy.HTTPError(
                    500,
                    message="Use 32 hexadecimal digits to represent each key")
            key_bytes = bytes.fromhex(key_hex)
            key_type = "network"
            key_name = "_posted_{:.6f}_{}".format(post_time, key_index)
            return_msg = config.add_new_key(key_bytes, key_type, key_name)
            if return_msg is not None:
                raise cherrypy.HTTPError(500, message=return_msg)


@cherrypy.expose
class LinkKeysService(object):
    @cherrypy.tools.json_out()
    def GET(self):
        return [
            key.hex() for key in config.link_keys.values()
        ]

    @cherrypy.tools.json_in()
    def POST(self):
        post_time = time.time()
        for key_index, key_hex in enumerate(cherrypy.request.json):
            if not (len(key_hex) == 32
                    and all(d in string.hexdigits for d in key_hex)):
                raise cherrypy.HTTPError(
                    500,
                    message="Use 32 hexadecimal digits to represent each key")
            key_bytes = bytes.fromhex(key_hex)
            key_type = "link"
            key_name = "_posted_{:.6f}_{}".format(post_time, key_index)
            return_msg = config.add_new_key(key_bytes, key_type, key_name)
            if return_msg is not None:
                raise cherrypy.HTTPError(500, message=return_msg)


@cherrypy.expose
class UtilizationService(object):
    @cherrypy.tools.json_out()
    def GET(self):
        return {
            "cpuPercent": psutil.cpu_percent(interval=1, percpu=False),
            "memoryPercent": psutil.virtual_memory().percent,
            "diskPercent": psutil.disk_usage("/").percent,
            "epochTimestamp": "{:.6f}".format(time.time()),
        }


@cherrypy.expose
class PcapFilesService(object):
    @cherrypy.tools.json_out()
    def GET(self):
        return [
            os.path.basename(filepath) for filepath in glob.glob(os.path.join(
                OUTPUT_DIRECTORY,
                "*.{}.pcap.zip".format(SENSOR_ID)))
        ]


@cherrypy.expose
class DownloadService(object):
    def GET(self, basename):
        valid_basenames = [
            os.path.basename(filepath) for filepath in glob.glob(os.path.join(
                OUTPUT_DIRECTORY,
                "*.{}.pcap.zip".format(SENSOR_ID)))
        ]
        if basename in valid_basenames:
            return cherrypy.lib.static.serve_file(
                os.path.join(OUTPUT_DIRECTORY, basename),
                "application/x-download",
                "attachment")


@cherrypy.expose
class NetworksService(object):
    @cherrypy.tools.json_out()
    def GET(self):
        networks_list = []
        for panid in config.networks.keys():
            earliest_timestamp = None
            if config.networks[panid]["earliest"] is not None:
                earliest_timestamp = "{:.6f}".format(
                    config.networks[panid]["earliest"])
            latest_timestamp = None
            if config.networks[panid]["latest"] is not None:
                latest_timestamp = "{:.6f}".format(
                    config.networks[panid]["latest"])
            networks_list.append({
                "panid": panid,
                "epidset": ";".join(
                    epid for epid in sorted(list(
                        config.networks[panid]["epidset"]
                    ))),
                "earliest": earliest_timestamp,
                "latest": latest_timestamp,
            })
        return networks_list


@cherrypy.expose
class ShortAddressesService(object):
    @cherrypy.tools.json_out()
    def GET(self):
        short_addresses_list = []
        for (panid, saddr) in config.short_addresses.keys():
            earliest_timestamp = None
            if config.short_addresses[(panid, saddr)]["earliest"] is not None:
                earliest_timestamp = "{:.6f}".format(
                    config.short_addresses[(panid, saddr)]["earliest"])
            latest_timestamp = None
            if config.short_addresses[(panid, saddr)]["latest"] is not None:
                latest_timestamp = "{:.6f}".format(
                    config.short_addresses[(panid, saddr)]["latest"])
            short_addresses_list.append({
                "panid": panid,
                "shortaddr": saddr,
                "altset": ";".join(
                    extendedaddr for extendedaddr in sorted(list(
                        config.short_addresses[(panid, saddr)]["altset"]
                    ))),
                "macset": ";".join(
                    macdevtype for macdevtype in sorted(list(
                        config.short_addresses[(panid, saddr)]["macset"]
                    ))),
                "nwkset": ";".join(
                    nwkdevtype for nwkdevtype in sorted(list(
                        config.short_addresses[(panid, saddr)]["nwkset"]
                    ))),
                "earliest": earliest_timestamp,
                "latest": latest_timestamp,
            })
        return short_addresses_list


@cherrypy.expose
class ExtendedAddressesService(object):
    @cherrypy.tools.json_out()
    def GET(self):
        extended_addresses_list = []
        for eaddr in config.extended_addresses.keys():
            earliest_timestamp = None
            if config.extended_addresses[eaddr]["earliest"] is not None:
                earliest_timestamp = "{:.6f}".format(
                    config.extended_addresses[eaddr]["earliest"])
            latest_timestamp = None
            if config.extended_addresses[eaddr]["latest"] is not None:
                latest_timestamp = "{:.6f}".format(
                    config.extended_addresses[eaddr]["latest"])
            extended_addresses_list.append({
                "extendedaddr": eaddr,
                "altset": ";".join(
                    str(localaddr) for localaddr in sorted(list(
                        config.extended_addresses[eaddr]["altset"]
                    ))),
                "macset": ";".join(
                    macdevtype for macdevtype in sorted(list(
                        config.extended_addresses[eaddr]["macset"]
                    ))),
                "nwkset": ";".join(
                    nwkdevtype for nwkdevtype in sorted(list(
                        config.extended_addresses[eaddr]["nwkset"]
                    ))),
                "earliest": earliest_timestamp,
                "latest": latest_timestamp,
            })
        return extended_addresses_list


@cherrypy.expose
class PairsService(object):
    @cherrypy.tools.json_out()
    def GET(self):
        pairs_list = []
        for (panid, saddr, daddr) in config.pairs.keys():
            pairs_list.append({
                "panid": panid,
                "srcaddr": saddr,
                "dstaddr": daddr,
                "earliest": "{:.6f}".format(
                    config.pairs[(panid, saddr, daddr)]["earliest"]),
                "latest": "{:.6f}".format(
                    config.pairs[(panid, saddr, daddr)]["latest"]),
            })
        return pairs_list


@cherrypy.expose
class PacketCountersService(object):
    @cherrypy.tools.json_out()
    def GET(self, last=None):
        with sqlite3.connect(DB_FILEPATH) as connection:
            connection.text_factory = str
            cursor = connection.cursor()
            pending_group = (
                datetime.fromtimestamp(time.time())
                .replace(second=0, microsecond=0).timestamp()
            )
            if last is None:
                start_group = 0.0
            else:
                start_group = (
                    datetime.fromtimestamp(float(last) + 60)
                    .replace(second=0, microsecond=0).timestamp()
                )
            cursor.execute(
                "SELECT pkt_time, der_mac_srcpanid, der_mac_srcshortaddr "
                "FROM basic_information "
                "WHERE error_msg IS NULL "
                "AND der_mac_srcpanid IS NOT NULL "
                "AND pkt_time>=$1 "
                "AND pkt_time<$2 "
                "ORDER BY pkt_time",
                (start_group, pending_group))
            result = cursor.fetchall()
            packet_counters = []
            tmp_dict = {}
            tmp_group = None
            for (pkt_time, srcpanid, srcshortaddr) in result:
                pkt_group = (
                    datetime.fromtimestamp(pkt_time)
                    .replace(second=0, microsecond=0).timestamp()
                )

                if tmp_group is None:
                    if pkt_group >= pending_group:
                        break
                    else:
                        tmp_group = pkt_group

                if pkt_group == tmp_group:
                    if srcpanid in tmp_dict.keys():
                        tmp_dict[srcpanid]["counter"] += 1
                    else:
                        tmp_dict[srcpanid] = {
                            "counter": 1,
                            "dev": {},
                        }

                    if srcshortaddr in tmp_dict[srcpanid]["dev"].keys():
                        tmp_dict[srcpanid]["dev"][srcshortaddr] += 1
                    elif srcshortaddr is not None:
                        tmp_dict[srcpanid]["dev"][srcshortaddr] = 1
                elif pkt_group > tmp_group:
                    tmp_pan_list = []
                    for panid in tmp_dict.keys():
                        tmp_dev_list = []
                        for shortaddr in tmp_dict[panid]["dev"].keys():
                            tmp_dev_list.append({
                                "srcshortaddr": shortaddr,
                                "counter": tmp_dict[panid]["dev"][shortaddr],
                            })
                        tmp_pan_list.append({
                            "srcpanid": panid,
                            "counter": tmp_dict[panid]["counter"],
                            "devicePacketCounters": tmp_dev_list,
                        })
                    packet_counters.append({
                        "epochTimestamp": "{:.6f}".format(tmp_group),
                        "panPacketCounters": tmp_pan_list,
                    })

                    tmp_dict = {}
                    tmp_group += 60
                    while tmp_group < pkt_group:
                        tmp_group += 60
                    if tmp_group != pkt_group:
                        raise ValueError("Unexpected group value")
                    elif tmp_group >= pending_group:
                        break

                    tmp_dict[srcpanid] = {
                        "counter": 1,
                        "dev": {},
                    }
                    if srcshortaddr is not None:
                        tmp_dict[srcpanid]["dev"][srcshortaddr] = 1
                else:
                    raise ValueError("Unexpected packet timestamp")
            if tmp_group is not None:
                if tmp_dict != {} and tmp_group < pending_group:
                    tmp_pan_list = []
                    for panid in tmp_dict.keys():
                        tmp_dev_list = []
                        for shortaddr in tmp_dict[panid]["dev"].keys():
                            tmp_dev_list.append({
                                "srcshortaddr": shortaddr,
                                "counter": tmp_dict[panid]["dev"][shortaddr],
                            })
                        tmp_pan_list.append({
                            "srcpanid": panid,
                            "counter": tmp_dict[panid]["counter"],
                            "devicePacketCounters": tmp_dev_list,
                        })
                    packet_counters.append({
                        "epochTimestamp": "{:.6f}".format(tmp_group),
                        "panPacketCounters": tmp_pan_list,
                    })
            return packet_counters


@cherrypy.expose
class ByteCountersService(object):
    @cherrypy.tools.json_out()
    def GET(self, last=None):
        with sqlite3.connect(DB_FILEPATH) as connection:
            connection.text_factory = str
            cursor = connection.cursor()
            pending_group = (
                datetime.fromtimestamp(time.time())
                .replace(second=0, microsecond=0).timestamp()
            )
            if last is None:
                start_group = 0.0
            else:
                start_group = (
                    datetime.fromtimestamp(float(last) + 60)
                    .replace(second=0, microsecond=0).timestamp()
                )
            cursor.execute(
                "SELECT pkt_time, phy_length, "
                "der_mac_srcpanid, der_mac_srcshortaddr "
                "FROM basic_information "
                "WHERE error_msg IS NULL "
                "AND phy_length IS NOT NULL "
                "AND der_mac_srcpanid IS NOT NULL "
                "AND pkt_time>=$1 "
                "AND pkt_time<$2 "
                "ORDER BY pkt_time",
                (start_group, pending_group))
            result = cursor.fetchall()
            byte_counters = []
            tmp_dict = {}
            tmp_group = None
            for (pkt_time, num_bytes, srcpanid, srcshortaddr) in result:
                pkt_group = (
                    datetime.fromtimestamp(pkt_time)
                    .replace(second=0, microsecond=0).timestamp()
                )

                if tmp_group is None:
                    if pkt_group >= pending_group:
                        break
                    else:
                        tmp_group = pkt_group

                if pkt_group == tmp_group:
                    if srcpanid in tmp_dict.keys():
                        tmp_dict[srcpanid]["counter"] += num_bytes
                    else:
                        tmp_dict[srcpanid] = {
                            "counter": num_bytes,
                            "dev": {},
                        }

                    if srcshortaddr in tmp_dict[srcpanid]["dev"].keys():
                        tmp_dict[srcpanid]["dev"][srcshortaddr] += num_bytes
                    elif srcshortaddr is not None:
                        tmp_dict[srcpanid]["dev"][srcshortaddr] = num_bytes
                elif pkt_group > tmp_group:
                    tmp_pan_list = []
                    for panid in tmp_dict.keys():
                        tmp_dev_list = []
                        for shortaddr in tmp_dict[panid]["dev"].keys():
                            tmp_dev_list.append({
                                "srcshortaddr": shortaddr,
                                "counter": tmp_dict[panid]["dev"][shortaddr],
                            })
                        tmp_pan_list.append({
                            "srcpanid": panid,
                            "counter": tmp_dict[panid]["counter"],
                            "deviceByteCounters": tmp_dev_list,
                        })
                    byte_counters.append({
                        "epochTimestamp": "{:.6f}".format(tmp_group),
                        "panByteCounters": tmp_pan_list,
                    })

                    tmp_dict = {}
                    tmp_group += 60
                    while tmp_group < pkt_group:
                        tmp_group += 60
                    if tmp_group != pkt_group:
                        raise ValueError("Unexpected group value")
                    elif tmp_group >= pending_group:
                        break

                    tmp_dict[srcpanid] = {
                        "counter": num_bytes,
                        "dev": {},
                    }
                    if srcshortaddr is not None:
                        tmp_dict[srcpanid]["dev"][srcshortaddr] = num_bytes
                else:
                    raise ValueError("Unexpected packet timestamp")
            if tmp_group is not None:
                if tmp_dict != {} and tmp_group < pending_group:
                    tmp_pan_list = []
                    for panid in tmp_dict.keys():
                        tmp_dev_list = []
                        for shortaddr in tmp_dict[panid]["dev"].keys():
                            tmp_dev_list.append({
                                "srcshortaddr": shortaddr,
                                "counter": tmp_dict[panid]["dev"][shortaddr],
                            })
                        tmp_pan_list.append({
                            "srcpanid": panid,
                            "counter": tmp_dict[panid]["counter"],
                            "deviceByteCounters": tmp_dev_list,
                        })
                    byte_counters.append({
                        "epochTimestamp": "{:.6f}".format(tmp_group),
                        "panByteCounters": tmp_pan_list,
                    })
            return byte_counters


@cherrypy.expose
class MACSeqnumsService(object):
    @cherrypy.tools.json_out()
    def GET(self, last=None):
        with sqlite3.connect(DB_FILEPATH) as connection:
            connection.text_factory = str
            cursor = connection.cursor()
            if last is None:
                cursor.execute(
                    "SELECT pkt_time, mac_seqnum, "
                    "der_mac_srcpanid, der_mac_srcshortaddr "
                    "FROM basic_information "
                    "WHERE error_msg IS NULL "
                    "AND (mac_frametype=$1 OR mac_frametype=$2) "
                    "AND mac_seqnum IS NOT NULL "
                    "AND der_mac_srcpanid IS NOT NULL "
                    "AND der_mac_srcshortaddr IS NOT NULL "
                    "ORDER BY pkt_time",
                    ("0b001: MAC Data", "0b011: MAC Command"))
            else:
                cursor.execute(
                    "SELECT pkt_time, mac_seqnum, "
                    "der_mac_srcpanid, der_mac_srcshortaddr "
                    "FROM basic_information "
                    "WHERE error_msg IS NULL "
                    "AND (mac_frametype=$1 OR mac_frametype=$2) "
                    "AND mac_seqnum IS NOT NULL "
                    "AND der_mac_srcpanid IS NOT NULL "
                    "AND der_mac_srcshortaddr IS NOT NULL "
                    "AND pkt_time>$3 "
                    "ORDER BY pkt_time",
                    ("0b001: MAC Data", "0b011: MAC Command", last))
            result = cursor.fetchall()
            mac_seqnums = []
            for (pkt_time, seqnum, srcpanid, srcshortaddr) in result:
                mac_seqnums.append({
                    "epochTimestamp": "{:.6f}".format(pkt_time),
                    "srcpanid": srcpanid,
                    "srcshortaddr": srcshortaddr,
                    "macSeqnum": seqnum,
                })
            return mac_seqnums


@cherrypy.expose
class BeaconSeqnumsService(object):
    @cherrypy.tools.json_out()
    def GET(self, last=None):
        with sqlite3.connect(DB_FILEPATH) as connection:
            connection.text_factory = str
            cursor = connection.cursor()
            if last is None:
                cursor.execute(
                    "SELECT pkt_time, mac_seqnum, "
                    "der_mac_srcpanid, der_mac_srcshortaddr "
                    "FROM basic_information "
                    "WHERE error_msg IS NULL "
                    "AND mac_frametype=$1 "
                    "AND mac_seqnum IS NOT NULL "
                    "AND der_mac_srcpanid IS NOT NULL "
                    "AND der_mac_srcshortaddr IS NOT NULL "
                    "ORDER BY pkt_time",
                    ("0b000: MAC Beacon",))
            else:
                cursor.execute(
                    "SELECT pkt_time, mac_seqnum, "
                    "der_mac_srcpanid, der_mac_srcshortaddr "
                    "FROM basic_information "
                    "WHERE error_msg IS NULL "
                    "AND mac_frametype=$1 "
                    "AND mac_seqnum IS NOT NULL "
                    "AND der_mac_srcpanid IS NOT NULL "
                    "AND der_mac_srcshortaddr IS NOT NULL "
                    "AND pkt_time>$2 "
                    "ORDER BY pkt_time",
                    ("0b000: MAC Beacon", last))
            result = cursor.fetchall()
            beacon_seqnums = []
            for (pkt_time, seqnum, srcpanid, srcshortaddr) in result:
                beacon_seqnums.append({
                    "epochTimestamp": "{:.6f}".format(pkt_time),
                    "srcpanid": srcpanid,
                    "srcshortaddr": srcshortaddr,
                    "beaconSeqnum": seqnum,
                })
            return beacon_seqnums


@cherrypy.expose
class NWKSeqnumsService(object):
    @cherrypy.tools.json_out()
    def GET(self, last=None):
        with sqlite3.connect(DB_FILEPATH) as connection:
            connection.text_factory = str
            cursor = connection.cursor()
            if last is None:
                cursor.execute(
                    "SELECT pkt_time, nwk_seqnum, "
                    "der_mac_srcpanid, der_mac_srcshortaddr "
                    "FROM basic_information "
                    "WHERE error_msg IS NULL "
                    "AND der_same_macnwksrc=$1 "
                    "AND nwk_seqnum IS NOT NULL "
                    "AND der_mac_srcpanid IS NOT NULL "
                    "AND der_mac_srcshortaddr IS NOT NULL "
                    "ORDER BY pkt_time",
                    ("Same MAC/NWK Src: True",))
            else:
                cursor.execute(
                    "SELECT pkt_time, nwk_seqnum, "
                    "der_mac_srcpanid, der_mac_srcshortaddr "
                    "FROM basic_information "
                    "WHERE error_msg IS NULL "
                    "AND der_same_macnwksrc=$1 "
                    "AND nwk_seqnum IS NOT NULL "
                    "AND der_mac_srcpanid IS NOT NULL "
                    "AND der_mac_srcshortaddr IS NOT NULL "
                    "AND pkt_time>$2 "
                    "ORDER BY pkt_time",
                    ("Same MAC/NWK Src: True", last))
            result = cursor.fetchall()
            nwk_seqnums = []
            for (pkt_time, seqnum, srcpanid, srcshortaddr) in result:
                nwk_seqnums.append({
                    "epochTimestamp": "{:.6f}".format(pkt_time),
                    "srcpanid": srcpanid,
                    "srcshortaddr": srcshortaddr,
                    "nwkSeqnum": seqnum,
                })
            return nwk_seqnums


@cherrypy.expose
class NWKAUXSeqnumsService(object):
    @cherrypy.tools.json_out()
    def GET(self, last=None):
        with sqlite3.connect(DB_FILEPATH) as connection:
            connection.text_factory = str
            cursor = connection.cursor()
            if last is None:
                cursor.execute(
                    "SELECT pkt_time, nwk_aux_framecounter, "
                    "der_mac_srcpanid, der_mac_srcshortaddr "
                    "FROM basic_information "
                    "WHERE error_msg IS NULL "
                    "AND nwk_aux_framecounter IS NOT NULL "
                    "AND der_mac_srcpanid IS NOT NULL "
                    "AND der_mac_srcshortaddr IS NOT NULL "
                    "ORDER BY pkt_time")
            else:
                cursor.execute(
                    "SELECT pkt_time, nwk_aux_framecounter, "
                    "der_mac_srcpanid, der_mac_srcshortaddr "
                    "FROM basic_information "
                    "WHERE error_msg IS NULL "
                    "AND nwk_aux_framecounter IS NOT NULL "
                    "AND der_mac_srcpanid IS NOT NULL "
                    "AND der_mac_srcshortaddr IS NOT NULL "
                    "AND pkt_time>$1 "
                    "ORDER BY pkt_time",
                    (last,))
            result = cursor.fetchall()
            nwkaux_seqnums = []
            for (pkt_time, seqnum, srcpanid, srcshortaddr) in result:
                nwkaux_seqnums.append({
                    "epochTimestamp": "{:.6f}".format(pkt_time),
                    "srcpanid": srcpanid,
                    "srcshortaddr": srcshortaddr,
                    "nwkauxSeqnum": seqnum,
                })
            return nwkaux_seqnums


@cherrypy.expose
class BatteryPercentagesService(object):
    @cherrypy.tools.json_out()
    def GET(self, last=None):
        with sqlite3.connect(DB_FILEPATH) as connection:
            connection.text_factory = str
            cursor = connection.cursor()
            if last is None:
                cursor.execute(
                    "SELECT pkt_time, srcpanid, srcshortaddr, percentage "
                    "FROM battery_percentages "
                    "ORDER BY pkt_time")
            else:
                cursor.execute(
                    "SELECT pkt_time, srcpanid, srcshortaddr, percentage "
                    "FROM battery_percentages "
                    "WHERE pkt_time>$1 "
                    "ORDER BY pkt_time",
                    (last,))
            result = cursor.fetchall()
            battery_percentages = []
            for (pkt_time, srcpanid, srcshortaddr, percentage) in result:
                battery_percentages.append({
                    "epochTimestamp": "{:.6f}".format(pkt_time),
                    "srcpanid": srcpanid,
                    "srcshortaddr": srcshortaddr,
                    "batteryPercentage": percentage,
                })
            return battery_percentages


@cherrypy.expose
class EventsService(object):
    @cherrypy.tools.json_out()
    def GET(self, last=None):
        with sqlite3.connect(DB_FILEPATH) as connection:
            connection.text_factory = str
            cursor = connection.cursor()
            if last is None:
                cursor.execute(
                    "SELECT pkt_time, description "
                    "FROM events "
                    "ORDER BY pkt_time")
            else:
                cursor.execute(
                    "SELECT pkt_time, description "
                    "FROM events "
                    "WHERE pkt_time>$1 "
                    "ORDER BY pkt_time",
                    (last,))
            result = cursor.fetchall()
            events = []
            for (pkt_time, description) in result:
                events.append({
                    "epochTimestamp": "{:.6f}".format(pkt_time),
                    "description": description,
                })
            return events


def start(sensor_id, output_directory, db_filepath, ipaddr, portnum):
    global SENSOR_ID
    global OUTPUT_DIRECTORY
    global DB_FILEPATH

    SENSOR_ID = sensor_id
    OUTPUT_DIRECTORY = output_directory
    DB_FILEPATH = db_filepath

    conf = {
        "/": {
            "request.dispatch": cherrypy.dispatch.MethodDispatcher(),
            "tools.response_headers.on": True,
            "tools.response_headers.headers": [
                ("Content-Type", "application/json"),
            ],
        },
    }

    cherrypy.tree.mount(
        NetworkKeysService(),
        "/api/network-keys",
        conf)
    cherrypy.tree.mount(
        LinkKeysService(),
        "/api/link-keys",
        conf)
    cherrypy.tree.mount(
        UtilizationService(),
        "/api/utilization",
        conf)
    cherrypy.tree.mount(
        PcapFilesService(),
        "/api/pcap-files",
        conf)
    cherrypy.tree.mount(
        DownloadService(),
        "/api/download",
        conf)
    cherrypy.tree.mount(
        NetworksService(),
        "/api/networks",
        conf)
    cherrypy.tree.mount(
        ShortAddressesService(),
        "/api/short-addresses",
        conf)
    cherrypy.tree.mount(
        ExtendedAddressesService(),
        "/api/extended-addresses",
        conf)
    cherrypy.tree.mount(
        PairsService(),
        "/api/pairs",
        conf)
    cherrypy.tree.mount(
        PacketCountersService(),
        "/api/packet-counters",
        conf)
    cherrypy.tree.mount(
        ByteCountersService(),
        "/api/byte-counters",
        conf)
    cherrypy.tree.mount(
        MACSeqnumsService(),
        "/api/mac-seqnums",
        conf)
    cherrypy.tree.mount(
        BeaconSeqnumsService(),
        "/api/beacon-seqnums",
        conf)
    cherrypy.tree.mount(
        NWKSeqnumsService(),
        "/api/nwk-seqnums",
        conf)
    cherrypy.tree.mount(
        NWKAUXSeqnumsService(),
        "/api/nwkaux-seqnums",
        conf)
    cherrypy.tree.mount(
        BatteryPercentagesService(),
        "/api/battery-percentages",
        conf)
    cherrypy.tree.mount(
        EventsService(),
        "/api/events",
        conf)

    cherrypy.config.update({
        "server.socket_host": ipaddr,
        "server.socket_port": portnum,
        "engine.autoreload.on": False,
        "log.screen": False,
        "log.access_file": "",
        "log.error_file": "",
    })
    cherrypy.log.access_log.propagate = False
    cherrypy.log.error_log.propagate = False

    cherrypy.engine.start()
    logging.info("Started a server at {}:{}".format(
        cherrypy.server.socket_host, cherrypy.server.socket_port))


def stop():
    cherrypy.engine.exit()
    logging.info("Stopped the server at {}:{}".format(
        cherrypy.server.socket_host, cherrypy.server.socket_port))
