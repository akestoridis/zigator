#!/usr/bin/env python3

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

import contextlib
import io
import os
import re
import sqlite3
import unittest
import zigator


DIR_PATH = os.path.dirname(os.path.abspath(__file__))


class TestIntegration(unittest.TestCase):
    def test_integration_info(self):
        """Test integration with INFO logging."""
        tmp_stdout = io.StringIO()
        with contextlib.redirect_stdout(tmp_stdout):
            with self.assertLogs(level="INFO") as cm:
                zigator.main([
                    "zigator",
                    "print-config",
                ])
        captured_output = tmp_stdout.getvalue().rstrip()
        self.assertEqual(len(cm.output), 2)
        self.assertTrue(re.search(
            r"^INFO:root:Started Zigator version "
            r"(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
            cm.output[0]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Printing the current configuration...$",
            cm.output[1]) is not None)
        config_list = captured_output.split("\n\n")
        self.assertEqual(len(config_list), 4)
        network_keys = config_list[0].split("\n")
        self.assertGreater(len(network_keys), 0)
        self.assertEqual(network_keys[0], "Network keys:")
        for i in range(1, len(network_keys)):
            self.assertGreater(len(network_keys[i]), 33)
            self.assertNotEqual(
                network_keys[i][:33],
                "11111111111111111111111111111111\t")
            self.assertNotEqual(
                network_keys[i][33:],
                "test_11111111111111111111111111111111")
        link_keys = config_list[1].split("\n")
        self.assertGreater(len(link_keys), 0)
        self.assertEqual(link_keys[0], "Link keys:")
        install_codes = config_list[2].split("\n")
        self.assertGreater(len(install_codes), 0)
        self.assertEqual(install_codes[0], "Install codes:")
        self.assertTrue(re.search(
            r"^Configuration directory: \".+zigator\"$",
            config_list[3]) is not None)

        with self.assertLogs(level="INFO") as cm:
            zigator.main([
                "zigator",
                "add-config-entry",
                "network-key",
                "11111111111111111111111111111111",
                "test_11111111111111111111111111111111",
            ])
        self.assertEqual(len(cm.output), 2)
        self.assertTrue(re.search(
            r"^INFO:root:Started Zigator version "
            r"(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
            cm.output[0]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Saved the network key "
            r"11111111111111111111111111111111 in the "
            r"\".+network-keys.tsv\" configuration file$",
            cm.output[1]) is not None)

        tmp_stdout = io.StringIO()
        with contextlib.redirect_stdout(tmp_stdout):
            with self.assertLogs(level="INFO") as cm:
                zigator.main([
                    "zigator",
                    "print-config",
                ])
        captured_output = tmp_stdout.getvalue().rstrip()
        self.assertEqual(len(cm.output), 2)
        self.assertTrue(re.search(
            r"^INFO:root:Started Zigator version "
            r"(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
            cm.output[0]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Printing the current configuration...$",
            cm.output[1]) is not None)
        config_list = captured_output.split("\n\n")
        self.assertEqual(len(config_list), 4)
        network_keys = config_list[0].split("\n")
        self.assertGreater(len(network_keys), 0)
        self.assertEqual(network_keys[0], "Network keys:")
        self.assertTrue(
            "11111111111111111111111111111111\t"
            "test_11111111111111111111111111111111" in network_keys)
        link_keys = config_list[1].split("\n")
        self.assertGreater(len(link_keys), 0)
        self.assertEqual(link_keys[0], "Link keys:")
        install_codes = config_list[2].split("\n")
        self.assertGreater(len(install_codes), 0)
        self.assertEqual(install_codes[0], "Install codes:")
        self.assertTrue(re.search(
            r"^Configuration directory: \".+zigator\"$",
            config_list[3]) is not None)

        pcap_directory = os.path.join(DIR_PATH, "data")
        db_filepath = os.path.join(DIR_PATH, "info-logging.db")
        with self.assertLogs(level="INFO") as cm:
            zigator.main([
                "zigator",
                "parse",
                pcap_directory,
                db_filepath,
            ])
        self.assertLoggingOutput(cm)

        connection = sqlite3.connect(db_filepath)
        connection.text_factory = str
        cursor = connection.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type=\"table\" "
            "ORDER BY name")
        self.assertEqual(
            cursor.fetchall(), [
                ("addresses",),
                ("devices",),
                ("networks",),
                ("packets",),
                ("pairs",)
            ])
        self.assertAddressesTable(cursor)
        self.assertDevicesTable(cursor)
        self.assertNetworksTable(cursor)
        self.assertPacketsTable(cursor)
        self.assertPairsTable(cursor)
        cursor.close()
        connection.close()

        with self.assertLogs(level="INFO") as cm:
            zigator.main([
                "zigator",
                "rm-config-entry",
                "network-key",
                "test_11111111111111111111111111111111",
            ])
        self.assertEqual(len(cm.output), 2)
        self.assertTrue(re.search(
            r"^INFO:root:Started Zigator version "
            r"(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
            cm.output[0]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Removed the "
            r"\"test_11111111111111111111111111111111\" network key "
            r"from the \".+network-keys.tsv\" configuration file$",
            cm.output[1]) is not None)

        tmp_stdout = io.StringIO()
        with contextlib.redirect_stdout(tmp_stdout):
            with self.assertLogs(level="INFO") as cm:
                zigator.main([
                    "zigator",
                    "print-config",
                ])
        captured_output = tmp_stdout.getvalue().rstrip()
        self.assertEqual(len(cm.output), 2)
        self.assertTrue(re.search(
            r"^INFO:root:Started Zigator version "
            r"(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
            cm.output[0]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Printing the current configuration...$",
            cm.output[1]) is not None)
        config_list = captured_output.split("\n\n")
        self.assertEqual(len(config_list), 4)
        network_keys = config_list[0].split("\n")
        self.assertGreater(len(network_keys), 0)
        self.assertEqual(network_keys[0], "Network keys:")
        for i in range(1, len(network_keys)):
            self.assertGreater(len(network_keys[i]), 33)
            self.assertNotEqual(
                network_keys[i][:33],
                "11111111111111111111111111111111\t")
            self.assertNotEqual(
                network_keys[i][33:],
                "test_11111111111111111111111111111111")
        link_keys = config_list[1].split("\n")
        self.assertGreater(len(link_keys), 0)
        self.assertEqual(link_keys[0], "Link keys:")
        install_codes = config_list[2].split("\n")
        self.assertGreater(len(install_codes), 0)
        self.assertEqual(install_codes[0], "Install codes:")
        self.assertTrue(re.search(
            r"^Configuration directory: \".+zigator\"$",
            config_list[3]) is not None)

    def assertLoggingOutput(self, cm):
        self.assertEqual(len(cm.output), 24)

        self.assertTrue(re.search(
            r"^INFO:root:Started Zigator version "
            r"(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
            cm.output[0]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Detected 3 pcap files in the \".+data\" directory$",
            cm.output[1]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:The pcap files will be parsed "
            r"by ([1-9]|[1-9][0-9]+) workers$",
            cm.output[2]) is not None)

        self.assertTrue(any(re.search(
            r"^INFO:root:Reading packets from the "
            r"\".+00-wrong-data-link-type.pcap\" file...$",
            log_msg) is not None for log_msg in cm.output[3:12]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 1 packets from the "
            r"\".+00-wrong-data-link-type.pcap\" file$",
            log_msg) is not None for log_msg in cm.output[3:12]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 1 out of the 3 pcap files$",
            log_msg) is not None for log_msg in cm.output[3:12]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Reading packets from the "
            r"\".+01-phy-testing.pcap\" file...$",
            log_msg) is not None for log_msg in cm.output[3:12]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 4 packets from the "
            r"\".+01-phy-testing.pcap\" file$",
            log_msg) is not None for log_msg in cm.output[3:12]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 2 out of the 3 pcap files$",
            log_msg) is not None for log_msg in cm.output[3:12]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Reading packets from the "
            r"\".+02-mac-testing.pcap\" file...$",
            log_msg) is not None for log_msg in cm.output[3:12]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 10 packets from the "
            r"\".+02-mac-testing.pcap\" file$",
            log_msg) is not None for log_msg in cm.output[3:12]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 3 out of the 3 pcap files$",
            log_msg) is not None for log_msg in cm.output[3:12]))

        self.assertTrue(re.search(
            r"^INFO:root:All ([1-9]|[1-9][0-9]+) workers "
            r"completed their tasks$",
            cm.output[12]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Sniffed 0 previously unknown network keys$",
            cm.output[13]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Sniffed 0 previously unknown link keys$",
            cm.output[14]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Discovered the EPID of 1 networks$",
            cm.output[15]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Discovered the extended address of 5 devices$",
            cm.output[16]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Discovered the short-to-extended "
            r"address mapping of 4 devices$",
            cm.output[17]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Discovered 1 flows of MAC Data packets$",
            cm.output[18]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Updating the database...$",
            cm.output[19]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Finished updating the database$",
            cm.output[20]) is not None)
        self.assertTrue(re.search(
            r"^WARNING:root:Generated 2 \"PE101: "
            r"Invalid packet length\" parsing errors$",
            cm.output[21]) is not None)
        self.assertTrue(re.search(
            r"^WARNING:root:Generated 1 \"PE102: "
            r"There are no IEEE 802.15.4 MAC fields\" parsing errors$",
            cm.output[22]) is not None)
        self.assertTrue(re.search(
            r"^WARNING:root:Generated 1 \"PE202: "
            r"Incorrect frame check sequence \(FCS\)\" parsing errors$",
            cm.output[23]) is not None)

    def assertAddressesTable(self, cursor):
        cursor.execute("SELECT * FROM addresses ORDER BY extendedaddr")
        col_names = [col_name[0] for col_name in cursor.description]
        self.assertEqual(
            col_names, [
                "shortaddr",
                "panid",
                "extendedaddr",
            ])
        self.assertEqual(
            cursor.fetchall(), [
                ("0xf001", "0xddee", "1122334444332211"),
                ("0xdead", "0x99aa", "1122334455667788"),
                ("0x50fa", "0xddee", "b19b10a7ed0ff1ce"),
                ("0xb0a7", "0xddee", "d00dbad1cec0ffee"),
            ])

    def assertDevicesTable(self, cursor):
        cursor.execute("SELECT * FROM devices ORDER BY nwkdevtype")
        col_names = [col_name[0] for col_name in cursor.description]
        self.assertEqual(
            col_names, [
                "extendedaddr",
                "macdevtype",
                "nwkdevtype",
            ])
        self.assertEqual(
            cursor.fetchall(), [
                ("0ff1cec0ffeed00d",
                    "Full-Function Device",
                    None),
                ("1122334444332211",
                    None,
                    None),
                ("d00dbad1cec0ffee",
                    "Reduced-Function Device",
                    "Zigbee End Device"),
                ("1122334455667788",
                    "Full-Function Device",
                    "Zigbee Router"),
                ("b19b10a7ed0ff1ce",
                    "Full-Function Device",
                    "Zigbee Router"),
            ])

    def assertNetworksTable(self, cursor):
        cursor.execute("SELECT * FROM networks ORDER BY epid")
        col_names = [col_name[0] for col_name in cursor.description]
        self.assertEqual(
            col_names, [
                "epid",
                "panids",
            ])
        self.assertEqual(
            cursor.fetchall(), [
                ("facefeedbeefcafe", "0x99aa"),
            ])

    def assertPacketsTable(self, cursor):
        cursor.execute(
            "SELECT * FROM packets ORDER BY pcap_filename, pkt_num")
        table_columns = list(enumerate(
            [col_name[0] for col_name in cursor.description]))
        self.assertEqual(
            table_columns, list(enumerate([
                "pcap_directory",
                "pcap_filename",
                "pkt_num",
                "pkt_time",
                "pkt_bytes",
                "pkt_show",
                "phy_length",
                "mac_fcs",
                "mac_frametype",
                "mac_security",
                "mac_framepending",
                "mac_ackreq",
                "mac_panidcomp",
                "mac_dstaddrmode",
                "mac_frameversion",
                "mac_srcaddrmode",
                "mac_seqnum",
                "mac_dstpanid",
                "mac_dstshortaddr",
                "mac_dstextendedaddr",
                "mac_srcpanid",
                "mac_srcshortaddr",
                "mac_srcextendedaddr",
                "mac_cmd_id",
                "mac_cmd_payloadlength",
                "mac_assocreq_apc",
                "mac_assocreq_devtype",
                "mac_assocreq_powsrc",
                "mac_assocreq_rxidle",
                "mac_assocreq_seccap",
                "mac_assocreq_allocaddr",
                "mac_assocrsp_shortaddr",
                "mac_assocrsp_status",
                "mac_disassoc_reason",
                "mac_realign_panid",
                "mac_realign_coordaddr",
                "mac_realign_channel",
                "mac_realign_shortaddr",
                "mac_realign_page",
                "mac_gtsreq_length",
                "mac_gtsreq_dir",
                "mac_gtsreq_chartype",
                "mac_beacon_beaconorder",
                "mac_beacon_sforder",
                "mac_beacon_finalcap",
                "mac_beacon_ble",
                "mac_beacon_pancoord",
                "mac_beacon_assocpermit",
                "mac_beacon_gtsnum",
                "mac_beacon_gtspermit",
                "mac_beacon_gtsmask",
                "mac_beacon_nsap",
                "mac_beacon_neap",
                "mac_beacon_shortaddresses",
                "mac_beacon_extendedaddresses",
                "nwk_beacon_protocolid",
                "nwk_beacon_stackprofile",
                "nwk_beacon_protocolversion",
                "nwk_beacon_routercap",
                "nwk_beacon_devdepth",
                "nwk_beacon_edcap",
                "nwk_beacon_epid",
                "nwk_beacon_txoffset",
                "nwk_beacon_updateid",
                "nwk_frametype",
                "nwk_protocolversion",
                "nwk_discroute",
                "nwk_multicast",
                "nwk_security",
                "nwk_srcroute",
                "nwk_extendeddst",
                "nwk_extendedsrc",
                "nwk_edinitiator",
                "nwk_dstshortaddr",
                "nwk_srcshortaddr",
                "nwk_radius",
                "nwk_seqnum",
                "nwk_dstextendedaddr",
                "nwk_srcextendedaddr",
                "nwk_srcroute_relaycount",
                "nwk_srcroute_relayindex",
                "nwk_srcroute_relaylist",
                "nwk_aux_seclevel",
                "nwk_aux_keytype",
                "nwk_aux_extnonce",
                "nwk_aux_framecounter",
                "nwk_aux_srcaddr",
                "nwk_aux_keyseqnum",
                "nwk_aux_deckey",
                "nwk_aux_decsrc",
                "nwk_aux_decpayload",
                "nwk_aux_decshow",
                "nwk_cmd_id",
                "nwk_cmd_payloadlength",
                "nwk_routerequest_mto",
                "nwk_routerequest_ed",
                "nwk_routerequest_mc",
                "nwk_routerequest_id",
                "nwk_routerequest_dstshortaddr",
                "nwk_routerequest_pathcost",
                "nwk_routerequest_dstextendedaddr",
                "nwk_routereply_eo",
                "nwk_routereply_er",
                "nwk_routereply_mc",
                "nwk_routereply_id",
                "nwk_routereply_origshortaddr",
                "nwk_routereply_respshortaddr",
                "nwk_routereply_pathcost",
                "nwk_routereply_origextendedaddr",
                "nwk_routereply_respextendedaddr",
                "nwk_networkstatus_code",
                "nwk_networkstatus_dstshortaddr",
                "nwk_leave_rejoin",
                "nwk_leave_request",
                "nwk_leave_rmch",
                "nwk_routerecord_relaycount",
                "nwk_routerecord_relaylist",
                "nwk_rejoinreq_apc",
                "nwk_rejoinreq_devtype",
                "nwk_rejoinreq_powsrc",
                "nwk_rejoinreq_rxidle",
                "nwk_rejoinreq_seccap",
                "nwk_rejoinreq_allocaddr",
                "nwk_rejoinrsp_shortaddr",
                "nwk_rejoinrsp_status",
                "nwk_linkstatus_count",
                "nwk_linkstatus_first",
                "nwk_linkstatus_last",
                "nwk_linkstatus_addresses",
                "nwk_linkstatus_incomingcosts",
                "nwk_linkstatus_outgoingcosts",
                "nwk_networkreport_count",
                "nwk_networkreport_type",
                "nwk_networkreport_epid",
                "nwk_networkreport_info",
                "nwk_networkupdate_count",
                "nwk_networkupdate_type",
                "nwk_networkupdate_epid",
                "nwk_networkupdate_updateid",
                "nwk_networkupdate_newpanid",
                "nwk_edtimeoutreq_reqtime",
                "nwk_edtimeoutreq_edconf",
                "nwk_edtimeoutrsp_status",
                "nwk_edtimeoutrsp_poll",
                "nwk_edtimeoutrsp_timeout",
                "aps_frametype",
                "aps_delmode",
                "aps_ackformat",
                "aps_security",
                "aps_ackreq",
                "aps_exthdr",
                "aps_dstendpoint",
                "aps_groupaddr",
                "aps_clusterid",
                "aps_clustername",
                "aps_profileid",
                "aps_profilename",
                "aps_srcendpoint",
                "aps_counter",
                "aps_fragmentation",
                "aps_blocknumber",
                "aps_ackbitfield",
                "aps_aux_seclevel",
                "aps_aux_keytype",
                "aps_aux_extnonce",
                "aps_aux_framecounter",
                "aps_aux_srcaddr",
                "aps_aux_keyseqnum",
                "aps_aux_deckey",
                "aps_aux_decsrc",
                "aps_aux_decpayload",
                "aps_aux_decshow",
                "aps_cmd_id",
                "aps_transportkey_stdkeytype",
                "aps_transportkey_key",
                "aps_transportkey_keyseqnum",
                "aps_transportkey_dstextendedaddr",
                "aps_transportkey_srcextendedaddr",
                "aps_transportkey_prtextendedaddr",
                "aps_transportkey_initflag",
                "aps_updatedevice_extendedaddr",
                "aps_updatedevice_shortaddr",
                "aps_updatedevice_status",
                "aps_removedevice_extendedaddr",
                "aps_requestkey_reqkeytype",
                "aps_requestkey_prtextendedaddr",
                "aps_switchkey_keyseqnum",
                "aps_tunnel_dstextendedaddr",
                "aps_tunnel_frametype",
                "aps_tunnel_delmode",
                "aps_tunnel_ackformat",
                "aps_tunnel_security",
                "aps_tunnel_ackreq",
                "aps_tunnel_exthdr",
                "aps_tunnel_counter",
                "aps_verifykey_stdkeytype",
                "aps_verifykey_extendedaddr",
                "aps_verifykey_keyhash",
                "aps_confirmkey_status",
                "aps_confirmkey_stdkeytype",
                "aps_confirmkey_extendedaddr",
                "zdp_seqnum",
                "zcl_frametype",
                "zcl_manufspecific",
                "zcl_direction",
                "zcl_disdefrsp",
                "zcl_manufcode",
                "zcl_seqnum",
                "zcl_cmd_id",
                "der_same_macnwkdst",
                "der_same_macnwksrc",
                "der_tx_type",
                "der_mac_dsttype",
                "der_mac_srctype",
                "der_nwk_dsttype",
                "der_nwk_srctype",
                "der_mac_dstpanid",
                "der_mac_dstshortaddr",
                "der_mac_dstextendedaddr",
                "der_mac_srcpanid",
                "der_mac_srcshortaddr",
                "der_mac_srcextendedaddr",
                "der_nwk_dstpanid",
                "der_nwk_dstshortaddr",
                "der_nwk_dstextendedaddr",
                "der_nwk_srcpanid",
                "der_nwk_srcshortaddr",
                "der_nwk_srcextendedaddr",
                "warning_msg",
                "error_msg",
            ])))
        obtained_entries = self.obtain_entries(
            cursor.fetchall(), table_columns)
        expected_entries = [
            [
                ("pcap_directory", None),
                ("pcap_filename", "00-wrong-data-link-type.pcap"),
                ("pkt_num", 1),
                ("pkt_time", 1599995905.0),
                ("pkt_bytes",
                    "00000000000000000000000008004500"
                    "003c41cd40004006faec7f0000017f00"
                    "0001d6461389bb32481a00000000a002"
                    "ffd7fe3000000204ffd70402080af3b8"
                    "15e40000000001030307"),
                ("pkt_show", None),
                ("phy_length", 74),
                ("error_msg", "PE102: There are no IEEE 802.15.4 MAC fields"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "01-phy-testing.pcap"),
                ("pkt_num", 1),
                ("pkt_time", 1599996161.0),
                ("pkt_bytes", "02008971ac"),
                ("pkt_show", None),
                ("phy_length", 5),
                ("mac_fcs", "0xac71"),
                ("mac_frametype", "MAC Acknowledgment"),
                ("mac_security", "MAC Security Disabled"),
                ("mac_framepending",
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq",
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "No destination MAC address"),
                ("mac_frameversion", "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "No source MAC address"),
                ("mac_seqnum", 137),
                ("der_tx_type", "Single-Hop Transmission"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "01-phy-testing.pcap"),
                ("pkt_num", 2),
                ("pkt_time", 1599996162.0),
                ("pkt_bytes", "0308cbffffffff076e03"),
                ("pkt_show", None),
                ("phy_length", 10),
                ("mac_fcs", "0x036e"),
                ("mac_frametype", "MAC Command"),
                ("mac_security", "MAC Security Disabled"),
                ("mac_framepending",
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq",
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "Short destination MAC address"),
                ("mac_frameversion", "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "No source MAC address"),
                ("mac_seqnum", 203),
                ("mac_dstpanid", "0xffff"),
                ("mac_dstshortaddr", "0xffff"),
                ("mac_cmd_id", "MAC Beacon Request"),
                ("mac_cmd_payloadlength", 0),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Broadcast"),
                ("der_mac_dstpanid", "0xffff"),
                ("der_mac_dstshortaddr", "0xffff"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "01-phy-testing.pcap"),
                ("pkt_num", 3),
                ("pkt_time", 1599996163.0),
                ("pkt_bytes", "d5"),
                ("pkt_show", None),
                ("error_msg", "PE101: Invalid packet length")
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "01-phy-testing.pcap"),
                ("pkt_num", 4),
                ("pkt_time", 1599996164.0),
                ("pkt_bytes",
                    "0102030405060708090a0b0c0d0e0f10"
                    "1112131415161718191a1b1c1d1e1f20"
                    "2122232425262728292a2b2c2d2e2f30"
                    "3132333435363738393a3b3c3d3e3f40"
                    "4142434445464748494a4b4c4d4e4f50"
                    "5152535455565758595a5b5c5d5e5f60"
                    "6162636465666768696a6b6c6d6e6f70"
                    "7172737475767778797a7b7c7d7e7f80"),
                ("pkt_show", None),
                ("error_msg", "PE101: Invalid packet length")
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 1),
                ("pkt_time", 1599996417.0),
                ("pkt_bytes", "1200ea7978"),
                ("pkt_show", None),
                ("phy_length", 5),
                ("mac_fcs", "0x7879"),
                ("mac_frametype", "MAC Acknowledgment"),
                ("mac_security", "MAC Security Disabled"),
                ("mac_framepending",
                    "Additional packets are pending for the receiver"),
                ("mac_ackreq",
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "No destination MAC address"),
                ("mac_frameversion", "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "No source MAC address"),
                ("mac_seqnum", 234),
                ("der_tx_type", "Single-Hop Transmission"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 2),
                ("pkt_time", 1599996418.0),
                ("pkt_bytes", "23c864aa99d0d0ffff88776655443322"
                              "11018e2c1c"),
                ("pkt_show", None),
                ("phy_length", 21),
                ("mac_fcs", "0x1c2c"),
                ("mac_frametype", "MAC Command"),
                ("mac_security", "MAC Security Disabled"),
                ("mac_framepending",
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq",
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "Short destination MAC address"),
                ("mac_frameversion", "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "Extended source MAC address"),
                ("mac_seqnum", 100),
                ("mac_dstpanid", "0x99aa"),
                ("mac_dstshortaddr", "0xd0d0"),
                ("mac_srcpanid", "0xffff"),
                ("mac_srcextendedaddr", "1122334455667788"),
                ("mac_cmd_id", "MAC Association Request"),
                ("mac_cmd_payloadlength", 1),
                ("mac_assocreq_apc",
                    "The sender is not capable of "
                    "becoming a PAN coordinator"),
                ("mac_assocreq_devtype", "Full-Function Device"),
                ("mac_assocreq_powsrc",
                    "The sender is a mains-powered device"),
                ("mac_assocreq_rxidle",
                    "Does not disable the receiver to conserve power"),
                ("mac_assocreq_seccap",
                    "Cannot transmit and receive secure MAC frames"),
                ("mac_assocreq_allocaddr", "Requests a short address"),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: None"),
                ("der_mac_dstpanid", "0x99aa"),
                ("der_mac_dstshortaddr", "0xd0d0"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 3),
                ("pkt_time", 1599996419.0),
                ("pkt_bytes", "63cc72aa9988776655443322110dd0ee"
                              "ffc0cef10f02adde0009e7"),
                ("pkt_show", None),
                ("phy_length", 27),
                ("mac_fcs", "0xe709"),
                ("mac_frametype", "MAC Command"),
                ("mac_security", "MAC Security Disabled"),
                ("mac_framepending",
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq",
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp",
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "Extended destination MAC address"),
                ("mac_frameversion", "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "Extended source MAC address"),
                ("mac_seqnum", 114),
                ("mac_dstpanid", "0x99aa"),
                ("mac_dstextendedaddr", "1122334455667788"),
                ("mac_srcextendedaddr", "0ff1cec0ffeed00d"),
                ("mac_cmd_id", "MAC Association Response"),
                ("mac_cmd_payloadlength", 3),
                ("mac_assocrsp_shortaddr", "0xdead"),
                ("mac_assocrsp_status", "Association successful"),
                ("der_tx_type", "Single-Hop Transmission"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 4),
                ("pkt_time", 1599996420.0),
                ("pkt_bytes", "638832ccbb00007afe041598"),
                ("pkt_show", None),
                ("phy_length", 12),
                ("mac_fcs", "0x9815"),
                ("mac_frametype", "MAC Command"),
                ("mac_security", "MAC Security Disabled"),
                ("mac_framepending",
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq",
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp",
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "Short destination MAC address"),
                ("mac_frameversion", "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "Short source MAC address"),
                ("mac_seqnum", 50),
                ("mac_dstpanid", "0xbbcc"),
                ("mac_dstshortaddr", "0x0000"),
                ("mac_srcshortaddr", "0xfe7a"),
                ("mac_cmd_id", "MAC Data Request"),
                ("mac_cmd_payloadlength", 0),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: None"),
                ("der_mac_srctype", "MAC Src Type: None"),
                ("der_mac_dstpanid", "0xbbcc"),
                ("der_mac_dstshortaddr", "0x0000"),
                ("der_mac_srcpanid", "0xbbcc"),
                ("der_mac_srcshortaddr", "0xfe7a"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 5),
                ("pkt_time", 1599996421.0),
                ("pkt_bytes", "03c820ffffffffffffeeffc0ced1ba0d"
                              "d00608a2"),
                ("pkt_show", None),
                ("phy_length", 20),
                ("mac_fcs", "0xa208"),
                ("mac_frametype", "MAC Command"),
                ("mac_security", "MAC Security Disabled"),
                ("mac_framepending",
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq",
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "Short destination MAC address"),
                ("mac_frameversion", "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "Extended source MAC address"),
                ("mac_seqnum", 32),
                ("mac_dstpanid", "0xffff"),
                ("mac_dstshortaddr", "0xffff"),
                ("mac_srcpanid", "0xffff"),
                ("mac_srcextendedaddr", "d00dbad1cec0ffee"),
                ("mac_cmd_id", "MAC Orphan Notification"),
                ("mac_cmd_payloadlength", 0),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Broadcast"),
                ("der_mac_dstpanid", "0xffff"),
                ("der_mac_dstshortaddr", "0xffff"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 6),
                ("pkt_time", 1599996422.0),
                ("pkt_bytes", "030800ffffffff073829"),
                ("pkt_show", None),
                ("phy_length", 10),
                ("mac_fcs", "0x2938"),
                ("mac_frametype", "MAC Command"),
                ("mac_security", "MAC Security Disabled"),
                ("mac_framepending",
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq",
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "Short destination MAC address"),
                ("mac_frameversion", "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "No source MAC address"),
                ("mac_seqnum", 0),
                ("mac_dstpanid", "0xffff"),
                ("mac_dstshortaddr", "0xffff"),
                ("mac_cmd_id", "MAC Beacon Request"),
                ("mac_cmd_payloadlength", 0),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Broadcast"),
                ("der_mac_dstpanid", "0xffff"),
                ("der_mac_dstshortaddr", "0xffff"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 7),
                ("pkt_time", 1599996423.0),
                ("pkt_bytes", "03cc40ffffeeffc0ced1ba0dd0eeddce"
                              "f10feda7109bb108eeddfa5014a7b02a"
                              "74"),
                ("pkt_show", None),
                ("phy_length", 33),
                ("mac_fcs", "0x742a"),
                ("mac_frametype", "MAC Command"),
                ("mac_security", "MAC Security Disabled"),
                ("mac_framepending",
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq",
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "Extended destination MAC address"),
                ("mac_frameversion", "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "Extended source MAC address"),
                ("mac_seqnum", 64),
                ("mac_dstpanid", "0xffff"),
                ("mac_dstextendedaddr", "d00dbad1cec0ffee"),
                ("mac_srcpanid", "0xddee"),
                ("mac_srcextendedaddr", "b19b10a7ed0ff1ce"),
                ("mac_cmd_id", "MAC Coordinator Realignment"),
                ("mac_cmd_payloadlength", 7),
                ("mac_realign_panid", "0xddee"),
                ("mac_realign_coordaddr", "0x50fa"),
                ("mac_realign_channel", 20),
                ("mac_realign_shortaddr", "0xb0a7"),
                ("der_tx_type", "Single-Hop Transmission"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 8),
                ("pkt_time", 1599996424.0),
                ("pkt_bytes", "008089aa99addeff0f0000002294feca"
                              "efbeedfecefaffffff00af74"),
                ("pkt_show", None),
                ("phy_length", 28),
                ("mac_fcs", "0x74af"),
                ("mac_frametype", "MAC Beacon"),
                ("mac_security", "MAC Security Disabled"),
                ("mac_framepending",
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq",
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "No destination MAC address"),
                ("mac_frameversion", "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "Short source MAC address"),
                ("mac_seqnum", 137),
                ("mac_srcpanid", "0x99aa"),
                ("mac_srcshortaddr", "0xdead"),
                ("mac_beacon_beaconorder", 15),
                ("mac_beacon_sforder", 15),
                ("mac_beacon_finalcap", 15),
                ("mac_beacon_ble", 0),
                ("mac_beacon_pancoord",
                    "The sender is not the PAN coordinator"),
                ("mac_beacon_assocpermit",
                    "The sender is currently not "
                    "accepting association requests"),
                ("mac_beacon_gtsnum", 0),
                ("mac_beacon_gtspermit", 0),
                ("mac_beacon_nsap", 0),
                ("mac_beacon_neap", 0),
                ("mac_beacon_shortaddresses", ""),
                ("mac_beacon_extendedaddresses", ""),
                ("nwk_beacon_protocolid", 0),
                ("nwk_beacon_stackprofile", 2),
                ("nwk_beacon_protocolversion", "Zigbee PRO"),
                ("nwk_beacon_routercap",
                    "The sender can accept join requests from routers"),
                ("nwk_beacon_devdepth", 2),
                ("nwk_beacon_edcap",
                    "The sender can accept join requests from end devices"),
                ("nwk_beacon_epid", "facefeedbeefcafe"),
                ("nwk_beacon_txoffset", 16777215),
                ("nwk_beacon_updateid", 0),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Router"),
                ("der_mac_srcpanid", "0x99aa"),
                ("der_mac_srcshortaddr", "0xdead"),
                ("der_mac_srcextendedaddr", "1122334455667788")
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 9),
                ("pkt_time", 1599996425.0),
                ("pkt_bytes", "618844eedd000001f00910000001f001"
                              "5511223344443322110680e4f3"),
                ("pkt_show", None),
                ("phy_length", 29),
                ("mac_fcs", "0xf3e4"),
                ("mac_frametype", "MAC Data"),
                ("mac_security", "MAC Security Disabled"),
                ("mac_framepending",
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp",
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "Short destination MAC address"),
                ("mac_frameversion", "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "Short source MAC address"),
                ("mac_seqnum", 68),
                ("mac_dstpanid", "0xddee"),
                ("mac_dstshortaddr", "0x0000"),
                ("mac_srcshortaddr", "0xf001"),
                ("nwk_frametype", "NWK Command"),
                ("nwk_protocolversion", "Zigbee PRO"),
                ("nwk_discroute", "Suppress route discovery"),
                ("nwk_multicast", "NWK Multicast Disabled"),
                ("nwk_security", "NWK Security Disabled"),
                ("nwk_srcroute", "NWK Source Route Omitted"),
                ("nwk_extendeddst", "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "NWK Extended Source Included"),
                ("nwk_edinitiator", "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x0000"),
                ("nwk_srcshortaddr", "0xf001"),
                ("nwk_radius", 1),
                ("nwk_seqnum", 85),
                ("nwk_srcextendedaddr", "1122334444332211"),
                ("nwk_cmd_id", "NWK Rejoin Request"),
                ("nwk_cmd_payloadlength", 1),
                ("nwk_rejoinreq_apc",
                    "The sender is not capable of "
                    "becoming a PAN coordinator"),
                ("nwk_rejoinreq_devtype", "Zigbee End Device"),
                ("nwk_rejoinreq_powsrc",
                    "The sender is not a mains-powered device"),
                ("nwk_rejoinreq_rxidle",
                    "Disables the receiver to conserve power when idle"),
                ("nwk_rejoinreq_seccap",
                    "Cannot transmit and receive secure MAC frames"),
                ("nwk_rejoinreq_allocaddr", "Requests a short address"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: None"),
                ("der_mac_srctype", "MAC Src Type: None"),
                ("der_nwk_dsttype", "NWK Dst Type: None"),
                ("der_nwk_srctype", "NWK Src Type: None"),
                ("der_mac_dstpanid", "0xddee"),
                ("der_mac_dstshortaddr", "0x0000"),
                ("der_mac_srcpanid", "0xddee"),
                ("der_mac_srcshortaddr", "0xf001"),
                ("der_mac_srcextendedaddr", "1122334444332211"),
                ("der_nwk_dstpanid", "0xddee"),
                ("der_nwk_dstshortaddr", "0x0000"),
                ("der_nwk_srcpanid", "0xddee"),
                ("der_nwk_srcshortaddr", "0xf001"),
                ("der_nwk_srcextendedaddr", "1122334444332211"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 10),
                ("pkt_time", 1599996426.0),
                ("pkt_bytes", "1200ea7979"),
                ("pkt_show", None),
                ("phy_length", 5),
                ("error_msg", "PE202: Incorrect frame check sequence (FCS)"),
            ],
        ]
        self.assert_entries(obtained_entries, expected_entries)

    def assertPairsTable(self, cursor):
        cursor.execute("SELECT * FROM pairs ORDER BY panid")
        col_names = [col_name[0] for col_name in cursor.description]
        self.assertEqual(
            col_names, [
                "srcaddr",
                "dstaddr",
                "panid",
                "first",
                "last",
            ])
        self.assertEqual(
            cursor.fetchall(), [
                ("0xf001", "0x0000", "0xddee", 1599996425.0, 1599996425.0),
            ])

    def obtain_entries(self, pkt_rows, table_columns):
        table_entries = []
        for i in range(len(pkt_rows)):
            self.assertEqual(len(pkt_rows[i]), len(table_columns))
            row_entries = []
            for j in range(len(table_columns)):
                if pkt_rows[i][j] is not None:
                    row_entries.append((table_columns[j][1], pkt_rows[i][j]))
            table_entries.append(row_entries)
        return table_entries

    def assert_entries(self, obtained_entries, expected_entries):
        self.assertEqual(len(obtained_entries), len(expected_entries))
        for i in range(len(expected_entries)):
            self.assertEqual(
                len(obtained_entries[i]), len(expected_entries[i]))
            for j in range(len(expected_entries[i])):
                self.assertEqual(
                    obtained_entries[i][j][0], expected_entries[i][j][0])
                if expected_entries[i][j][1] is not None:
                    self.assertEqual(
                        obtained_entries[i][j][1],
                        expected_entries[i][j][1])


if __name__ == "__main__":
    unittest.main()
