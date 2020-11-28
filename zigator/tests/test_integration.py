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
            self.assertNotEqual(
                network_keys[i][:33],
                "22222222222222222222222222222222\t")
        link_keys = config_list[1].split("\n")
        self.assertGreater(len(link_keys), 0)
        self.assertEqual(link_keys[0], "Link keys:")
        for i in range(1, len(link_keys)):
            self.assertGreater(len(link_keys[i]), 33)
            self.assertNotEqual(
                link_keys[i][:33],
                "33333333333333333333333333333333\t")
            self.assertNotEqual(
                link_keys[i][33:],
                "test_33333333333333333333333333333333")
            self.assertNotEqual(
                link_keys[i][:33],
                "44444444444444444444444444444444\t")
            self.assertNotEqual(
                link_keys[i][:33],
                "3c6047f3c55c8c8290a5839c213b6714\t")
            self.assertNotEqual(
                link_keys[i][:33],
                "865eb452951420552e9fdbb3f16642ea\t")
            self.assertNotEqual(
                link_keys[i][:33],
                "77777777777777777777777777777777\t")
            self.assertNotEqual(
                link_keys[i][:33],
                "88888888888888888888888888888888\t")
        install_codes = config_list[2].split("\n")
        self.assertGreater(len(install_codes), 0)
        self.assertEqual(install_codes[0], "Install codes:")
        for i in range(1, len(install_codes)):
            self.assertGreater(len(install_codes[i]), 37)
            self.assertNotEqual(
                install_codes[i][:37],
                "55555555555555555555555555555555a9d1\t")
            self.assertNotEqual(
                install_codes[i][37:],
                "test_55555555555555555555555555555555a9d1")
            self.assertNotEqual(
                install_codes[i][:37],
                "66666666666666666666666666666666a603\t")
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

        with self.assertLogs(level="INFO") as cm:
            zigator.main([
                "zigator",
                "add-config-entry",
                "link-key",
                "33333333333333333333333333333333",
                "test_33333333333333333333333333333333",
            ])
        self.assertEqual(len(cm.output), 2)
        self.assertTrue(re.search(
            r"^INFO:root:Started Zigator version "
            r"(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
            cm.output[0]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Saved the link key "
            r"33333333333333333333333333333333 in the "
            r"\".+link-keys.tsv\" configuration file$",
            cm.output[1]) is not None)

        with self.assertLogs(level="INFO") as cm:
            zigator.main([
                "zigator",
                "add-config-entry",
                "install-code",
                "55555555555555555555555555555555a9d1",
                "test_55555555555555555555555555555555a9d1",
            ])
        self.assertEqual(len(cm.output), 2)
        self.assertTrue(re.search(
            r"^INFO:root:Started Zigator version "
            r"(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
            cm.output[0]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Saved the install code "
            r"55555555555555555555555555555555a9d1 in the "
            r"\".+install-codes.tsv\" configuration file$",
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
        self.assertTrue(
            "33333333333333333333333333333333\t"
            "test_33333333333333333333333333333333" in link_keys)
        self.assertTrue(
            "3c6047f3c55c8c8290a5839c213b6714\t"
            "_derived_55555555555555555555555555555555a9d1" in link_keys)
        install_codes = config_list[2].split("\n")
        self.assertGreater(len(install_codes), 0)
        self.assertTrue(
            "55555555555555555555555555555555a9d1\t"
            "test_55555555555555555555555555555555a9d1" in install_codes)
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

        with self.assertLogs(level="INFO") as cm:
            zigator.main([
                "zigator",
                "rm-config-entry",
                "link-key",
                "test_33333333333333333333333333333333",
            ])
        self.assertEqual(len(cm.output), 2)
        self.assertTrue(re.search(
            r"^INFO:root:Started Zigator version "
            r"(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
            cm.output[0]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Removed the "
            r"\"test_33333333333333333333333333333333\" link key "
            r"from the \".+link-keys.tsv\" configuration file$",
            cm.output[1]) is not None)

        with self.assertLogs(level="INFO") as cm:
            zigator.main([
                "zigator",
                "rm-config-entry",
                "install-code",
                "test_55555555555555555555555555555555a9d1",
            ])
        self.assertEqual(len(cm.output), 2)
        self.assertTrue(re.search(
            r"^INFO:root:Started Zigator version "
            r"(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
            cm.output[0]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Removed the "
            r"\"test_55555555555555555555555555555555a9d1\" install code "
            r"from the \".+install-codes.tsv\" configuration file$",
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
            self.assertNotEqual(
                network_keys[i][:33],
                "22222222222222222222222222222222\t")
        link_keys = config_list[1].split("\n")
        self.assertGreater(len(link_keys), 0)
        self.assertEqual(link_keys[0], "Link keys:")
        for i in range(1, len(link_keys)):
            self.assertGreater(len(link_keys[i]), 33)
            self.assertNotEqual(
                link_keys[i][:33],
                "33333333333333333333333333333333\t")
            self.assertNotEqual(
                link_keys[i][33:],
                "test_33333333333333333333333333333333")
            self.assertNotEqual(
                link_keys[i][:33],
                "44444444444444444444444444444444\t")
            self.assertNotEqual(
                link_keys[i][:33],
                "3c6047f3c55c8c8290a5839c213b6714\t")
            self.assertNotEqual(
                link_keys[i][:33],
                "865eb452951420552e9fdbb3f16642ea\t")
            self.assertNotEqual(
                link_keys[i][:33],
                "77777777777777777777777777777777\t")
            self.assertNotEqual(
                link_keys[i][:33],
                "88888888888888888888888888888888\t")
        install_codes = config_list[2].split("\n")
        self.assertGreater(len(install_codes), 0)
        self.assertEqual(install_codes[0], "Install codes:")
        for i in range(1, len(install_codes)):
            self.assertGreater(len(install_codes[i]), 37)
            self.assertNotEqual(
                install_codes[i][:37],
                "55555555555555555555555555555555a9d1\t")
            self.assertNotEqual(
                install_codes[i][37:],
                "test_55555555555555555555555555555555a9d1")
            self.assertNotEqual(
                install_codes[i][:37],
                "66666666666666666666666666666666a603\t")
        self.assertTrue(re.search(
            r"^Configuration directory: \".+zigator\"$",
            config_list[3]) is not None)

    def assertLoggingOutput(self, cm):
        self.assertEqual(len(cm.output), 42)

        self.assertTrue(re.search(
            r"^INFO:root:Started Zigator version "
            r"(0\+[0-9a-f]{7}|[0-9]+\.[0-9]+(\+[0-9a-f]{7})?)$",
            cm.output[0]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Detected 8 pcap files in the \".+data\" directory$",
            cm.output[1]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:The pcap files will be parsed "
            r"by ([1-9]|[1-9][0-9]+) workers$",
            cm.output[2]) is not None)

        self.assertTrue(any(re.search(
            r"^INFO:root:Reading packets from the "
            r"\".+00-wrong-data-link-type.pcap\" file...$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 1 packets from the "
            r"\".+00-wrong-data-link-type.pcap\" file$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 1 out of the 8 pcap files$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Reading packets from the "
            r"\".+01-phy-testing.pcap\" file...$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 4 packets from the "
            r"\".+01-phy-testing.pcap\" file$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 2 out of the 8 pcap files$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Reading packets from the "
            r"\".+02-mac-testing.pcap\" file...$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 12 packets from the "
            r"\".+02-mac-testing.pcap\" file$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 3 out of the 8 pcap files$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Reading packets from the "
            r"\".+03-nwk-testing.pcap\" file...$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 15 packets from the "
            r"\".+03-nwk-testing.pcap\" file$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 4 out of the 8 pcap files$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Reading packets from the "
            r"\".+04-aps-testing.pcap\" file...$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 11 packets from the "
            r"\".+04-aps-testing.pcap\" file$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 5 out of the 8 pcap files$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Reading packets from the "
            r"\".+05-zdp-testing.pcap\" file...$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 1 packets from the "
            r"\".+05-zdp-testing.pcap\" file$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 6 out of the 8 pcap files$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Reading packets from the "
            r"\".+06-zcl-testing.pcap\" file...$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 1 packets from the "
            r"\".+06-zcl-testing.pcap\" file$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 7 out of the 8 pcap files$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Reading packets from the "
            r"\".+07-sll-testing.pcap\" file...$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 1 packets from the "
            r"\".+07-sll-testing.pcap\" file$",
            log_msg) is not None for log_msg in cm.output[3:27]))
        self.assertTrue(any(re.search(
            r"^INFO:root:Parsed 8 out of the 8 pcap files$",
            log_msg) is not None for log_msg in cm.output[3:27]))

        self.assertTrue(re.search(
            r"^INFO:root:All ([1-9]|[1-9][0-9]+) workers "
            r"completed their tasks$",
            cm.output[27]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Sniffed 0 previously unknown network keys$",
            cm.output[28]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Sniffed 1 previously unknown link keys$",
            cm.output[29]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Discovered the EPID of 1 networks$",
            cm.output[30]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Discovered the extended address of 11 devices$",
            cm.output[31]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Discovered the short-to-extended "
            r"address mapping of 13 devices$",
            cm.output[32]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Discovered 12 flows of MAC Data packets$",
            cm.output[33]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Updating the database...$",
            cm.output[34]) is not None)
        self.assertTrue(re.search(
            r"^INFO:root:Finished updating the database$",
            cm.output[35]) is not None)
        self.assertTrue(re.search(
            r"^WARNING:root:Generated 1 \"PW301: "
            r"Unable to decrypt the NWK payload\" parsing warnings$",
            cm.output[36]) is not None)
        self.assertTrue(re.search(
            r"^WARNING:root:Generated 3 \"PW401: "
            r"Unable to decrypt the APS payload\" parsing warnings$",
            cm.output[37]) is not None)
        self.assertTrue(re.search(
            r"^WARNING:root:Generated 2 \"PE101: "
            r"Invalid packet length\" parsing errors$",
            cm.output[38]) is not None)
        self.assertTrue(re.search(
            r"^WARNING:root:Generated 2 \"PE102: "
            r"There are no IEEE 802.15.4 MAC fields\" parsing errors$",
            cm.output[39]) is not None)
        self.assertTrue(re.search(
            r"^WARNING:root:Generated 1 \"PE202: "
            r"Incorrect frame check sequence \(FCS\)\" parsing errors$",
            cm.output[40]) is not None)
        self.assertTrue(re.search(
            r"^WARNING:root:Generated 1 \"PE224: "
            r"Unexpected payload\" parsing errors$",
            cm.output[41]) is not None)

    def assertAddressesTable(self, cursor):
        cursor.execute("SELECT * FROM addresses ORDER BY extendedaddr, panid")
        col_names = [col_name[0] for col_name in cursor.description]
        self.assertEqual(
            col_names, [
                "shortaddr",
                "panid",
                "extendedaddr",
            ])
        self.assertEqual(
            cursor.fetchall(), [
                ("0xb000", "0x9999", "1122334444332211"),
                ("0xf001", "0xddee", "1122334444332211"),
                ("0xdead", "0x99aa", "1122334455667788"),
                ("0x0000", "0x7777", "7777770000000001"),
                ("0x0000", "0xdddd", "7777770000000001"),
                ("0x1101", "0x7777", "7777770000000002"),
                ("0x1102", "0x7777", "7777770000000003"),
                ("0x1102", "0xdddd", "7777770000000003"),
                ("0x2201", "0x7777", "7777770000000004"),
                ("0x2202", "0x7777", "7777770000000005"),
                ("0x2202", "0xdddd", "7777770000000005"),
                ("0x50fa", "0xddee", "b19b10a7ed0ff1ce"),
                ("0xb0a7", "0xddee", "d00dbad1cec0ffee"),
            ])

    def assertDevicesTable(self, cursor):
        cursor.execute("SELECT * FROM devices ORDER BY extendedaddr")
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
                ("1122334455667788",
                    "Full-Function Device",
                    "Zigbee Router"),
                ("7777770000000001",
                    "Full-Function Device",
                    "Zigbee Coordinator"),
                ("7777770000000002",
                    "Full-Function Device",
                    "Zigbee Router"),
                ("7777770000000003",
                    "Full-Function Device",
                    "Zigbee Router"),
                ("7777770000000004",
                    None,
                    None),
                ("7777770000000005",
                    None,
                    None),
                ("8888880000000001",
                    None,
                    None),
                ("b19b10a7ed0ff1ce",
                    "Full-Function Device",
                    "Zigbee Router"),
                ("d00dbad1cec0ffee",
                    "Reduced-Function Device",
                    "Zigbee End Device"),
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
                "sll_pkttype",
                "sll_arphrdtype",
                "sll_addrlength",
                "sll_addr",
                "sll_protocoltype",
                "phy_length",
                "phy_payload",
                "mac_show",
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
                "aps_cluster_id",
                "aps_profile_id",
                "aps_srcendpoint",
                "aps_counter",
                "aps_fragmentation",
                "aps_blocknumber",
                "aps_ackbitfield",
                "aps_tunnel_dstextendedaddr",
                "aps_tunnel_frametype",
                "aps_tunnel_delmode",
                "aps_tunnel_ackformat",
                "aps_tunnel_security",
                "aps_tunnel_ackreq",
                "aps_tunnel_exthdr",
                "aps_tunnel_counter",
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
                "aps_tunnel_cmd_id",
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
                ("error_msg", "PE102: There are no IEEE 802.15.4 MAC fields"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "01-phy-testing.pcap"),
                ("pkt_num", 1),
                ("pkt_time", 1599996161.0),
                ("phy_length", 5),
                ("phy_payload", "02008971ac"),
                ("mac_show", None),
                ("mac_fcs", "0xac71"),
                ("mac_frametype", "0b010: "
                    "MAC Acknowledgment"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b0: "
                    "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "0b00: "
                    "No destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b00: "
                    "No source MAC address"),
                ("mac_seqnum", 137),
                ("der_tx_type", "Single-Hop Transmission"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "01-phy-testing.pcap"),
                ("pkt_num", 2),
                ("pkt_time", 1599996162.0),
                ("phy_length", 10),
                ("phy_payload", "0308cbffffffff076e03"),
                ("mac_show", None),
                ("mac_fcs", "0x036e"),
                ("mac_frametype", "0b011: "
                    "MAC Command"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b0: "
                    "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b00: "
                    "No source MAC address"),
                ("mac_seqnum", 203),
                ("mac_dstpanid", "0xffff"),
                ("mac_dstshortaddr", "0xffff"),
                ("mac_cmd_id", "0x07: "
                    "MAC Beacon Request"),
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
                ("phy_length", 1),
                ("error_msg", "PE101: Invalid packet length")
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "01-phy-testing.pcap"),
                ("pkt_num", 4),
                ("pkt_time", 1599996164.0),
                ("phy_length", 128),
                ("error_msg", "PE101: Invalid packet length")
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 1),
                ("pkt_time", 1599996417.0),
                ("phy_length", 5),
                ("phy_payload", "1200ea7978"),
                ("mac_show", None),
                ("mac_fcs", "0x7879"),
                ("mac_frametype", "0b010: "
                    "MAC Acknowledgment"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b1: "
                    "Additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b0: "
                    "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "0b00: "
                    "No destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b00: "
                    "No source MAC address"),
                ("mac_seqnum", 234),
                ("der_tx_type", "Single-Hop Transmission"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 2),
                ("pkt_time", 1599996418.0),
                ("phy_length", 21),
                ("phy_payload", "23c864aa99d0d0ffff88776655443322"
                                "11018e2c1c"),
                ("mac_show", None),
                ("mac_fcs", "0x1c2c"),
                ("mac_frametype", "0b011: "
                    "MAC Command"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b0: "
                    "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b11: "
                    "Extended source MAC address"),
                ("mac_seqnum", 100),
                ("mac_dstpanid", "0x99aa"),
                ("mac_dstshortaddr", "0xd0d0"),
                ("mac_srcpanid", "0xffff"),
                ("mac_srcextendedaddr", "1122334455667788"),
                ("mac_cmd_id", "0x01: "
                    "MAC Association Request"),
                ("mac_cmd_payloadlength", 1),
                ("mac_assocreq_apc", "0b0: "
                    "The sender is not capable of "
                    "becoming a PAN coordinator"),
                ("mac_assocreq_devtype", "0b1: "
                    "Full-Function Device"),
                ("mac_assocreq_powsrc", "0b1: "
                    "The sender is a mains-powered device"),
                ("mac_assocreq_rxidle", "0b1: "
                    "Does not disable the receiver to conserve power"),
                ("mac_assocreq_seccap", "0b0: "
                    "Cannot transmit and receive secure MAC frames"),
                ("mac_assocreq_allocaddr", "0b1: "
                    "Requests a short address"),
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
                ("phy_length", 27),
                ("phy_payload", "63cc72aa9988776655443322110dd0ee"
                                "ffc0cef10f02adde0009e7"),
                ("mac_show", None),
                ("mac_fcs", "0xe709"),
                ("mac_frametype", "0b011: "
                    "MAC Command"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b11: "
                    "Extended destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b11: "
                    "Extended source MAC address"),
                ("mac_seqnum", 114),
                ("mac_dstpanid", "0x99aa"),
                ("mac_dstextendedaddr", "1122334455667788"),
                ("mac_srcextendedaddr", "0ff1cec0ffeed00d"),
                ("mac_cmd_id", "0x02: "
                    "MAC Association Response"),
                ("mac_cmd_payloadlength", 3),
                ("mac_assocrsp_shortaddr", "0xdead"),
                ("mac_assocrsp_status", "0x00: "
                    "Association successful"),
                ("der_tx_type", "Single-Hop Transmission"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 4),
                ("pkt_time", 1599996420.0),
                ("phy_length", 12),
                ("phy_payload", "638832ccbb00007afe041598"),
                ("mac_show", None),
                ("mac_fcs", "0x9815"),
                ("mac_frametype", "0b011: "
                    "MAC Command"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 50),
                ("mac_dstpanid", "0xbbcc"),
                ("mac_dstshortaddr", "0x0000"),
                ("mac_srcshortaddr", "0xfe7a"),
                ("mac_cmd_id", "0x04: "
                    "MAC Data Request"),
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
                ("phy_length", 20),
                ("phy_payload", "03c820ffffffffffffeeffc0ced1ba0d"
                                "d00608a2"),
                ("mac_show", None),
                ("mac_fcs", "0xa208"),
                ("mac_frametype", "0b011: "
                    "MAC Command"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b0: "
                    "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b11: "
                    "Extended source MAC address"),
                ("mac_seqnum", 32),
                ("mac_dstpanid", "0xffff"),
                ("mac_dstshortaddr", "0xffff"),
                ("mac_srcpanid", "0xffff"),
                ("mac_srcextendedaddr", "d00dbad1cec0ffee"),
                ("mac_cmd_id", "0x06: "
                    "MAC Orphan Notification"),
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
                ("phy_length", 10),
                ("phy_payload", "030800ffffffff073829"),
                ("mac_show", None),
                ("mac_fcs", "0x2938"),
                ("mac_frametype", "0b011: "
                    "MAC Command"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b0: "
                    "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b00: "
                    "No source MAC address"),
                ("mac_seqnum", 0),
                ("mac_dstpanid", "0xffff"),
                ("mac_dstshortaddr", "0xffff"),
                ("mac_cmd_id", "0x07: "
                    "MAC Beacon Request"),
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
                ("phy_length", 33),
                ("phy_payload", "03cc40ffffeeffc0ced1ba0dd0eeddce"
                                "f10feda7109bb108eeddfa5014a7b02a"
                                "74"),
                ("mac_show", None),
                ("mac_fcs", "0x742a"),
                ("mac_frametype", "0b011: "
                    "MAC Command"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b0: "
                    "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "0b11: "
                    "Extended destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b11: "
                    "Extended source MAC address"),
                ("mac_seqnum", 64),
                ("mac_dstpanid", "0xffff"),
                ("mac_dstextendedaddr", "d00dbad1cec0ffee"),
                ("mac_srcpanid", "0xddee"),
                ("mac_srcextendedaddr", "b19b10a7ed0ff1ce"),
                ("mac_cmd_id", "0x08: "
                    "MAC Coordinator Realignment"),
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
                ("phy_length", 28),
                ("phy_payload", "008089aa99addeff0f0000002294feca"
                                "efbeedfecefaffffff00af74"),
                ("mac_show", None),
                ("mac_fcs", "0x74af"),
                ("mac_frametype", "0b000: "
                    "MAC Beacon"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b0: "
                    "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "0b00: "
                    "No destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 137),
                ("mac_srcpanid", "0x99aa"),
                ("mac_srcshortaddr", "0xdead"),
                ("mac_beacon_beaconorder", 15),
                ("mac_beacon_sforder", 15),
                ("mac_beacon_finalcap", 15),
                ("mac_beacon_ble", 0),
                ("mac_beacon_pancoord", "0b0: "
                    "The sender is not the PAN coordinator"),
                ("mac_beacon_assocpermit", "0b0: "
                    "The sender is currently not "
                    "accepting association requests"),
                ("mac_beacon_gtsnum", 0),
                ("mac_beacon_gtspermit", 0),
                ("mac_beacon_nsap", 0),
                ("mac_beacon_neap", 0),
                ("nwk_beacon_protocolid", 0),
                ("nwk_beacon_stackprofile", 2),
                ("nwk_beacon_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_beacon_routercap", "0b1: "
                    "The sender can accept join requests from routers"),
                ("nwk_beacon_devdepth", 2),
                ("nwk_beacon_edcap", "0b1: "
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
                ("phy_length", 29),
                ("phy_payload", "618844eedd000001f00910000001f001"
                                "5511223344443322110680e4f3"),
                ("mac_show", None),
                ("mac_fcs", "0xf3e4"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 68),
                ("mac_dstpanid", "0xddee"),
                ("mac_dstshortaddr", "0x0000"),
                ("mac_srcshortaddr", "0xf001"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b0: "
                    "NWK Security Disabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x0000"),
                ("nwk_srcshortaddr", "0xf001"),
                ("nwk_radius", 1),
                ("nwk_seqnum", 85),
                ("nwk_srcextendedaddr", "1122334444332211"),
                ("nwk_cmd_id", "0x06: "
                    "NWK Rejoin Request"),
                ("nwk_cmd_payloadlength", 1),
                ("nwk_rejoinreq_apc", "0b0: "
                    "The sender is not capable of "
                    "becoming a PAN coordinator"),
                ("nwk_rejoinreq_devtype", "0b0: "
                    "Zigbee End Device"),
                ("nwk_rejoinreq_powsrc", "0b0: "
                    "The sender is not a mains-powered device"),
                ("nwk_rejoinreq_rxidle", "0b0: "
                    "Disables the receiver to conserve power when idle"),
                ("nwk_rejoinreq_seccap", "0b0: "
                    "Cannot transmit and receive secure MAC frames"),
                ("nwk_rejoinreq_allocaddr", "0b1: "
                    "Requests a short address"),
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
                ("phy_length", 5),
                ("phy_payload", "1200ea7979"),
                ("mac_show", None),
                ("error_msg", "PE202: Incorrect frame check sequence (FCS)"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 11),
                ("pkt_time", 1599996427.0),
                ("phy_length", 10),
                ("phy_payload", "1200b40000000000c982"),
                ("mac_show", None),
                ("mac_fcs", "0x82c9"),
                ("mac_frametype", "0b010: "
                    "MAC Acknowledgment"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b1: "
                    "Additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b0: "
                    "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "0b00: "
                    "No destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b00: "
                    "No source MAC address"),
                ("mac_seqnum", 180),
                ("error_msg", "PE224: Unexpected payload"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "02-mac-testing.pcap"),
                ("pkt_num", 12),
                ("pkt_time", 1599996428.0),
                ("error_msg", "PE102: There are no IEEE 802.15.4 MAC fields"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 1),
                ("pkt_time", 1599996673.0),
                ("phy_length", 51),
                ("phy_payload", "4188657777ffff00000912fcff00001e"
                                "a1010000000077777728112700000100"
                                "000000777777004e131904fdab211e41"
                                "4cb1f1"),
                ("mac_show", None),
                ("mac_fcs", "0xf1b1"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 101),
                ("mac_dstpanid", "0x7777"),
                ("mac_dstshortaddr", "0xffff"),
                ("mac_srcshortaddr", "0x0000"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0xfffc"),
                ("nwk_srcshortaddr", "0x0000"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 161),
                ("nwk_srcextendedaddr", "7777770000000001"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10001),
                ("nwk_aux_srcaddr", "7777770000000001"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000001"),
                ("nwk_aux_decpayload", "010802fcff00"),
                ("nwk_aux_decshow", None),
                ("nwk_cmd_id", "0x01: "
                    "NWK Route Request"),
                ("nwk_cmd_payloadlength", 5),
                ("nwk_routerequest_mto", "0b01: "
                    "Many-to-One Route Request with Route Record support"),
                ("nwk_routerequest_ed", "0b0: "
                    "The extended destination address is not present"),
                ("nwk_routerequest_mc", "0b0: "
                    "The destination address is not a Group ID"),
                ("nwk_routerequest_id", 2),
                ("nwk_routerequest_dstshortaddr", "0xfffc"),
                ("nwk_routerequest_pathcost", 0),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: False"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Broadcast"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Coordinator"),
                ("der_nwk_dsttype",
                    "NWK Dst Type: All routers and coordinator"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
                ("der_mac_dstpanid", "0x7777"),
                ("der_mac_dstshortaddr", "0xffff"),
                ("der_mac_srcpanid", "0x7777"),
                ("der_mac_srcshortaddr", "0x0000"),
                ("der_mac_srcextendedaddr", "7777770000000001"),
                ("der_nwk_dstpanid", "0x7777"),
                ("der_nwk_dstshortaddr", "0xfffc"),
                ("der_nwk_srcpanid", "0x7777"),
                ("der_nwk_srcshortaddr", "0x0000"),
                ("der_nwk_srcextendedaddr", "7777770000000001"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 2),
                ("pkt_time", 1599996674.0),
                ("phy_length", 77),
                ("phy_payload", "618866777701110211091a011102111d"
                                "a2020000000077777703000000007777"
                                "77281227000003000000007777770017"
                                "9bab129ace96cd202519666648cca5ad"
                                "60a8356ef620ccb7a631cf9715"),
                ("mac_show", None),
                ("mac_fcs", "0x1597"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 102),
                ("mac_dstpanid", "0x7777"),
                ("mac_dstshortaddr", "0x1101"),
                ("mac_srcshortaddr", "0x1102"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b1: "
                    "NWK Extended Destination Included"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x1101"),
                ("nwk_srcshortaddr", "0x1102"),
                ("nwk_radius", 29),
                ("nwk_seqnum", 162),
                ("nwk_dstextendedaddr", "7777770000000002"),
                ("nwk_srcextendedaddr", "7777770000000003"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10002),
                ("nwk_aux_srcaddr", "7777770000000003"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000003"),
                ("nwk_aux_decpayload", "02300501110000080200000000777777"
                                       "0100000000777777"),
                ("nwk_aux_decshow", None),
                ("nwk_cmd_id", "0x02: "
                    "NWK Route Reply"),
                ("nwk_cmd_payloadlength", 23),
                ("nwk_routereply_eo", "0b1: "
                    "The extended originator address is present"),
                ("nwk_routereply_er", "0b1: "
                    "The extended responder address is present"),
                ("nwk_routereply_mc", "0b0: "
                    "The responder address is not a Group ID"),
                ("nwk_routereply_id", 5),
                ("nwk_routereply_origshortaddr", "0x1101"),
                ("nwk_routereply_respshortaddr", "0x0000"),
                ("nwk_routereply_pathcost", 8),
                ("nwk_routereply_origextendedaddr", "7777770000000002"),
                ("nwk_routereply_respextendedaddr", "7777770000000001"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Router"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Router"),
                ("der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Router"),
                ("der_mac_dstpanid", "0x7777"),
                ("der_mac_dstshortaddr", "0x1101"),
                ("der_mac_dstextendedaddr", "7777770000000002"),
                ("der_mac_srcpanid", "0x7777"),
                ("der_mac_srcshortaddr", "0x1102"),
                ("der_mac_srcextendedaddr", "7777770000000003"),
                ("der_nwk_dstpanid", "0x7777"),
                ("der_nwk_dstshortaddr", "0x1101"),
                ("der_nwk_dstextendedaddr", "7777770000000002"),
                ("der_nwk_srcpanid", "0x7777"),
                ("der_nwk_srcshortaddr", "0x1102"),
                ("der_nwk_srcextendedaddr", "7777770000000003"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 3),
                ("pkt_time", 1599996675.0),
                ("phy_length", 57),
                ("phy_payload", "618867777701110211091a000002111e"
                                "a3010000000077777703000000007777"
                                "772813270000030000000077777700b2"
                                "947514e144434c0056"),
                ("mac_show", None),
                ("mac_fcs", "0x5600"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 103),
                ("mac_dstpanid", "0x7777"),
                ("mac_dstshortaddr", "0x1101"),
                ("mac_srcshortaddr", "0x1102"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b1: "
                    "NWK Extended Destination Included"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x0000"),
                ("nwk_srcshortaddr", "0x1102"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 163),
                ("nwk_dstextendedaddr", "7777770000000001"),
                ("nwk_srcextendedaddr", "7777770000000003"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10003),
                ("nwk_aux_srcaddr", "7777770000000003"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000003"),
                ("nwk_aux_decpayload", "030c0211"),
                ("nwk_aux_decshow", None),
                ("nwk_cmd_id", "0x03: "
                    "NWK Network Status"),
                ("nwk_cmd_payloadlength", 3),
                ("nwk_networkstatus_code", "0x0c: "
                    "Many-to-one route failure"),
                ("nwk_networkstatus_dstshortaddr", "0x1102"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: False"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Router"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Router"),
                ("der_nwk_dsttype", "NWK Dst Type: Zigbee Coordinator"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Router"),
                ("der_mac_dstpanid", "0x7777"),
                ("der_mac_dstshortaddr", "0x1101"),
                ("der_mac_dstextendedaddr", "7777770000000002"),
                ("der_mac_srcpanid", "0x7777"),
                ("der_mac_srcshortaddr", "0x1102"),
                ("der_mac_srcextendedaddr", "7777770000000003"),
                ("der_nwk_dstpanid", "0x7777"),
                ("der_nwk_dstshortaddr", "0x0000"),
                ("der_nwk_dstextendedaddr", "7777770000000001"),
                ("der_nwk_srcpanid", "0x7777"),
                ("der_nwk_srcshortaddr", "0x1102"),
                ("der_nwk_srcextendedaddr", "7777770000000003"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 4),
                ("pkt_time", 1599996676.0),
                ("phy_length", 47),
                ("phy_payload", "4188687777ffff02110912fdff021101"
                                "a4030000000077777728142700000300"
                                "0000007777770059df821d51765a1a"),
                ("mac_show", None),
                ("mac_fcs", "0x1a5a"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 104),
                ("mac_dstpanid", "0x7777"),
                ("mac_dstshortaddr", "0xffff"),
                ("mac_srcshortaddr", "0x1102"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0xfffd"),
                ("nwk_srcshortaddr", "0x1102"),
                ("nwk_radius", 1),
                ("nwk_seqnum", 164),
                ("nwk_srcextendedaddr", "7777770000000003"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10004),
                ("nwk_aux_srcaddr", "7777770000000003"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000003"),
                ("nwk_aux_decpayload", "0400"),
                ("nwk_aux_decshow", None),
                ("nwk_cmd_id", "0x04: "
                    "NWK Leave"),
                ("nwk_cmd_payloadlength", 1),
                ("nwk_leave_rejoin", "0b0: "
                    "The device will not rejoin the network"),
                ("nwk_leave_request", "0b0: "
                    "The sending device wants to leave the network"),
                ("nwk_leave_rmch", "0b0: "
                    "The device's children will "
                    "not be removed from the network"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: False"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Broadcast"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Router"),
                ("der_nwk_dsttype", "NWK Dst Type: All active receivers"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Router"),
                ("der_mac_dstpanid", "0x7777"),
                ("der_mac_dstshortaddr", "0xffff"),
                ("der_mac_srcpanid", "0x7777"),
                ("der_mac_srcshortaddr", "0x1102"),
                ("der_mac_srcextendedaddr", "7777770000000003"),
                ("der_nwk_dstpanid", "0x7777"),
                ("der_nwk_dstshortaddr", "0xfffd"),
                ("der_nwk_srcpanid", "0x7777"),
                ("der_nwk_srcshortaddr", "0x1102"),
                ("der_nwk_srcextendedaddr", "7777770000000003"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 5),
                ("pkt_time", 1599996677.0),
                ("phy_length", 57),
                ("phy_payload", "618869777700000211091a000001221e"
                                "a5010000000077777704000000007777"
                                "77281527000003000000007777770055"
                                "78fa0d274ff50d5bce"),
                ("mac_show", None),
                ("mac_fcs", "0xce5b"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 105),
                ("mac_dstpanid", "0x7777"),
                ("mac_dstshortaddr", "0x0000"),
                ("mac_srcshortaddr", "0x1102"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b1: "
                    "NWK Extended Destination Included"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x0000"),
                ("nwk_srcshortaddr", "0x2201"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 165),
                ("nwk_dstextendedaddr", "7777770000000001"),
                ("nwk_srcextendedaddr", "7777770000000004"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10005),
                ("nwk_aux_srcaddr", "7777770000000003"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000003"),
                ("nwk_aux_decpayload", "05010211"),
                ("nwk_aux_decshow", None),
                ("nwk_cmd_id", "0x05: "
                    "NWK Route Record"),
                ("nwk_cmd_payloadlength", 3),
                ("nwk_routerecord_relaycount", 1),
                ("nwk_routerecord_relaylist", "0x1102"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: False"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Coordinator"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Router"),
                ("der_nwk_dsttype", "NWK Dst Type: Zigbee Coordinator"),
                ("der_nwk_srctype", "NWK Src Type: None"),
                ("der_mac_dstpanid", "0x7777"),
                ("der_mac_dstshortaddr", "0x0000"),
                ("der_mac_dstextendedaddr", "7777770000000001"),
                ("der_mac_srcpanid", "0x7777"),
                ("der_mac_srcshortaddr", "0x1102"),
                ("der_mac_srcextendedaddr", "7777770000000003"),
                ("der_nwk_dstpanid", "0x7777"),
                ("der_nwk_dstshortaddr", "0x0000"),
                ("der_nwk_dstextendedaddr", "7777770000000001"),
                ("der_nwk_srcpanid", "0x7777"),
                ("der_nwk_srcshortaddr", "0x2201"),
                ("der_nwk_srcextendedaddr", "7777770000000004"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 6),
                ("pkt_time", 1599996678.0),
                ("phy_length", 47),
                ("phy_payload", "61886a77770211012209120211012201"
                                "a6040000000077777728162700000400"
                                "00000077777700f358fd02788cd978"),
                ("mac_show", None),
                ("mac_fcs", "0x78d9"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 106),
                ("mac_dstpanid", "0x7777"),
                ("mac_dstshortaddr", "0x1102"),
                ("mac_srcshortaddr", "0x2201"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x1102"),
                ("nwk_srcshortaddr", "0x2201"),
                ("nwk_radius", 1),
                ("nwk_seqnum", 166),
                ("nwk_srcextendedaddr", "7777770000000004"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10006),
                ("nwk_aux_srcaddr", "7777770000000004"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000004"),
                ("nwk_aux_decpayload", "0680"),
                ("nwk_aux_decshow", None),
                ("nwk_cmd_id", "0x06: "
                    "NWK Rejoin Request"),
                ("nwk_cmd_payloadlength", 1),
                ("nwk_rejoinreq_apc", "0b0: "
                    "The sender is not capable of "
                    "becoming a PAN coordinator"),
                ("nwk_rejoinreq_devtype", "0b0: "
                    "Zigbee End Device"),
                ("nwk_rejoinreq_powsrc", "0b0: "
                    "The sender is not a mains-powered device"),
                ("nwk_rejoinreq_rxidle", "0b0: "
                    "Disables the receiver to conserve power when idle"),
                ("nwk_rejoinreq_seccap", "0b0: "
                    "Cannot transmit and receive secure MAC frames"),
                ("nwk_rejoinreq_allocaddr", "0b1: "
                    "Requests a short address"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Router"),
                ("der_mac_srctype", "MAC Src Type: None"),
                ("der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
                ("der_nwk_srctype", "NWK Src Type: None"),
                ("der_mac_dstpanid", "0x7777"),
                ("der_mac_dstshortaddr", "0x1102"),
                ("der_mac_dstextendedaddr", "7777770000000003"),
                ("der_mac_srcpanid", "0x7777"),
                ("der_mac_srcshortaddr", "0x2201"),
                ("der_mac_srcextendedaddr", "7777770000000004"),
                ("der_nwk_dstpanid", "0x7777"),
                ("der_nwk_dstshortaddr", "0x1102"),
                ("der_nwk_dstextendedaddr", "7777770000000003"),
                ("der_nwk_srcpanid", "0x7777"),
                ("der_nwk_srcshortaddr", "0x2201"),
                ("der_nwk_srcextendedaddr", "7777770000000004"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 7),
                ("pkt_time", 1599996679.0),
                ("phy_length", 57),
                ("phy_payload", "61886b777701220211091a0122021101"
                                "a7040000000077777703000000007777"
                                "7728172700000300000000777777001a"
                                "d125b694f3d1374b5d"),
                ("mac_show", None),
                ("mac_fcs", "0x5d4b"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 107),
                ("mac_dstpanid", "0x7777"),
                ("mac_dstshortaddr", "0x2201"),
                ("mac_srcshortaddr", "0x1102"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b1: "
                    "NWK Extended Destination Included"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x2201"),
                ("nwk_srcshortaddr", "0x1102"),
                ("nwk_radius", 1),
                ("nwk_seqnum", 167),
                ("nwk_dstextendedaddr", "7777770000000004"),
                ("nwk_srcextendedaddr", "7777770000000003"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10007),
                ("nwk_aux_srcaddr", "7777770000000003"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000003"),
                ("nwk_aux_decpayload", "07012200"),
                ("nwk_aux_decshow", None),
                ("nwk_cmd_id", "0x07: "
                    "NWK Rejoin Response"),
                ("nwk_cmd_payloadlength", 3),
                ("nwk_rejoinrsp_shortaddr", "0x2201"),
                ("nwk_rejoinrsp_status", "0x00: "
                    "Rejoin successful"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: None"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Router"),
                ("der_nwk_dsttype", "NWK Dst Type: None"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Router"),
                ("der_mac_dstpanid", "0x7777"),
                ("der_mac_dstshortaddr", "0x2201"),
                ("der_mac_dstextendedaddr", "7777770000000004"),
                ("der_mac_srcpanid", "0x7777"),
                ("der_mac_srcshortaddr", "0x1102"),
                ("der_mac_srcextendedaddr", "7777770000000003"),
                ("der_nwk_dstpanid", "0x7777"),
                ("der_nwk_dstshortaddr", "0x2201"),
                ("der_nwk_dstextendedaddr", "7777770000000004"),
                ("der_nwk_srcpanid", "0x7777"),
                ("der_nwk_srcshortaddr", "0x1102"),
                ("der_nwk_srcextendedaddr", "7777770000000003"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 8),
                ("pkt_time", 1599996680.0),
                ("phy_length", 53),
                ("phy_payload", "41886c7777ffff01110912fcff011101"
                                "a8020000000077777728182700000200"
                                "00000077777700bfd091df542acea045"
                                "00844ba8ba"),
                ("mac_show", None),
                ("mac_fcs", "0xbaa8"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 108),
                ("mac_dstpanid", "0x7777"),
                ("mac_dstshortaddr", "0xffff"),
                ("mac_srcshortaddr", "0x1101"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0xfffc"),
                ("nwk_srcshortaddr", "0x1101"),
                ("nwk_radius", 1),
                ("nwk_seqnum", 168),
                ("nwk_srcextendedaddr", "7777770000000002"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10008),
                ("nwk_aux_srcaddr", "7777770000000002"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000002"),
                ("nwk_aux_decpayload", "0862000003021111"),
                ("nwk_aux_decshow", None),
                ("nwk_cmd_id", "0x08: "
                    "NWK Link Status"),
                ("nwk_cmd_payloadlength", 7),
                ("nwk_linkstatus_count", 2),
                ("nwk_linkstatus_first", "0b1: "
                    "This is the first frame of the sender's link status"),
                ("nwk_linkstatus_last", "0b1: "
                    "This is the last frame of the sender's link status"),
                ("nwk_linkstatus_addresses", "0x0000,0x1102"),
                ("nwk_linkstatus_incomingcosts", "3,1"),
                ("nwk_linkstatus_outgoingcosts", "0,1"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: False"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Broadcast"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Router"),
                ("der_nwk_dsttype",
                    "NWK Dst Type: All routers and coordinator"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Router"),
                ("der_mac_dstpanid", "0x7777"),
                ("der_mac_dstshortaddr", "0xffff"),
                ("der_mac_srcpanid", "0x7777"),
                ("der_mac_srcshortaddr", "0x1101"),
                ("der_mac_srcextendedaddr", "7777770000000002"),
                ("der_nwk_dstpanid", "0x7777"),
                ("der_nwk_dstshortaddr", "0xfffc"),
                ("der_nwk_srcpanid", "0x7777"),
                ("der_nwk_srcshortaddr", "0x1101"),
                ("der_nwk_srcextendedaddr", "7777770000000002"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 9),
                ("pkt_time", 1599996681.0),
                ("phy_length", 57),
                ("phy_payload", "61886d7777000002110912000002111e"
                                "a9030000000077777728192700000300"
                                "000000777777007253e1c7f063d359df"
                                "2882b0f45213a5ba20"),
                ("mac_show", None),
                ("mac_fcs", "0x20ba"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 109),
                ("mac_dstpanid", "0x7777"),
                ("mac_dstshortaddr", "0x0000"),
                ("mac_srcshortaddr", "0x1102"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x0000"),
                ("nwk_srcshortaddr", "0x1102"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 169),
                ("nwk_srcextendedaddr", "7777770000000003"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10009),
                ("nwk_aux_srcaddr", "7777770000000003"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000003"),
                ("nwk_aux_decpayload", "09010d90e1fedec001c07777"),
                ("nwk_aux_decshow", None),
                ("nwk_cmd_id", "0x09: "
                    "NWK Network Report"),
                ("nwk_cmd_payloadlength", 11),
                ("nwk_networkreport_count", 1),
                ("nwk_networkreport_type", "0b000: "
                    "PAN Identifier Conflict"),
                ("nwk_networkreport_epid", "c001c0defee1900d"),
                ("nwk_networkreport_info", "0x7777"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Coordinator"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Router"),
                ("der_nwk_dsttype", "NWK Dst Type: Zigbee Coordinator"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Router"),
                ("der_mac_dstpanid", "0x7777"),
                ("der_mac_dstshortaddr", "0x0000"),
                ("der_mac_dstextendedaddr", "7777770000000001"),
                ("der_mac_srcpanid", "0x7777"),
                ("der_mac_srcshortaddr", "0x1102"),
                ("der_mac_srcextendedaddr", "7777770000000003"),
                ("der_nwk_dstpanid", "0x7777"),
                ("der_nwk_dstshortaddr", "0x0000"),
                ("der_nwk_dstextendedaddr", "7777770000000001"),
                ("der_nwk_srcpanid", "0x7777"),
                ("der_nwk_srcshortaddr", "0x1102"),
                ("der_nwk_srcextendedaddr", "7777770000000003"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 10),
                ("pkt_time", 1599996682.0),
                ("phy_length", 58),
                ("phy_payload", "41886e7777ffff00000912ffff00001e"
                                "aa0100000000777777281a2700000100"
                                "000000777777005a913c15e8babd543c"
                                "8b812a34cad8d32ec0fe"),
                ("mac_show", None),
                ("mac_fcs", "0xfec0"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 110),
                ("mac_dstpanid", "0x7777"),
                ("mac_dstshortaddr", "0xffff"),
                ("mac_srcshortaddr", "0x0000"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0xffff"),
                ("nwk_srcshortaddr", "0x0000"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 170),
                ("nwk_srcextendedaddr", "7777770000000001"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10010),
                ("nwk_aux_srcaddr", "7777770000000001"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000001"),
                ("nwk_aux_decpayload", "0a010d90e1fedec001c0028888"),
                ("nwk_aux_decshow", None),
                ("nwk_cmd_id", "0x0a: "
                    "NWK Network Update"),
                ("nwk_cmd_payloadlength", 12),
                ("nwk_networkupdate_count", 1),
                ("nwk_networkupdate_type", "0b000: "
                    "PAN Identifier Update"),
                ("nwk_networkupdate_epid", "c001c0defee1900d"),
                ("nwk_networkupdate_updateid", 2),
                ("nwk_networkupdate_newpanid", "0x8888"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Broadcast"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Coordinator"),
                ("der_nwk_dsttype", "NWK Dst Type: All devices"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
                ("der_mac_dstpanid", "0x7777"),
                ("der_mac_dstshortaddr", "0xffff"),
                ("der_mac_srcpanid", "0x7777"),
                ("der_mac_srcshortaddr", "0x0000"),
                ("der_mac_srcextendedaddr", "7777770000000001"),
                ("der_nwk_dstpanid", "0x7777"),
                ("der_nwk_dstshortaddr", "0xffff"),
                ("der_nwk_srcpanid", "0x7777"),
                ("der_nwk_srcshortaddr", "0x0000"),
                ("der_nwk_srcextendedaddr", "7777770000000001"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 11),
                ("pkt_time", 1599996683.0),
                ("phy_length", 56),
                ("phy_payload", "61886f777702110222091a0211022201"
                                "ab030000000077777705000000007777"
                                "77281b270000050000000077777700d7"
                                "24e5e1132d07b3a5"),
                ("mac_show", None),
                ("mac_fcs", "0xa5b3"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 111),
                ("mac_dstpanid", "0x7777"),
                ("mac_dstshortaddr", "0x1102"),
                ("mac_srcshortaddr", "0x2202"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b1: "
                    "NWK Extended Destination Included"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x1102"),
                ("nwk_srcshortaddr", "0x2202"),
                ("nwk_radius", 1),
                ("nwk_seqnum", 171),
                ("nwk_dstextendedaddr", "7777770000000003"),
                ("nwk_srcextendedaddr", "7777770000000005"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10011),
                ("nwk_aux_srcaddr", "7777770000000005"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000005"),
                ("nwk_aux_decpayload", "0b0300"),
                ("nwk_aux_decshow", None),
                ("nwk_cmd_id", "0x0b: "
                    "NWK End Device Timeout Request"),
                ("nwk_cmd_payloadlength", 2),
                ("nwk_edtimeoutreq_reqtime", "0x03: "
                    "8 minutes"),
                ("nwk_edtimeoutreq_edconf", 0),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Router"),
                ("der_mac_srctype", "MAC Src Type: None"),
                ("der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
                ("der_nwk_srctype", "NWK Src Type: None"),
                ("der_mac_dstpanid", "0x7777"),
                ("der_mac_dstshortaddr", "0x1102"),
                ("der_mac_dstextendedaddr", "7777770000000003"),
                ("der_mac_srcpanid", "0x7777"),
                ("der_mac_srcshortaddr", "0x2202"),
                ("der_mac_srcextendedaddr", "7777770000000005"),
                ("der_nwk_dstpanid", "0x7777"),
                ("der_nwk_dstshortaddr", "0x1102"),
                ("der_nwk_dstextendedaddr", "7777770000000003"),
                ("der_nwk_srcpanid", "0x7777"),
                ("der_nwk_srcshortaddr", "0x2202"),
                ("der_nwk_srcextendedaddr", "7777770000000005"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 12),
                ("pkt_time", 1599996684.0),
                ("phy_length", 56),
                ("phy_payload", "618870777702220211091a0222021101"
                                "ac050000000077777703000000007777"
                                "77281c27000003000000007777770039"
                                "dd4715cd65c49785"),
                ("mac_show", None),
                ("mac_fcs", "0x8597"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 112),
                ("mac_dstpanid", "0x7777"),
                ("mac_dstshortaddr", "0x2202"),
                ("mac_srcshortaddr", "0x1102"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b1: "
                    "NWK Extended Destination Included"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x2202"),
                ("nwk_srcshortaddr", "0x1102"),
                ("nwk_radius", 1),
                ("nwk_seqnum", 172),
                ("nwk_dstextendedaddr", "7777770000000005"),
                ("nwk_srcextendedaddr", "7777770000000003"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10012),
                ("nwk_aux_srcaddr", "7777770000000003"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000003"),
                ("nwk_aux_decpayload", "0c0003"),
                ("nwk_aux_decshow", None),
                ("nwk_cmd_id", "0x0c: "
                    "NWK End Device Timeout Response"),
                ("nwk_cmd_payloadlength", 2),
                ("nwk_edtimeoutrsp_status", "0x00: "
                    "Success"),
                ("nwk_edtimeoutrsp_poll", "0b1: "
                    "MAC Data Poll Keepalive is supported"),
                ("nwk_edtimeoutrsp_timeout", "0b1: "
                    "End Device Timeout Request Keepalive is supported"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: None"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Router"),
                ("der_nwk_dsttype", "NWK Dst Type: None"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Router"),
                ("der_mac_dstpanid", "0x7777"),
                ("der_mac_dstshortaddr", "0x2202"),
                ("der_mac_dstextendedaddr", "7777770000000005"),
                ("der_mac_srcpanid", "0x7777"),
                ("der_mac_srcshortaddr", "0x1102"),
                ("der_mac_srcextendedaddr", "7777770000000003"),
                ("der_nwk_dstpanid", "0x7777"),
                ("der_nwk_dstshortaddr", "0x2202"),
                ("der_nwk_dstextendedaddr", "7777770000000005"),
                ("der_nwk_srcpanid", "0x7777"),
                ("der_nwk_srcshortaddr", "0x1102"),
                ("der_nwk_srcextendedaddr", "7777770000000003"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 13),
                ("pkt_time", 1599996685.0),
                ("phy_length", 65),
                ("phy_payload", "4188717777ffff01110812fdff01111e"
                                "ad0200000000777777281d2700000200"
                                "0000007777770057c6f9c760d6a6a245"
                                "23068b5509399352c48474caa3791465"
                                "f5"),
                ("mac_show", None),
                ("mac_fcs", "0xf565"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 113),
                ("mac_dstpanid", "0x7777"),
                ("mac_dstshortaddr", "0xffff"),
                ("mac_srcshortaddr", "0x1101"),
                ("nwk_frametype", "0b00: "
                    "NWK Data"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0xfffd"),
                ("nwk_srcshortaddr", "0x1101"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 173),
                ("nwk_srcextendedaddr", "7777770000000002"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10013),
                ("nwk_aux_srcaddr", "7777770000000002"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000002"),
                ("nwk_aux_decpayload", "08001300000000818101110200000000"
                                       "7777778e"),
                ("nwk_aux_decshow", None),
                ("aps_frametype", "0b00: "
                    "APS Data"),
                ("aps_delmode", "0b10: "
                    "Broadcast"),
                ("aps_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_security", "0b0: "
                    "APS Security Disabled"),
                ("aps_ackreq", "0b0: "
                    "The sender does not request an APS ACK"),
                ("aps_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_dstendpoint", 0),
                ("aps_cluster_id", "0x0013: "
                    "Device_annce"),
                ("aps_profile_id", "0x0000: "
                    "Zigbee Device Profile (ZDP)"),
                ("aps_srcendpoint", 0),
                ("aps_counter", 129),
                ("zdp_seqnum", 129),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: False"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Broadcast"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Router"),
                ("der_nwk_dsttype", "NWK Dst Type: All active receivers"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Router"),
                ("der_mac_dstpanid", "0x7777"),
                ("der_mac_dstshortaddr", "0xffff"),
                ("der_mac_srcpanid", "0x7777"),
                ("der_mac_srcshortaddr", "0x1101"),
                ("der_mac_srcextendedaddr", "7777770000000002"),
                ("der_nwk_dstpanid", "0x7777"),
                ("der_nwk_dstshortaddr", "0xfffd"),
                ("der_nwk_srcpanid", "0x7777"),
                ("der_nwk_srcshortaddr", "0x1101"),
                ("der_nwk_srcextendedaddr", "7777770000000002"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 14),
                ("pkt_time", 1599996686.0),
                ("phy_length", 29),
                ("phy_payload", "6188729999000000b00910000000b001"
                                "ae11223344443322110680fe8d"),
                ("mac_show", None),
                ("mac_fcs", "0x8dfe"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 114),
                ("mac_dstpanid", "0x9999"),
                ("mac_dstshortaddr", "0x0000"),
                ("mac_srcshortaddr", "0xb000"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b0: "
                    "NWK Security Disabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x0000"),
                ("nwk_srcshortaddr", "0xb000"),
                ("nwk_radius", 1),
                ("nwk_seqnum", 174),
                ("nwk_srcextendedaddr", "1122334444332211"),
                ("nwk_cmd_id", "0x06: "
                    "NWK Rejoin Request"),
                ("nwk_cmd_payloadlength", 1),
                ("nwk_rejoinreq_apc", "0b0: "
                    "The sender is not capable of "
                    "becoming a PAN coordinator"),
                ("nwk_rejoinreq_devtype", "0b0: "
                    "Zigbee End Device"),
                ("nwk_rejoinreq_powsrc", "0b0: "
                    "The sender is not a mains-powered device"),
                ("nwk_rejoinreq_rxidle", "0b0: "
                    "Disables the receiver to conserve power when idle"),
                ("nwk_rejoinreq_seccap", "0b0: "
                    "Cannot transmit and receive secure MAC frames"),
                ("nwk_rejoinreq_allocaddr", "0b1: "
                    "Requests a short address"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: None"),
                ("der_mac_srctype", "MAC Src Type: None"),
                ("der_nwk_dsttype", "NWK Dst Type: None"),
                ("der_nwk_srctype", "NWK Src Type: None"),
                ("der_mac_dstpanid", "0x9999"),
                ("der_mac_dstshortaddr", "0x0000"),
                ("der_mac_srcpanid", "0x9999"),
                ("der_mac_srcshortaddr", "0xb000"),
                ("der_mac_srcextendedaddr", "1122334444332211"),
                ("der_nwk_dstpanid", "0x9999"),
                ("der_nwk_dstshortaddr", "0x0000"),
                ("der_nwk_srcpanid", "0x9999"),
                ("der_nwk_srcshortaddr", "0xb000"),
                ("der_nwk_srcextendedaddr", "1122334444332211"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "03-nwk-testing.pcap"),
                ("pkt_num", 15),
                ("pkt_time", 1599996687.0),
                ("phy_length", 47),
                ("phy_payload", "6188739999000000b00912000000b001"
                                "af1122334444332211281f2700001122"
                                "334444332211004bf59324ae58a8a8"),
                ("mac_show", None),
                ("mac_fcs", "0xa8a8"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 115),
                ("mac_dstpanid", "0x9999"),
                ("mac_dstshortaddr", "0x0000"),
                ("mac_srcshortaddr", "0xb000"),
                ("nwk_frametype", "0b01: "
                    "NWK Command"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x0000"),
                ("nwk_srcshortaddr", "0xb000"),
                ("nwk_radius", 1),
                ("nwk_seqnum", 175),
                ("nwk_srcextendedaddr", "1122334444332211"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10015),
                ("nwk_aux_srcaddr", "1122334444332211"),
                ("nwk_aux_keyseqnum", 0),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Single-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: None"),
                ("der_mac_srctype", "MAC Src Type: None"),
                ("der_nwk_dsttype", "NWK Dst Type: None"),
                ("der_nwk_srctype", "NWK Src Type: None"),
                ("der_mac_dstpanid", "0x9999"),
                ("der_mac_dstshortaddr", "0x0000"),
                ("der_mac_srcpanid", "0x9999"),
                ("der_mac_srcshortaddr", "0xb000"),
                ("der_mac_srcextendedaddr", "1122334444332211"),
                ("der_nwk_dstpanid", "0x9999"),
                ("der_nwk_dstshortaddr", "0x0000"),
                ("der_nwk_srcpanid", "0x9999"),
                ("der_nwk_srcshortaddr", "0xb000"),
                ("der_nwk_srcextendedaddr", "1122334444332211"),
                ("warning_msg", "PW301: Unable to decrypt the NWK payload"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "04-aps-testing.pcap"),
                ("pkt_num", 1),
                ("pkt_time", 1599996929.0),
                ("phy_length", 45),
                ("phy_payload", "618800dddd000002110802000002111e"
                                "f028002800000300000000777777002f"
                                "0b86a79f3c0c0bae0f4915355e"),
                ("mac_show", None),
                ("mac_fcs", "0x5e35"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 0),
                ("mac_dstpanid", "0xdddd"),
                ("mac_dstshortaddr", "0x0000"),
                ("mac_srcshortaddr", "0x1102"),
                ("nwk_frametype", "0b00: "
                    "NWK Data"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b0: "
                    "NWK Extended Source Omitted"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x0000"),
                ("nwk_srcshortaddr", "0x1102"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 240),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10240),
                ("nwk_aux_srcaddr", "7777770000000003"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000003"),
                ("nwk_aux_decpayload", "020005000000004e"),
                ("nwk_aux_decshow", None),
                ("aps_frametype", "0b10: "
                    "APS Acknowledgment"),
                ("aps_delmode", "0b00: "
                    "Normal unicast delivery"),
                ("aps_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_security", "0b0: "
                    "APS Security Disabled"),
                ("aps_ackreq", "0b0: "
                    "The sender does not request an APS ACK"),
                ("aps_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_dstendpoint", 0),
                ("aps_cluster_id", "0x0005: "
                    "Active_EP_req"),
                ("aps_profile_id", "0x0000: "
                    "Zigbee Device Profile (ZDP)"),
                ("aps_srcendpoint", 0),
                ("aps_counter", 78),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Coordinator"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Router"),
                ("der_nwk_dsttype", "NWK Dst Type: Zigbee Coordinator"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Router"),
                ("der_mac_dstpanid", "0xdddd"),
                ("der_mac_dstshortaddr", "0x0000"),
                ("der_mac_dstextendedaddr", "7777770000000001"),
                ("der_mac_srcpanid", "0xdddd"),
                ("der_mac_srcshortaddr", "0x1102"),
                ("der_mac_srcextendedaddr", "7777770000000003"),
                ("der_nwk_dstpanid", "0xdddd"),
                ("der_nwk_dstshortaddr", "0x0000"),
                ("der_nwk_dstextendedaddr", "7777770000000001"),
                ("der_nwk_srcpanid", "0xdddd"),
                ("der_nwk_srcshortaddr", "0x1102"),
                ("der_nwk_srcextendedaddr", "7777770000000003"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "04-aps-testing.pcap"),
                ("pkt_num", 2),
                ("pkt_time", 1599996930.0),
                ("phy_length", 73),
                ("phy_payload", "618801dddd021100000800021100001e"
                                "f1216430012800000100000000777777"
                                "130c00b08bf1dc4788a49d87f2c10be7"
                                "30a6609c7830b68dd17b0b1e9b111751"
                                "c0ae44b66ca98fb79b"),
                ("mac_show", None),
                ("mac_fcs", "0x9bb7"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 1),
                ("mac_dstpanid", "0xdddd"),
                ("mac_dstshortaddr", "0x1102"),
                ("mac_srcshortaddr", "0x0000"),
                ("nwk_frametype", "0b00: "
                    "NWK Data"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b0: "
                    "NWK Security Disabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b0: "
                    "NWK Extended Source Omitted"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x1102"),
                ("nwk_srcshortaddr", "0x0000"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 241),
                ("aps_frametype", "0b01: "
                    "APS Command"),
                ("aps_delmode", "0b00: "
                    "Normal unicast delivery"),
                ("aps_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_security", "0b1: "
                    "APS Security Enabled"),
                ("aps_ackreq", "0b0: "
                    "The sender does not request an APS ACK"),
                ("aps_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_counter", 100),
                ("aps_aux_seclevel", "0b000: "
                    "None"),
                ("aps_aux_keytype", "0b10: "
                    "Key-Transport Key"),
                ("aps_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("aps_aux_framecounter", 10241),
                ("aps_aux_srcaddr", "7777770000000001"),
                ("aps_aux_deckey", "7fd574249d55ee1cb5f4663067d0a2f7"),
                ("aps_aux_decsrc", "7777770000000001"),
                ("aps_aux_decpayload", "05011111111111111111111111111111"
                                       "11110003000000007777770100000000"
                                       "777777"),
                ("aps_aux_decshow", None),
                ("aps_cmd_id", "0x05: "
                    "APS Transport Key"),
                ("aps_transportkey_stdkeytype", "0x01: "
                    "Standard Network Key"),
                ("aps_transportkey_key", "11111111111111111111111111111111"),
                ("aps_transportkey_keyseqnum", 0),
                ("aps_transportkey_dstextendedaddr", "7777770000000003"),
                ("aps_transportkey_srcextendedaddr", "7777770000000001"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Router"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Coordinator"),
                ("der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
                ("der_mac_dstpanid", "0xdddd"),
                ("der_mac_dstshortaddr", "0x1102"),
                ("der_mac_dstextendedaddr", "7777770000000003"),
                ("der_mac_srcpanid", "0xdddd"),
                ("der_mac_srcshortaddr", "0x0000"),
                ("der_mac_srcextendedaddr", "7777770000000001"),
                ("der_nwk_dstpanid", "0xdddd"),
                ("der_nwk_dstshortaddr", "0x1102"),
                ("der_nwk_dstextendedaddr", "7777770000000003"),
                ("der_nwk_srcpanid", "0xdddd"),
                ("der_nwk_srcshortaddr", "0x0000"),
                ("der_nwk_srcextendedaddr", "7777770000000001"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "04-aps-testing.pcap"),
                ("pkt_num", 3),
                ("pkt_time", 1599996931.0),
                ("phy_length", 51),
                ("phy_payload", "618802dddd000002110802000002111e"
                                "f2280228000003000000007777770063"
                                "7382faa41af8dede95aae7c71e62bc14"
                                "309e84"),
                ("mac_show", None),
                ("mac_fcs", "0x849e"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 2),
                ("mac_dstpanid", "0xdddd"),
                ("mac_dstshortaddr", "0x0000"),
                ("mac_srcshortaddr", "0x1102"),
                ("nwk_frametype", "0b00: "
                    "NWK Data"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b0: "
                    "NWK Extended Source Omitted"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x0000"),
                ("nwk_srcshortaddr", "0x1102"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 242),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10242),
                ("nwk_aux_srcaddr", "7777770000000003"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000003"),
                ("nwk_aux_decpayload", "0165060400000000777777012201"),
                ("nwk_aux_decshow", None),
                ("aps_frametype", "0b01: "
                    "APS Command"),
                ("aps_delmode", "0b00: "
                    "Normal unicast delivery"),
                ("aps_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_security", "0b0: "
                    "APS Security Disabled"),
                ("aps_ackreq", "0b0: "
                    "The sender does not request an APS ACK"),
                ("aps_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_counter", 101),
                ("aps_cmd_id", "0x06: "
                    "APS Update Device"),
                ("aps_updatedevice_extendedaddr", "7777770000000004"),
                ("aps_updatedevice_shortaddr", "0x2201"),
                ("aps_updatedevice_status", "0x01: "
                    "Standard device unsecured rejoin"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Coordinator"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Router"),
                ("der_nwk_dsttype", "NWK Dst Type: Zigbee Coordinator"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Router"),
                ("der_mac_dstpanid", "0xdddd"),
                ("der_mac_dstshortaddr", "0x0000"),
                ("der_mac_dstextendedaddr", "7777770000000001"),
                ("der_mac_srcpanid", "0xdddd"),
                ("der_mac_srcshortaddr", "0x1102"),
                ("der_mac_srcextendedaddr", "7777770000000003"),
                ("der_nwk_dstpanid", "0xdddd"),
                ("der_nwk_dstshortaddr", "0x0000"),
                ("der_nwk_dstextendedaddr", "7777770000000001"),
                ("der_nwk_srcpanid", "0xdddd"),
                ("der_nwk_srcshortaddr", "0x1102"),
                ("der_nwk_srcextendedaddr", "7777770000000003"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "04-aps-testing.pcap"),
                ("pkt_num", 4),
                ("pkt_time", 1599996932.0),
                ("phy_length", 58),
                ("phy_payload", "618803dddd021102220822000002221e"
                                "f32804280000050000000077777700e4"
                                "fe9e9dbe918f04f05dea7c6eb7d696f8"
                                "593a51ff2c698be1514f"),
                ("mac_show", None),
                ("mac_fcs", "0x4f51"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 3),
                ("mac_dstpanid", "0xdddd"),
                ("mac_dstshortaddr", "0x1102"),
                ("mac_srcshortaddr", "0x2202"),
                ("nwk_frametype", "0b00: "
                    "NWK Data"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b0: "
                    "NWK Extended Source Omitted"),
                ("nwk_edinitiator", "0b1: "
                    "NWK End Device Initiator"),
                ("nwk_dstshortaddr", "0x0000"),
                ("nwk_srcshortaddr", "0x2202"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 243),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10244),
                ("nwk_aux_srcaddr", "7777770000000005"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000005"),
                ("nwk_aux_decpayload", "216620032800000500000000777777a1"
                                       "72bdcebf07"),
                ("nwk_aux_decshow", None),
                ("aps_frametype", "0b01: "
                    "APS Command"),
                ("aps_delmode", "0b00: "
                    "Normal unicast delivery"),
                ("aps_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_security", "0b1: "
                    "APS Security Enabled"),
                ("aps_ackreq", "0b0: "
                    "The sender does not request an APS ACK"),
                ("aps_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_counter", 102),
                ("aps_aux_seclevel", "0b000: "
                    "None"),
                ("aps_aux_keytype", "0b00: "
                    "Data Key"),
                ("aps_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("aps_aux_framecounter", 10243),
                ("aps_aux_srcaddr", "7777770000000005"),
                ("aps_aux_deckey", "3c6047f3c55c8c8290a5839c213b6714"),
                ("aps_aux_decsrc", "7777770000000005"),
                ("aps_aux_decpayload", "0804"),
                ("aps_aux_decshow", None),
                ("aps_cmd_id", "0x08: "
                    "APS Request Key"),
                ("aps_requestkey_reqkeytype", "0x04: "
                    "Trust Center Link Key"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: False"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Router"),
                ("der_mac_srctype", "MAC Src Type: None"),
                ("der_nwk_dsttype", "NWK Dst Type: Zigbee Coordinator"),
                ("der_nwk_srctype", "NWK Src Type: None"),
                ("der_mac_dstpanid", "0xdddd"),
                ("der_mac_dstshortaddr", "0x1102"),
                ("der_mac_dstextendedaddr", "7777770000000003"),
                ("der_mac_srcpanid", "0xdddd"),
                ("der_mac_srcshortaddr", "0x2202"),
                ("der_mac_srcextendedaddr", "7777770000000005"),
                ("der_nwk_dstpanid", "0xdddd"),
                ("der_nwk_dstshortaddr", "0x0000"),
                ("der_nwk_dstextendedaddr", "7777770000000001"),
                ("der_nwk_srcpanid", "0xdddd"),
                ("der_nwk_srcshortaddr", "0x2202"),
                ("der_nwk_srcextendedaddr", "7777770000000005"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "04-aps-testing.pcap"),
                ("pkt_num", 5),
                ("pkt_time", 1599996933.0),
                ("phy_length", 102),
                ("phy_payload", "618804dddd021100000802021100001e"
                                "f4280628000001000000007777770085"
                                "8835951bb1bcf9e7d01df09ef712c00e"
                                "efb3b05cf09c3bd150aaa8ca119a6f66"
                                "f4726670110c801de6c83184305bebf4"
                                "fa35046d46952124f7ef6bbd08903fd6"
                                "be82ace1008c"),
                ("mac_show", None),
                ("mac_fcs", "0x8c00"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 4),
                ("mac_dstpanid", "0xdddd"),
                ("mac_dstshortaddr", "0x1102"),
                ("mac_srcshortaddr", "0x0000"),
                ("nwk_frametype", "0b00: "
                    "NWK Data"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b0: "
                    "NWK Extended Source Omitted"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x1102"),
                ("nwk_srcshortaddr", "0x0000"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 244),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10246),
                ("nwk_aux_srcaddr", "7777770000000001"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000001"),
                ("nwk_aux_decpayload", "01670e05000000007777772168300528"
                                       "00000100000000777777cc649d4d224f"
                                       "4ca1ecaf93b54bac7b35059ac2fc2499"
                                       "c197e2e819f64e356bc3818e1712b544"
                                       "e3"),
                ("nwk_aux_decshow", None),
                ("aps_frametype", "0b01: "
                    "APS Command"),
                ("aps_delmode", "0b00: "
                    "Normal unicast delivery"),
                ("aps_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_security", "0b0: "
                    "APS Security Disabled"),
                ("aps_ackreq", "0b0: "
                    "The sender does not request an APS ACK"),
                ("aps_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_counter", 103),
                ("aps_tunnel_dstextendedaddr", "7777770000000005"),
                ("aps_tunnel_frametype", "0b01: "
                    "APS Command"),
                ("aps_tunnel_delmode", "0b00: "
                    "Normal unicast delivery"),
                ("aps_tunnel_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_tunnel_security", "0b1: "
                    "APS Security Enabled"),
                ("aps_tunnel_ackreq", "0b0: "
                    "The sender does not request an APS ACK"),
                ("aps_tunnel_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_tunnel_counter", 104),
                ("aps_aux_seclevel", "0b000: "
                    "None"),
                ("aps_aux_keytype", "0b10: "
                    "Key-Transport Key"),
                ("aps_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("aps_aux_framecounter", 10245),
                ("aps_aux_srcaddr", "7777770000000001"),
                ("aps_aux_deckey", "1ea41eb62567f51bbe58e392552a8384"),
                ("aps_aux_decsrc", "7777770000000001"),
                ("aps_aux_decpayload", "05011111111111111111111111111111"
                                       "11110005000000007777770100000000"
                                       "777777"),
                ("aps_aux_decshow", None),
                ("aps_cmd_id", "0x0e: "
                    "APS Tunnel"),
                ("aps_tunnel_cmd_id", "0x05: "
                    "APS Transport Key"),
                ("aps_transportkey_stdkeytype", "0x01: "
                    "Standard Network Key"),
                ("aps_transportkey_key", "11111111111111111111111111111111"),
                ("aps_transportkey_keyseqnum", 0),
                ("aps_transportkey_dstextendedaddr", "7777770000000005"),
                ("aps_transportkey_srcextendedaddr", "7777770000000001"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Router"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Coordinator"),
                ("der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
                ("der_mac_dstpanid", "0xdddd"),
                ("der_mac_dstshortaddr", "0x1102"),
                ("der_mac_dstextendedaddr", "7777770000000003"),
                ("der_mac_srcpanid", "0xdddd"),
                ("der_mac_srcshortaddr", "0x0000"),
                ("der_mac_srcextendedaddr", "7777770000000001"),
                ("der_nwk_dstpanid", "0xdddd"),
                ("der_nwk_dstshortaddr", "0x1102"),
                ("der_nwk_dstextendedaddr", "7777770000000003"),
                ("der_nwk_srcpanid", "0xdddd"),
                ("der_nwk_srcshortaddr", "0x0000"),
                ("der_nwk_srcextendedaddr", "7777770000000001"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "04-aps-testing.pcap"),
                ("pkt_num", 6),
                ("pkt_time", 1599996934.0),
                ("phy_length", 94),
                ("phy_payload", "618805dddd021100000806022200001e"
                                "f5010002112808280000010000000077"
                                "777700d19df543cb1215afff9214f79f"
                                "dde657319e8d56f7b4f445ae538af8e9"
                                "8375464eda7f1187c985ce73fdce05ac"
                                "f3202d3d08c324c98678a51f71cc"),
                ("mac_show", None),
                ("mac_fcs", "0xcc71"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 5),
                ("mac_dstpanid", "0xdddd"),
                ("mac_dstshortaddr", "0x1102"),
                ("mac_srcshortaddr", "0x0000"),
                ("nwk_frametype", "0b00: "
                    "NWK Data"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b1: "
                    "NWK Source Route Included"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b0: "
                    "NWK Extended Source Omitted"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x2202"),
                ("nwk_srcshortaddr", "0x0000"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 245),
                ("nwk_srcroute_relaycount", 1),
                ("nwk_srcroute_relayindex", 0),
                ("nwk_srcroute_relaylist", "0x1102"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10248),
                ("nwk_aux_srcaddr", "7777770000000001"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000001"),
                ("nwk_aux_decpayload", "21693807280000010000000077777799"
                                       "262fa4394ec3d25fa0974709a3543127"
                                       "c5d73d2dc7d22cfcbc5099a8e92083c7"
                                       "0b8465267d"),
                ("nwk_aux_decshow", None),
                ("aps_frametype", "0b01: "
                    "APS Command"),
                ("aps_delmode", "0b00: "
                    "Normal unicast delivery"),
                ("aps_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_security", "0b1: "
                    "APS Security Enabled"),
                ("aps_ackreq", "0b0: "
                    "The sender does not request an APS ACK"),
                ("aps_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_counter", 105),
                ("aps_aux_seclevel", "0b000: "
                    "None"),
                ("aps_aux_keytype", "0b11: "
                    "Key-Load Key"),
                ("aps_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("aps_aux_framecounter", 10247),
                ("aps_aux_srcaddr", "7777770000000001"),
                ("aps_aux_deckey", "7ce4d9f97efa924c0c37617071954fb4"),
                ("aps_aux_decsrc", "7777770000000001"),
                ("aps_aux_decpayload", "05047777777777777777777777777777"
                                       "77770500000000777777010000000077"
                                       "7777"),
                ("aps_aux_decshow", None),
                ("aps_cmd_id", "0x05: "
                    "APS Transport Key"),
                ("aps_transportkey_stdkeytype", "0x04: "
                    "Trust Center Link Key"),
                ("aps_transportkey_key", "77777777777777777777777777777777"),
                ("aps_transportkey_dstextendedaddr", "7777770000000005"),
                ("aps_transportkey_srcextendedaddr", "7777770000000001"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: False"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Router"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Coordinator"),
                ("der_nwk_dsttype", "NWK Dst Type: None"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
                ("der_mac_dstpanid", "0xdddd"),
                ("der_mac_dstshortaddr", "0x1102"),
                ("der_mac_dstextendedaddr", "7777770000000003"),
                ("der_mac_srcpanid", "0xdddd"),
                ("der_mac_srcshortaddr", "0x0000"),
                ("der_mac_srcextendedaddr", "7777770000000001"),
                ("der_nwk_dstpanid", "0xdddd"),
                ("der_nwk_dstshortaddr", "0x2202"),
                ("der_nwk_dstextendedaddr", "7777770000000005"),
                ("der_nwk_srcpanid", "0xdddd"),
                ("der_nwk_srcshortaddr", "0x0000"),
                ("der_nwk_srcextendedaddr", "7777770000000001"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "04-aps-testing.pcap"),
                ("pkt_num", 7),
                ("pkt_time", 1599996935.0),
                ("phy_length", 65),
                ("phy_payload", "618806dddd021102220822000002221e"
                                "f6280928000005000000007777770076"
                                "8f7929dd7656778f5f7be60cfd955544"
                                "b806f43876c6ce07dff20d1d7a6af509"
                                "5a"),
                ("mac_show", None),
                ("mac_fcs", "0x5a09"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 6),
                ("mac_dstpanid", "0xdddd"),
                ("mac_dstshortaddr", "0x1102"),
                ("mac_srcshortaddr", "0x2202"),
                ("nwk_frametype", "0b00: "
                    "NWK Data"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b0: "
                    "NWK Extended Source Omitted"),
                ("nwk_edinitiator", "0b1: "
                    "NWK End Device Initiator"),
                ("nwk_dstshortaddr", "0x0000"),
                ("nwk_srcshortaddr", "0x2202"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 246),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10249),
                ("nwk_aux_srcaddr", "7777770000000005"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000005"),
                ("nwk_aux_decpayload", "416a0f04050000000077777744761a20"
                                       "e1b77e6d6da445f80dc9bee6"),
                ("nwk_aux_decshow", None),
                ("aps_frametype", "0b01: "
                    "APS Command"),
                ("aps_delmode", "0b00: "
                    "Normal unicast delivery"),
                ("aps_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_security", "0b0: "
                    "APS Security Disabled"),
                ("aps_ackreq", "0b1: "
                    "The sender requests an APS ACK"),
                ("aps_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_counter", 106),
                ("aps_cmd_id", "0x0f: "
                    "APS Verify Key"),
                ("aps_verifykey_stdkeytype", "0x04: "
                    "Trust Center Link Key"),
                ("aps_verifykey_extendedaddr", "7777770000000005"),
                ("aps_verifykey_keyhash", "44761a20e1b77e6d6da445f80dc9bee6"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: False"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Router"),
                ("der_mac_srctype", "MAC Src Type: None"),
                ("der_nwk_dsttype", "NWK Dst Type: Zigbee Coordinator"),
                ("der_nwk_srctype", "NWK Src Type: None"),
                ("der_mac_dstpanid", "0xdddd"),
                ("der_mac_dstshortaddr", "0x1102"),
                ("der_mac_dstextendedaddr", "7777770000000003"),
                ("der_mac_srcpanid", "0xdddd"),
                ("der_mac_srcshortaddr", "0x2202"),
                ("der_mac_srcextendedaddr", "7777770000000005"),
                ("der_nwk_dstpanid", "0xdddd"),
                ("der_nwk_dstshortaddr", "0x0000"),
                ("der_nwk_dstextendedaddr", "7777770000000001"),
                ("der_nwk_srcpanid", "0xdddd"),
                ("der_nwk_srcshortaddr", "0x2202"),
                ("der_nwk_srcextendedaddr", "7777770000000005"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "04-aps-testing.pcap"),
                ("pkt_num", 8),
                ("pkt_time", 1599996936.0),
                ("phy_length", 71),
                ("phy_payload", "618807dddd021100000806022200001e"
                                "f701000211280b280000010000000077"
                                "777700a51ab28a7b75473e079cfae1dd"
                                "4b0465e7c324fed38728259f8005b18a"
                                "f2aa35b585b4f9"),
                ("mac_show", None),
                ("mac_fcs", "0xf9b4"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 7),
                ("mac_dstpanid", "0xdddd"),
                ("mac_dstshortaddr", "0x1102"),
                ("mac_srcshortaddr", "0x0000"),
                ("nwk_frametype", "0b00: "
                    "NWK Data"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b1: "
                    "NWK Source Route Included"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b0: "
                    "NWK Extended Source Omitted"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x2202"),
                ("nwk_srcshortaddr", "0x0000"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 247),
                ("nwk_srcroute_relaycount", 1),
                ("nwk_srcroute_relayindex", 0),
                ("nwk_srcroute_relaylist", "0x1102"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10251),
                ("nwk_aux_srcaddr", "7777770000000001"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000001"),
                ("nwk_aux_decpayload", "616b200a2800000100000000777777f4"
                                       "7eaf4f21f699864b20fd30db5d1e"),
                ("nwk_aux_decshow", None),
                ("aps_frametype", "0b01: "
                    "APS Command"),
                ("aps_delmode", "0b00: "
                    "Normal unicast delivery"),
                ("aps_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_security", "0b1: "
                    "APS Security Enabled"),
                ("aps_ackreq", "0b1: "
                    "The sender requests an APS ACK"),
                ("aps_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_counter", 107),
                ("aps_aux_seclevel", "0b000: "
                    "None"),
                ("aps_aux_keytype", "0b00: "
                    "Data Key"),
                ("aps_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("aps_aux_framecounter", 10250),
                ("aps_aux_srcaddr", "7777770000000001"),
                ("aps_aux_deckey", "77777777777777777777777777777777"),
                ("aps_aux_decsrc", "7777770000000001"),
                ("aps_aux_decpayload", "1000040500000000777777"),
                ("aps_aux_decshow", None),
                ("aps_cmd_id", "0x10: "
                    "APS Confirm Key"),
                ("aps_confirmkey_status", "0x00: "
                    "SUCCESS"),
                ("aps_confirmkey_stdkeytype", "0x04: "
                    "Trust Center Link Key"),
                ("aps_confirmkey_extendedaddr", "7777770000000005"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: False"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Router"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Coordinator"),
                ("der_nwk_dsttype", "NWK Dst Type: None"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
                ("der_mac_dstpanid", "0xdddd"),
                ("der_mac_dstshortaddr", "0x1102"),
                ("der_mac_dstextendedaddr", "7777770000000003"),
                ("der_mac_srcpanid", "0xdddd"),
                ("der_mac_srcshortaddr", "0x0000"),
                ("der_mac_srcextendedaddr", "7777770000000001"),
                ("der_nwk_dstpanid", "0xdddd"),
                ("der_nwk_dstshortaddr", "0x2202"),
                ("der_nwk_dstextendedaddr", "7777770000000005"),
                ("der_nwk_srcpanid", "0xdddd"),
                ("der_nwk_srcshortaddr", "0x0000"),
                ("der_nwk_srcextendedaddr", "7777770000000001"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "04-aps-testing.pcap"),
                ("pkt_num", 9),
                ("pkt_time", 1599996937.0),
                ("phy_length", 73),
                ("phy_payload", "618808ccbb023300000800023300001e"
                                "f8216c300c2800000100000000888888"
                                "8845b02807a59c4ec310ceaf16630456"
                                "1794f1e8ed2e4b9f584fc41bae5ab7ca"
                                "2c10b160c6442fcd4b"),
                ("mac_show", None),
                ("mac_fcs", "0x4bcd"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 8),
                ("mac_dstpanid", "0xbbcc"),
                ("mac_dstshortaddr", "0x3302"),
                ("mac_srcshortaddr", "0x0000"),
                ("nwk_frametype", "0b00: "
                    "NWK Data"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b0: "
                    "NWK Security Disabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b0: "
                    "NWK Extended Source Omitted"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x3302"),
                ("nwk_srcshortaddr", "0x0000"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 248),
                ("aps_frametype", "0b01: "
                    "APS Command"),
                ("aps_delmode", "0b00: "
                    "Normal unicast delivery"),
                ("aps_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_security", "0b1: "
                    "APS Security Enabled"),
                ("aps_ackreq", "0b0: "
                    "The sender does not request an APS ACK"),
                ("aps_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_counter", 108),
                ("aps_aux_seclevel", "0b000: "
                    "None"),
                ("aps_aux_keytype", "0b10: "
                    "Key-Transport Key"),
                ("aps_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("aps_aux_framecounter", 10252),
                ("aps_aux_srcaddr", "8888880000000001"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: None"),
                ("der_mac_srctype", "MAC Src Type: None"),
                ("der_nwk_dsttype", "NWK Dst Type: None"),
                ("der_nwk_srctype", "NWK Src Type: None"),
                ("der_mac_dstpanid", "0xbbcc"),
                ("der_mac_dstshortaddr", "0x3302"),
                ("der_mac_srcpanid", "0xbbcc"),
                ("der_mac_srcshortaddr", "0x0000"),
                ("der_nwk_dstpanid", "0xbbcc"),
                ("der_nwk_dstshortaddr", "0x3302"),
                ("der_nwk_srcpanid", "0xbbcc"),
                ("der_nwk_srcshortaddr", "0x0000"),
                ("warning_msg", "PW401: Unable to decrypt the APS payload"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "04-aps-testing.pcap"),
                ("pkt_num", 10),
                ("pkt_time", 1599996938.0),
                ("phy_length", 102),
                ("phy_payload", "618809dddd021100000802021100001e"
                                "f9280e28000001000000007777770091"
                                "2877e54569311d5801bb164a4f22aacf"
                                "0271e4e3ab3034ad3ed6011519e6281a"
                                "437cf2020f351cef28a43aa02e4fe88c"
                                "ac30135bacec3453ea2478af4e0343a6"
                                "abdf871f690f"),
                ("mac_show", None),
                ("mac_fcs", "0x0f69"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 9),
                ("mac_dstpanid", "0xdddd"),
                ("mac_dstshortaddr", "0x1102"),
                ("mac_srcshortaddr", "0x0000"),
                ("nwk_frametype", "0b00: "
                    "NWK Data"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b0: "
                    "NWK Extended Source Omitted"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x1102"),
                ("nwk_srcshortaddr", "0x0000"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 249),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10254),
                ("nwk_aux_srcaddr", "7777770000000001"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000001"),
                ("nwk_aux_decpayload", "016d0e0600000000777777216e300d28"
                                       "00000100000000777777212d9e96d1d1"
                                       "9d39efe53d826e20921ace4ef24e4108"
                                       "172c5ccdf55383cb0aad2603e31bbc85"
                                       "ba"),
                ("nwk_aux_decshow", None),
                ("aps_frametype", "0b01: "
                    "APS Command"),
                ("aps_delmode", "0b00: "
                    "Normal unicast delivery"),
                ("aps_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_security", "0b0: "
                    "APS Security Disabled"),
                ("aps_ackreq", "0b0: "
                    "The sender does not request an APS ACK"),
                ("aps_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_counter", 109),
                ("aps_tunnel_dstextendedaddr", "7777770000000006"),
                ("aps_tunnel_frametype", "0b01: "
                    "APS Command"),
                ("aps_tunnel_delmode", "0b00: "
                    "Normal unicast delivery"),
                ("aps_tunnel_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_tunnel_security", "0b1: "
                    "APS Security Enabled"),
                ("aps_tunnel_ackreq", "0b0: "
                    "The sender does not request an APS ACK"),
                ("aps_tunnel_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_tunnel_counter", 110),
                ("aps_aux_seclevel", "0b000: "
                    "None"),
                ("aps_aux_keytype", "0b10: "
                    "Key-Transport Key"),
                ("aps_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("aps_aux_framecounter", 10253),
                ("aps_aux_srcaddr", "7777770000000001"),
                ("aps_cmd_id", "0x0e: "
                    "APS Tunnel"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Router"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Coordinator"),
                ("der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
                ("der_mac_dstpanid", "0xdddd"),
                ("der_mac_dstshortaddr", "0x1102"),
                ("der_mac_dstextendedaddr", "7777770000000003"),
                ("der_mac_srcpanid", "0xdddd"),
                ("der_mac_srcshortaddr", "0x0000"),
                ("der_mac_srcextendedaddr", "7777770000000001"),
                ("der_nwk_dstpanid", "0xdddd"),
                ("der_nwk_dstshortaddr", "0x1102"),
                ("der_nwk_dstextendedaddr", "7777770000000003"),
                ("der_nwk_srcpanid", "0xdddd"),
                ("der_nwk_srcshortaddr", "0x0000"),
                ("der_nwk_srcextendedaddr", "7777770000000001"),
                ("warning_msg", "PW401: Unable to decrypt the APS payload"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "04-aps-testing.pcap"),
                ("pkt_num", 11),
                ("pkt_time", 1599996939.0),
                ("phy_length", 71),
                ("phy_payload", "61880adddd021100000806042200001e"
                                "fa010002112810280000010000000077"
                                "77770064daa9fd5bf73111bfe5590ef3"
                                "d37667c1f524ac937a39ee7ddda6661d"
                                "4c614fcb1ed67a"),
                ("mac_show", None),
                ("mac_fcs", "0x7ad6"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 10),
                ("mac_dstpanid", "0xdddd"),
                ("mac_dstshortaddr", "0x1102"),
                ("mac_srcshortaddr", "0x0000"),
                ("nwk_frametype", "0b00: "
                    "NWK Data"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b1: "
                    "NWK Source Route Included"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b0: "
                    "NWK Extended Source Omitted"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x2204"),
                ("nwk_srcshortaddr", "0x0000"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 250),
                ("nwk_srcroute_relaycount", 1),
                ("nwk_srcroute_relayindex", 0),
                ("nwk_srcroute_relaylist", "0x1102"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10256),
                ("nwk_aux_srcaddr", "7777770000000001"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000001"),
                ("nwk_aux_decpayload", "616f200f2800000100000000777777ee"
                                       "b4ddfdebbb3954077f42c3f435c6"),
                ("nwk_aux_decshow", None),
                ("aps_frametype", "0b01: "
                    "APS Command"),
                ("aps_delmode", "0b00: "
                    "Normal unicast delivery"),
                ("aps_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_security", "0b1: "
                    "APS Security Enabled"),
                ("aps_ackreq", "0b1: "
                    "The sender requests an APS ACK"),
                ("aps_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_counter", 111),
                ("aps_aux_seclevel", "0b000: "
                    "None"),
                ("aps_aux_keytype", "0b00: "
                    "Data Key"),
                ("aps_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("aps_aux_framecounter", 10255),
                ("aps_aux_srcaddr", "7777770000000001"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: False"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Router"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Coordinator"),
                ("der_nwk_dsttype", "NWK Dst Type: None"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
                ("der_mac_dstpanid", "0xdddd"),
                ("der_mac_dstshortaddr", "0x1102"),
                ("der_mac_dstextendedaddr", "7777770000000003"),
                ("der_mac_srcpanid", "0xdddd"),
                ("der_mac_srcshortaddr", "0x0000"),
                ("der_mac_srcextendedaddr", "7777770000000001"),
                ("der_nwk_dstpanid", "0xdddd"),
                ("der_nwk_dstshortaddr", "0x2204"),
                ("der_nwk_srcpanid", "0xdddd"),
                ("der_nwk_srcshortaddr", "0x0000"),
                ("der_nwk_srcextendedaddr", "7777770000000001"),
                ("warning_msg", "PW401: Unable to decrypt the APS payload"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "05-zdp-testing.pcap"),
                ("pkt_num", 1),
                ("pkt_time", 1599997185.0),
                ("phy_length", 64),
                ("phy_payload", "418840ddddffff02110812fdff02111e"
                                "c0030000000077777728f02800000300"
                                "000000777777003ff95cf26fbd92a1eb"
                                "609e76862aa4a1967eebc4dd2ab50c9d"),
                ("mac_show", None),
                ("mac_fcs", "0x9d0c"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 64),
                ("mac_dstpanid", "0xdddd"),
                ("mac_dstshortaddr", "0xffff"),
                ("mac_srcshortaddr", "0x1102"),
                ("nwk_frametype", "0b00: "
                    "NWK Data"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b1: "
                    "NWK Extended Source Included"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0xfffd"),
                ("nwk_srcshortaddr", "0x1102"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 192),
                ("nwk_srcextendedaddr", "7777770000000003"),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10480),
                ("nwk_aux_srcaddr", "7777770000000003"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000003"),
                ("nwk_aux_decpayload", "08000000000000e98501000000007777"
                                       "770000"),
                ("nwk_aux_decshow", None),
                ("aps_frametype", "0b00: "
                    "APS Data"),
                ("aps_delmode", "0b10: "
                    "Broadcast"),
                ("aps_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_security", "0b0: "
                    "APS Security Disabled"),
                ("aps_ackreq", "0b0: "
                    "The sender does not request an APS ACK"),
                ("aps_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_dstendpoint", 0),
                ("aps_cluster_id", "0x0000: "
                    "NWK_addr_req"),
                ("aps_profile_id", "0x0000: "
                    "Zigbee Device Profile (ZDP)"),
                ("aps_srcendpoint", 0),
                ("aps_counter", 233),
                ("zdp_seqnum", 133),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: False"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Broadcast"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Router"),
                ("der_nwk_dsttype", "NWK Dst Type: All active receivers"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Router"),
                ("der_mac_dstpanid", "0xdddd"),
                ("der_mac_dstshortaddr", "0xffff"),
                ("der_mac_srcpanid", "0xdddd"),
                ("der_mac_srcshortaddr", "0x1102"),
                ("der_mac_srcextendedaddr", "7777770000000003"),
                ("der_nwk_dstpanid", "0xdddd"),
                ("der_nwk_dstshortaddr", "0xfffd"),
                ("der_nwk_srcpanid", "0xdddd"),
                ("der_nwk_srcshortaddr", "0x1102"),
                ("der_nwk_srcextendedaddr", "7777770000000003"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "06-zcl-testing.pcap"),
                ("pkt_num", 1),
                ("pkt_time", 1599997441.0),
                ("phy_length", 50),
                ("phy_payload", "618840dddd021100000802021100001e"
                                "c028e029000001000000007777770095"
                                "ff22b54b9a50b6d5676b0c2f671af32c"
                                "9042"),
                ("mac_show", None),
                ("mac_fcs", "0x4290"),
                ("mac_frametype", "0b001: "
                    "MAC Data"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b1: "
                    "The sender requests a MAC Acknowledgment"),
                ("mac_panidcomp", "0b1: "
                    "The source PAN ID is the same "
                    "as the destination PAN ID"),
                ("mac_dstaddrmode", "0b10: "
                    "Short destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b10: "
                    "Short source MAC address"),
                ("mac_seqnum", 64),
                ("mac_dstpanid", "0xdddd"),
                ("mac_dstshortaddr", "0x1102"),
                ("mac_srcshortaddr", "0x0000"),
                ("nwk_frametype", "0b00: "
                    "NWK Data"),
                ("nwk_protocolversion", "0b0010: "
                    "Zigbee PRO"),
                ("nwk_discroute", "0b0: "
                    "Suppress route discovery"),
                ("nwk_multicast", "0b0: "
                    "NWK Multicast Disabled"),
                ("nwk_security", "0b1: "
                    "NWK Security Enabled"),
                ("nwk_srcroute", "0b0: "
                    "NWK Source Route Omitted"),
                ("nwk_extendeddst", "0b0: "
                    "NWK Extended Destination Omitted"),
                ("nwk_extendedsrc", "0b0: "
                    "NWK Extended Source Omitted"),
                ("nwk_edinitiator", "0b0: "
                    "NWK Not End Device Initiator"),
                ("nwk_dstshortaddr", "0x1102"),
                ("nwk_srcshortaddr", "0x0000"),
                ("nwk_radius", 30),
                ("nwk_seqnum", 192),
                ("nwk_aux_seclevel", "0b000: "
                    "None"),
                ("nwk_aux_keytype", "0b01: "
                    "Network Key"),
                ("nwk_aux_extnonce", "0b1: "
                    "The source address is present"),
                ("nwk_aux_framecounter", 10720),
                ("nwk_aux_srcaddr", "7777770000000001"),
                ("nwk_aux_keyseqnum", 0),
                ("nwk_aux_deckey", "11111111111111111111111111111111"),
                ("nwk_aux_decsrc", "7777770000000001"),
                ("nwk_aux_decpayload", "40010000040101500000000100"),
                ("nwk_aux_decshow", None),
                ("aps_frametype", "0b00: "
                    "APS Data"),
                ("aps_delmode", "0b00: "
                    "Normal unicast delivery"),
                ("aps_ackformat", "0b0: "
                    "APS ACK Format Disabled"),
                ("aps_security", "0b0: "
                    "APS Security Disabled"),
                ("aps_ackreq", "0b1: "
                    "The sender requests an APS ACK"),
                ("aps_exthdr", "0b0: "
                    "The extended header is not included"),
                ("aps_dstendpoint", 1),
                ("aps_cluster_id", "0x0000: "
                    "Basic"),
                ("aps_profile_id", "0x0104: "
                    "Zigbee Home Automation (ZHA)"),
                ("aps_srcendpoint", 1),
                ("aps_counter", 80),
                ("zcl_frametype", "0b00: "
                    "Global Command"),
                ("zcl_manufspecific", "0b0: "
                    "The command is not manufacturer-specific"),
                ("zcl_direction", "0b0: "
                    "From the client to the server"),
                ("zcl_disdefrsp", "0b0: "
                    "A Default Response will be returned"),
                ("zcl_seqnum", 0),
                ("zcl_cmd_id", "0x00: "
                    "Read Attributes"),
                ("der_same_macnwkdst", "Same MAC/NWK Dst: True"),
                ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
                ("der_tx_type", "Multi-Hop Transmission"),
                ("der_mac_dsttype", "MAC Dst Type: Zigbee Router"),
                ("der_mac_srctype", "MAC Src Type: Zigbee Coordinator"),
                ("der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
                ("der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
                ("der_mac_dstpanid", "0xdddd"),
                ("der_mac_dstshortaddr", "0x1102"),
                ("der_mac_dstextendedaddr", "7777770000000003"),
                ("der_mac_srcpanid", "0xdddd"),
                ("der_mac_srcshortaddr", "0x0000"),
                ("der_mac_srcextendedaddr", "7777770000000001"),
                ("der_nwk_dstpanid", "0xdddd"),
                ("der_nwk_dstshortaddr", "0x1102"),
                ("der_nwk_dstextendedaddr", "7777770000000003"),
                ("der_nwk_srcpanid", "0xdddd"),
                ("der_nwk_srcshortaddr", "0x0000"),
                ("der_nwk_srcextendedaddr", "7777770000000001"),
            ],
            [
                ("pcap_directory", None),
                ("pcap_filename", "07-sll-testing.pcap"),
                ("pkt_num", 1),
                ("pkt_time", 1599997697.0),
                ("sll_pkttype", "0x0003: "
                    "The packet was sent to another host by another host"),
                ("sll_arphrdtype", 0x0325),
                ("sll_addrlength", 0),
                ("sll_addr", "0000000000000000"),
                ("sll_protocoltype", 0x00f6),
                ("phy_length", 5),
                ("phy_payload", "02007780b2"),
                ("mac_show", None),
                ("mac_fcs", "0xb280"),
                ("mac_frametype", "0b010: "
                    "MAC Acknowledgment"),
                ("mac_security", "0b0: "
                    "MAC Security Disabled"),
                ("mac_framepending", "0b0: "
                    "No additional packets are pending for the receiver"),
                ("mac_ackreq", "0b0: "
                    "The sender does not request a MAC Acknowledgment"),
                ("mac_panidcomp", "0b0: "
                    "Do not compress the source PAN ID"),
                ("mac_dstaddrmode", "0b00: "
                    "No destination MAC address"),
                ("mac_frameversion", "0b00: "
                    "IEEE 802.15.4-2003 Frame Version"),
                ("mac_srcaddrmode", "0b00: "
                    "No source MAC address"),
                ("mac_seqnum", 119),
                ("der_tx_type", "Single-Hop Transmission"),
            ],
        ]
        self.assert_entries(obtained_entries, expected_entries)

    def assertPairsTable(self, cursor):
        cursor.execute("SELECT * FROM pairs ORDER BY panid, dstaddr, srcaddr")
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
                ("0x1102", "0x0000", "0x7777", 1599996677.0, 1599996681.0),
                ("0x1102", "0x1101", "0x7777", 1599996674.0, 1599996675.0),
                ("0x2201", "0x1102", "0x7777", 1599996678.0, 1599996678.0),
                ("0x2202", "0x1102", "0x7777", 1599996683.0, 1599996683.0),
                ("0x1102", "0x2201", "0x7777", 1599996679.0, 1599996679.0),
                ("0x1102", "0x2202", "0x7777", 1599996684.0, 1599996684.0),
                ("0xb000", "0x0000", "0x9999", 1599996686.0, 1599996687.0),
                ("0x0000", "0x3302", "0xbbcc", 1599996937.0, 1599996937.0),
                ("0x1102", "0x0000", "0xdddd", 1599996929.0, 1599996931.0),
                ("0x0000", "0x1102", "0xdddd", 1599996930.0, 1599997441.0),
                ("0x2202", "0x1102", "0xdddd", 1599996932.0, 1599996935.0),
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
