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

import logging
import os
import time

from scapy.all import PcapReader


def main(pcap_filepath):
    """Monitor packets from a pcap file continuously."""
    if not os.path.isfile(pcap_filepath):
        raise ValueError("The provided pcap file \"{}\" "
                         "does not exist".format(pcap_filepath))

    logging.info("Monitoring packets from the \"{}\" file until "
                 "the interrupt key (Ctrl-C) is hit...".format(pcap_filepath))
    pcap_reader = PcapReader(pcap_filepath)
    try:
        while True:
            try:
                pkt = pcap_reader.__next__()
                print(pkt.summary())
            except StopIteration:
                time.sleep(0.005)
    except KeyboardInterrupt:
        pcap_reader.close()
        logging.info("Finished the monitoring of packets from the \"{}\" file"
                     "".format(pcap_filepath))
