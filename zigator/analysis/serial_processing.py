# Copyright (C) 2022 Dimitrios-Georgios Akestoridis
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
import multiprocessing as mp
import os

from .. import config


NWK_COMMAND_IDENTIFIERS = [
    "0x01: NWK Route Request",
    "0x02: NWK Route Reply",
    "0x03: NWK Network Status",
    "0x04: NWK Leave",
    "0x05: NWK Route Record",
    "0x06: NWK Rejoin Request",
    "0x07: NWK Rejoin Response",
    "0x08: NWK Link Status",
    "0x09: NWK Network Report",
    "0x0a: NWK Network Update",
    "0x0b: NWK End Device Timeout Request",
    "0x0c: NWK End Device Timeout Response",
]


def serial_processing(db_filepath, tablename, out_dirpath, num_workers):
    """Process data from captured packets serially."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Connect to the provided database
    config.db.connect(db_filepath)

    # Fetch distinct and sorted pairs of pcap directories and filenames
    logging.info("Fetching information about distinct pcap files...")
    pcap_tuples = config.db.fetch_values(
        tablename,
        ["pcap_directory", "pcap_filename"],
        None,
        True,
        ["pcap_directory", "pcap_filename"],
    )

    # Determine the number of processes that will be used
    if num_workers is None:
        if hasattr(os, "sched_getaffinity"):
            num_workers = len(os.sched_getaffinity(0))
        else:
            num_workers = mp.cpu_count()
    if num_workers < 1:
        num_workers = 1
    logging.info(
        "Processing data from captured packets serially "
        + "that were in {} pcap files using {} workers...".format(
            len(pcap_tuples),
            num_workers,
        ),
    )

    # Create variables that will be shared by the processes
    task_index = mp.Value("L", 0, lock=False)
    task_lock = mp.Lock()

    # Start the processes
    processes = []
    for _ in range(num_workers):
        p = mp.Process(
            target=worker,
            args=(
                db_filepath,
                tablename,
                pcap_tuples,
                out_dirpath,
                task_index,
                task_lock,
            ),
        )
        p.start()
        processes.append(p)

    # Make sure that all processes terminated
    for p in processes:
        p.join()
    logging.info("All {} workers completed their tasks".format(num_workers))


def worker(
    db_filepath,
    tablename,
    pcap_tuples,
    out_dirpath,
    task_index,
    task_lock,
):
    # Connect to the provided database
    config.db.connect(db_filepath)

    pcap_id = 0
    while True:
        with task_lock:
            # Get the next task
            if task_index.value < len(pcap_tuples):
                pcap_directory, pcap_filename = pcap_tuples[task_index.value]
                task_index.value += 1
                pcap_id = task_index.value
            else:
                break

        # Fetch data about each packet that was in the provided pcap file,
        # sorted by packet time
        fetched_tuples = config.db.fetch_values(
            tablename,
            [
                "pkt_time",
                "error_msg",
                "nwk_frametype",
                "nwk_security",
                "nwk_cmd_id",
                "nwk_cmd_payloadlength",
                "der_tx_type",
                "der_nwk_dsttype",
                "der_nwk_srctype",
                "mac_frametype",
                "mac_panidcomp",
                "mac_srcpanid",
                "mac_dstaddrmode",
                "mac_srcaddrmode",
                "mac_dstshortaddr",
                "mac_srcshortaddr",
                "mac_dstpanid",
                "nwk_dstshortaddr",
                "nwk_srcshortaddr",
                "mac_cmd_id",
                "mac_realign_panid",
                "mac_realign_coordaddr",
                "mac_realign_shortaddr",
            ],
            [
                ("pcap_directory", pcap_directory),
                ("pcap_filename", pcap_filename),
            ],
            False,
            ["pkt_time"],
        )

        # Predict the name of each encrypted NWK command identifier
        confusion_matrix = {}
        latest_beacon = {}
        latest_data = {}
        latest_realign = {}
        latest_panid = {}
        latest_addr = {}
        for fetched_tuple in fetched_tuples:
            pkt_time = fetched_tuple[0]
            error_msg = fetched_tuple[1]
            nwk_frametype = fetched_tuple[2]
            nwk_security = fetched_tuple[3]
            nwk_cmd_id = fetched_tuple[4]
            nwk_cmd_payloadlength = fetched_tuple[5]
            der_tx_type = fetched_tuple[6]
            der_nwk_dsttype = fetched_tuple[7]
            der_nwk_srctype = fetched_tuple[8]
            mac_frametype = fetched_tuple[9]
            mac_panidcomp = fetched_tuple[10]
            mac_srcpanid = fetched_tuple[11]
            mac_dstaddrmode = fetched_tuple[12]
            mac_srcaddrmode = fetched_tuple[13]
            mac_dstshortaddr = fetched_tuple[14]
            mac_srcshortaddr = fetched_tuple[15]
            mac_dstpanid = fetched_tuple[16]
            nwk_dstshortaddr = fetched_tuple[17]
            nwk_srcshortaddr = fetched_tuple[18]
            mac_cmd_id = fetched_tuple[19]
            mac_realign_panid = fetched_tuple[20]
            mac_realign_coordaddr = fetched_tuple[21]
            mac_realign_shortaddr = fetched_tuple[22]

            if (
                error_msg is None
                and mac_frametype == "0b000: MAC Beacon"
                and mac_srcpanid is not None
                and mac_srcaddrmode == "0b10: Short source MAC address"
                and mac_srcshortaddr is not None
            ):
                latest_beacon[(mac_srcpanid, mac_srcshortaddr)] = pkt_time

            if (
                error_msg is None
                and mac_frametype == "0b001: MAC Data"
                and mac_panidcomp.startswith("0b1:")
                and mac_dstaddrmode == "0b10: Short destination MAC address"
                and mac_srcaddrmode == "0b10: Short source MAC address"
                and mac_dstpanid is not None
                and mac_dstshortaddr is not None
                and mac_srcshortaddr is not None
            ):
                latest_data[
                    (
                        mac_dstpanid,
                        mac_dstshortaddr,
                        mac_srcshortaddr,
                    )
                ] = pkt_time

            if (
                error_msg is None
                and mac_frametype == "0b011: MAC Command"
                and mac_cmd_id == "0x08: MAC Coordinator Realignment"
                and mac_realign_panid is not None
                and mac_realign_coordaddr is not None
                and mac_realign_shortaddr is not None
            ):
                latest_realign[
                    (
                        mac_realign_panid,
                        mac_realign_shortaddr,
                        mac_realign_coordaddr,
                    )
                ] = pkt_time

            if (
                error_msg is None
                and mac_srcpanid is not None
                and int(mac_srcpanid, 16) >= 0
                and int(mac_srcpanid, 16) <= 65534
            ):
                latest_panid[mac_srcpanid] = pkt_time

            if (
                error_msg is None
                and mac_dstpanid is not None
                and int(mac_dstpanid, 16) >= 0
                and int(mac_dstpanid, 16) <= 65534
            ):
                latest_panid[mac_dstpanid] = pkt_time

            if (
                error_msg is None
                and mac_frametype == "0b001: MAC Data"
                and mac_panidcomp.startswith("0b1:")
                and mac_dstaddrmode == "0b10: Short destination MAC address"
                and mac_srcaddrmode == "0b10: Short source MAC address"
                and mac_dstpanid is not None
                and int(mac_dstpanid, 16) >= 0
                and int(mac_dstpanid, 16) <= 65534
                and mac_dstshortaddr is not None
                and mac_srcshortaddr is not None
            ):
                if (
                    int(mac_dstshortaddr, 16) >= 0
                    and int(mac_dstshortaddr, 16) <= 65527
                ):
                    latest_addr[
                        (
                            mac_dstpanid,
                            mac_dstshortaddr,
                        )
                    ] = pkt_time

                if (
                    int(mac_srcshortaddr, 16) >= 0
                    and int(mac_srcshortaddr, 16) <= 65527
                ):
                    latest_addr[
                        (
                            mac_dstpanid,
                            mac_srcshortaddr,
                        )
                    ] = pkt_time

                if (
                    nwk_dstshortaddr is not None
                    and int(nwk_dstshortaddr, 16) >= 0
                    and int(nwk_dstshortaddr, 16) <= 65527
                ):
                    latest_addr[
                        (
                            mac_dstpanid,
                            nwk_dstshortaddr,
                        )
                    ] = pkt_time

                if (
                    nwk_srcshortaddr is not None
                    and int(nwk_srcshortaddr, 16) >= 0
                    and int(nwk_srcshortaddr, 16) <= 65527
                ):
                    latest_addr[
                        (
                            mac_dstpanid,
                            nwk_srcshortaddr,
                        )
                    ] = pkt_time

            if (
                error_msg is None
                and nwk_frametype == "0b01: NWK Command"
                and nwk_security == "0b1: NWK Security Enabled"
                and nwk_cmd_id is not None
            ):
                last_beacon_time = None
                if (mac_dstpanid, nwk_dstshortaddr) in latest_beacon.keys():
                    last_beacon_time = latest_beacon[
                        (
                            mac_dstpanid,
                            nwk_dstshortaddr,
                        )
                    ]

                last_data_time = None
                if (
                    (
                        mac_dstpanid,
                        nwk_srcshortaddr,
                        nwk_dstshortaddr,
                    ) in latest_data.keys()
                ):
                    last_data_time = latest_data[
                        (
                            mac_dstpanid,
                            nwk_srcshortaddr,
                            nwk_dstshortaddr,
                        )
                    ]

                last_realign_time = None
                if (
                    (
                        mac_dstpanid,
                        nwk_srcshortaddr,
                        nwk_dstshortaddr,
                    ) in latest_realign.keys()
                ):
                    last_realign_time = latest_realign[
                        (
                            mac_dstpanid,
                            nwk_srcshortaddr,
                            nwk_dstshortaddr,
                        )
                    ]

                max_beacon_time = None
                if len(latest_beacon.keys()) > 0:
                    max_beacon_time = max(latest_beacon.values())

                num_panids = 0
                for panid in latest_panid.keys():
                    if pkt_time - latest_panid[panid] < 360.0:
                        num_panids += 1

                num_short_addresses = 0
                for panid, shortaddr in latest_addr.keys():
                    if (
                        panid == mac_dstpanid
                        and pkt_time - latest_addr[(panid, shortaddr)] < 360.0
                    ):
                        num_short_addresses += 1

                prediction = predict_nwk_cmd_id(
                    nwk_cmd_payloadlength,
                    der_tx_type,
                    der_nwk_dsttype,
                    der_nwk_srctype,
                    pkt_time,
                    last_beacon_time,
                    last_data_time,
                    last_realign_time,
                    max_beacon_time,
                    num_panids,
                    num_short_addresses,
                )

                if nwk_cmd_id not in NWK_COMMAND_IDENTIFIERS:
                    raise ValueError(
                        "Unexpected name for a NWK command identifier: "
                        + "{}".format(nwk_cmd_id),
                    )
                elif nwk_cmd_id not in confusion_matrix.keys():
                    confusion_matrix[nwk_cmd_id] = {}

                if prediction not in NWK_COMMAND_IDENTIFIERS:
                    raise ValueError(
                        "Unexpected prediction for a NWK command identifier: "
                        + "{}".format(prediction),
                    )
                elif prediction not in confusion_matrix[nwk_cmd_id].keys():
                    confusion_matrix[nwk_cmd_id][prediction] = 1
                else:
                    confusion_matrix[nwk_cmd_id][prediction] += 1

        # Derive the path of each output file
        out_confusionmatrix_filepath = os.path.join(
            out_dirpath,
            "pcap{}--{}--confusionmatrix.tsv".format(
                str(pcap_id).zfill(3),
                os.path.splitext(pcap_filename)[0],
            ),
        )

        # Generate the confusion matrix
        results_confusionmatrix = [[""] + NWK_COMMAND_IDENTIFIERS]
        for actual in NWK_COMMAND_IDENTIFIERS:
            tmp_row = [actual]
            for predicted in NWK_COMMAND_IDENTIFIERS:
                if (
                    actual not in confusion_matrix.keys()
                    or predicted not in confusion_matrix[actual].keys()
                ):
                    tmp_row.append(0)
                else:
                    tmp_row.append(confusion_matrix[actual][predicted])
            results_confusionmatrix.append(tmp_row)

        # Write the confusion matrix in the corresponding output file
        fp = open(out_confusionmatrix_filepath, mode="w", encoding="utf-8")
        for line in results_confusionmatrix:
            for i in range(len(line)):
                if i == 0:
                    fp.write("{}".format(line[i]))
                else:
                    fp.write("\t{}".format(line[i]))
            fp.write("\n")
        fp.close()

    # Disconnect from the provided database
    config.db.disconnect()


def predict_nwk_cmd_id(
    nwk_cmd_payloadlength,
    der_tx_type,
    der_nwk_dsttype,
    der_nwk_srctype,
    pkt_time,
    last_beacon_time,
    last_data_time,
    last_realign_time,
    max_beacon_time,
    num_panids,
    num_short_addresses,
):
    if nwk_cmd_payloadlength == 12:
        return "0x0a: NWK Network Update"
    elif nwk_cmd_payloadlength == 2:
        if der_nwk_dsttype == "NWK Dst Type: Zigbee End Device":
            return "0x0c: NWK End Device Timeout Response"
        else:
            return "0x0b: NWK End Device Timeout Request"
    elif nwk_cmd_payloadlength == 3:
        if der_tx_type == "Single-Hop Transmission":
            return "0x07: NWK Rejoin Response"
        else:
            if (
                der_nwk_dsttype in {
                    "NWK Dst Type: Zigbee End Device",
                    "NWK Dst Type: All active receivers",
                }
            ):
                return "0x03: NWK Network Status"
            else:
                if num_short_addresses >= 3:
                    return "0x05: NWK Route Record"
                else:
                    return "0x03: NWK Network Status"
    else:
        if der_nwk_dsttype == "NWK Dst Type: All routers and coordinator":
            if der_tx_type == "Single-Hop Transmission":
                return "0x08: NWK Link Status"
            else:
                return "0x01: NWK Route Request"
        else:
            if nwk_cmd_payloadlength in {5, 9}:
                return "0x05: NWK Route Record"
            elif nwk_cmd_payloadlength == 1:
                if der_tx_type == "Single-Hop Transmission":
                    if der_nwk_srctype == "NWK Src Type: Zigbee Coordinator":
                        return "0x04: NWK Leave"
                    else:
                        if (
                            der_nwk_dsttype in {
                                "NWK Dst Type: Zigbee End Device",
                                "NWK Dst Type: All active receivers",
                            }
                        ):
                            return "0x04: NWK Leave"
                        else:
                            if (
                                last_realign_time is not None
                                and pkt_time - last_realign_time < 3.0
                            ):
                                if (
                                    last_beacon_time is None
                                    or last_beacon_time < last_realign_time
                                ):
                                    return "0x04: NWK Leave"
                                else:
                                    return "0x06: NWK Rejoin Request"
                            elif (
                                last_data_time is not None
                                and pkt_time - last_data_time < 360.0
                            ):
                                if (
                                    last_beacon_time is None
                                    or last_beacon_time < last_data_time
                                ):
                                    return "0x04: NWK Leave"
                                else:
                                    return "0x06: NWK Rejoin Request"
                            elif (
                                last_beacon_time is not None
                                and pkt_time - last_beacon_time < 3.0
                            ):
                                return "0x06: NWK Rejoin Request"
                            else:
                                return "0x04: NWK Leave"
                else:
                    if (
                        der_nwk_dsttype in {
                            "NWK Dst Type: Zigbee End Device",
                            "NWK Dst Type: All active receivers",
                        }
                    ):
                        return "0x03: NWK Network Status"
                    else:
                        if num_short_addresses >= 2:
                            return "0x05: NWK Route Record"
                        else:
                            return "0x03: NWK Network Status"
            elif nwk_cmd_payloadlength == 7:
                if der_nwk_srctype == "NWK Src Type: Zigbee End Device":
                    return "0x05: NWK Route Record"
                else:
                    if num_short_addresses >= 5:
                        return "0x05: NWK Route Record"
                    else:
                        return "0x02: NWK Route Reply"
            elif nwk_cmd_payloadlength in {15, 23}:
                if der_nwk_dsttype == "NWK Dst Type: Zigbee Router":
                    if der_nwk_srctype == "NWK Src Type: Zigbee End Device":
                        return "0x05: NWK Route Record"
                    else:
                        if (
                            (
                                nwk_cmd_payloadlength == 15
                                and num_short_addresses >= 9
                            )
                            or (
                                nwk_cmd_payloadlength == 23
                                and num_short_addresses >= 13
                            )
                        ):
                            return "0x05: NWK Route Record"
                        else:
                            return "0x02: NWK Route Reply"
                else:
                    if der_nwk_srctype == "NWK Src Type: Zigbee End Device":
                        return "0x05: NWK Route Record"
                    elif (
                        der_nwk_srctype == "NWK Src Type: Zigbee Coordinator"
                    ):
                        if (
                            (
                                nwk_cmd_payloadlength == 15
                                and num_short_addresses >= 9
                            )
                            or (
                                nwk_cmd_payloadlength == 23
                                and num_short_addresses >= 13
                            )
                        ):
                            return "0x05: NWK Route Record"
                        else:
                            return "0x02: NWK Route Reply"
                    else:
                        if (
                            max_beacon_time is not None
                            and pkt_time - max_beacon_time < 3.0
                            and num_panids >= (nwk_cmd_payloadlength - 9) // 2
                        ):
                            return "0x09: NWK Network Report"
                        else:
                            if (
                                (
                                    nwk_cmd_payloadlength == 15
                                    and num_short_addresses >= 9
                                )
                                or (
                                    nwk_cmd_payloadlength == 23
                                    and num_short_addresses >= 13
                                )
                            ):
                                return "0x05: NWK Route Record"
                            else:
                                return "0x02: NWK Route Reply"
            else:
                if der_nwk_dsttype == "NWK Dst Type: Zigbee Router":
                    return "0x05: NWK Route Record"
                else:
                    if der_nwk_srctype == "NWK Src Type: Zigbee Router":
                        if (
                            max_beacon_time is not None
                            and pkt_time - max_beacon_time < 3.0
                            and num_panids >= (nwk_cmd_payloadlength - 9) // 2
                        ):
                            return "0x09: NWK Network Report"
                        else:
                            return "0x05: NWK Route Record"
                    else:
                        return "0x05: NWK Route Record"
