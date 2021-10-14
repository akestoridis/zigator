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

import logging
import string
import subprocess
import textwrap


def make():
    try:
        args = [
            "which",
            "dfu-util",
        ]
        cp = subprocess.run(args, capture_output=True)
        if cp.returncode != 0:
            logging.error("Failed at locating the dfu-util command")
            return
        logging.debug("Successfully located the dfu-util command")
    except Exception:
        logging.error("An exception was raised while trying to locate "
                      "the dfu-util command")
        return

    try:
        args = [
            "dfu-util",
            "-V",
        ]
        cp = subprocess.run(args, capture_output=True)
        if cp.returncode != 0:
            logging.error("Failed at identifying the version of dfu-util")
            return
        elif cp.stdout.decode().splitlines()[0] != "dfu-util 0.7":
            logging.error("Version 0.7 of dfu-util is required in order to "
                          "flash firmware images to an ATUSB")
            return
        logging.debug("Successfully identified the version of dfu-util")
    except Exception:
        logging.error("An exception was raised while trying to identify "
                      "the version of dfu-util")
        return

    attackid = None
    menu = {
        "00": "Ignore RX_START interrupts; equivalent to the original ATUSB "
              "firmware",
        "01": "Jam only Network Update commands",
        "02": "Spoof a MAC acknowledgment for each 12-byte Data Request of a "
              "specified network",
        "03": "Jam only packets of a specified network that request a MAC "
              "acknowledgment",
        "04": "Jam only packets of a specified network that request a MAC "
              "acknowledgment and then spoof a MAC acknowledgment",
        "05": "Jam only Rejoin Responses of a specified network",
        "06": "Jam only Rejoin Responses and Network Update commands",
        "07": "Jam only 28-byte beacons, whose EPID matches with the 32 "
              "least-significant bits of the specified EPID",
        "08": "Jam only 28-byte beacons, whose EPID matches with the 32 "
              "least-significant bits of the specified EPID, and Network "
              "Update commands",
        "09": "Jam only Rejoin Responses and Network Update commands with a "
              "MAC acknowledgment being spoofed for each jammed Rejoin "
              "Response",
        "10": "Jam only Network Update commands and spoof a MAC "
              "acknowledgment for each 12-byte Data Request of a specified "
              "network",
        "11": "Jam only 12-byte MAC commands of a specified network that "
              "request a MAC acknowledgment",
    }
    print("Enter the ID of an available attack:")
    for key in sorted(menu.keys()):
        attack_description = textwrap.wrap(menu[key], width=74)
        for i, line in enumerate(attack_description):
            if i == 0:
                print("{}) {}".format(key, line))
            else:
                print("    {}".format(line))
    while True:
        option = input("#? ")
        if option in menu.keys():
            attackid = option
            break

    panid = None
    if attackid in {"02", "03", "04", "05", "10", "11"}:
        while True:
            print("Enter the PAN ID as four hexadecimal digits:")
            panid = input("0x")
            if len(panid) == 4 and all(d in string.hexdigits for d in panid):
                break

    epid = None
    if attackid in {"07", "08"}:
        while True:
            print("Enter the EPID as sixteen hexadecimal digits:")
            epid = input("0x")
            if len(epid) == 16 and all(d in string.hexdigits for d in epid):
                break

    try:
        args = [
            "make",
            "clean",
        ]
        cp = subprocess.run(args, capture_output=True)
        if cp.returncode != 0:
            logging.error("Failed at cleaning up the firmware source code")
            return
        logging.info("Successfully cleaned up the firmware source code")
    except Exception:
        logging.error("An exception was raised while trying to clean up "
                      "the firmware source code")
        return

    try:
        args = [
            "sudo",
            "make",
            "dfu",
            "ATTACKID={}".format(attackid),
        ]
        if panid is not None:
            args.append("PANID=0x{}".format(panid))
        if epid is not None:
            args.append("EPID=0x{}".format(epid))
        cp = subprocess.run(args)
        if cp.returncode != 0:
            logging.error("Failed at compiling the firmware image and "
                          "flashing it to an ATUSB")
            return
        logging.info("Successfully compiled the firmware image and flashed "
                     "it to an ATUSB")
    except Exception:
        logging.error("An exception was raised while trying to compile "
                      "the firmware image and flash it to an ATUSB")
        return
