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
        cp = subprocess.run(args, capture_output=True, check=False)
        if cp.returncode != 0:
            logging.error("Failed at locating the dfu-util command")
            return
        logging.debug("Successfully located the dfu-util command")
    except Exception:
        logging.error(
            "An exception was raised while trying to locate "
            + "the dfu-util command",
        )
        return

    try:
        args = [
            "dfu-util",
            "-V",
        ]
        cp = subprocess.run(args, capture_output=True, check=False)
        if cp.returncode != 0:
            logging.error("Failed at identifying the version of dfu-util")
            return
        elif cp.stdout.decode().splitlines()[0] != "dfu-util 0.7":
            logging.error(
                "Version 0.7 of dfu-util is required in order to "
                + "flash firmware images to an ATUSB",
            )
            return
        logging.debug("Successfully identified the version of dfu-util")
    except Exception:
        logging.error(
            "An exception was raised while trying to identify "
            + "the version of dfu-util",
        )
        return

    attackid = None
    menu = {
        "00": "Ignore RX_START interrupts; equivalent to the original ATUSB "
              + "firmware",
        "01": "Jam only Network Update commands",
        "02": "Spoof a MAC acknowledgment for each 12-byte Data Request of a "
              + "specified network",
        "03": "Jam only packets of a specified network that request a MAC "
              + "acknowledgment",
        "04": "Jam only packets of a specified network that request a MAC "
              + "acknowledgment and then spoof a MAC acknowledgment",
        "05": "Jam only Rejoin Responses of a specified network",
        "06": "Jam only Rejoin Responses and Network Update commands",
        "07": "Jam only 28-byte beacons, whose EPID matches with the 32 "
              + "least-significant bits of the specified EPID",
        "08": "Jam only 28-byte beacons, whose EPID matches with the 32 "
              + "least-significant bits of the specified EPID, and Network "
              + "Update commands",
        "09": "Jam only Rejoin Responses and Network Update commands with a "
              + "MAC acknowledgment being spoofed for each jammed Rejoin "
              + "Response",
        "10": "Jam only Network Update commands and spoof a MAC "
              + "acknowledgment for each 12-byte Data Request of a specified "
              + "network",
        "11": "Jam only 12-byte MAC commands of a specified network that "
              + "request a MAC acknowledgment",
        "12": "Jam only 12-byte MAC commands of a specified network that "
              + "request a MAC acknowledgment and then spoof a MAC "
              + "acknowledgment followed by a 127-byte NWK Data packet",
        "13": "Jam only certain 12-byte MAC commands of a specified network "
              + "that request a MAC acknowledgment and then spoof a MAC "
              + "acknowledgment followed by a 127-byte NWK Data packet, "
              + "according to specified active and idle time intervals, with "
              + "the active period restarting whenever a period of "
              + "inactivity is observed and the idle period restarting "
              + "whenever certain packet types are observed",
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
    if attackid in {"02", "03", "04", "05", "10", "11", "12", "13"}:
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

    shortdstaddr = None
    if attackid in {"12", "13"}:
        while True:
            print(
                "Enter the short destination address as four hexadecimal "
                + "digits:",
            )
            shortdstaddr = input("0x")
            if (
                len(shortdstaddr) == 4
                and all(d in string.hexdigits for d in shortdstaddr)
            ):
                break

    shortsrcaddr = None
    if attackid in {"12", "13"}:
        while True:
            print(
                "Enter the short source address as four hexadecimal digits:",
            )
            shortsrcaddr = input("0x")
            if (
                len(shortsrcaddr) == 4
                and all(d in string.hexdigits for d in shortsrcaddr)
            ):
                break

    framecounter = None
    if attackid in {"12", "13"}:
        while True:
            print(
                "Enter the value of the 32-bit frame counter in decimal "
                + "notation:",
            )
            framecounter = input("")
            if (
                all(d in string.digits for d in framecounter)
                and int(framecounter, 10) < 4294967296
            ):
                break

    extendedsrcaddr = None
    if attackid in {"12", "13"}:
        while True:
            print(
                "Enter the extended source address as sixteen hexadecimal "
                + "digits:",
            )
            extendedsrcaddr = input("0x")
            if (
                len(extendedsrcaddr) == 16
                and all(d in string.hexdigits for d in extendedsrcaddr)
            ):
                break

    keyseqnum = None
    if attackid in {"12", "13"}:
        while True:
            print(
                "Enter the value of the 8-bit key sequence number in decimal "
                + "notation:",
            )
            keyseqnum = input("")
            if (
                all(d in string.digits for d in keyseqnum)
                and int(keyseqnum, 10) < 256
            ):
                break

    activesec = None
    if attackid in {"13"}:
        while True:
            print(
                "Enter the number of seconds for each active period in "
                + "decimal notation:",
            )
            activesec = input("")
            if (
                all(d in string.digits for d in activesec)
                and int(activesec, 10) < 4294967296
            ):
                break

    idlesec = None
    if attackid in {"13"}:
        while True:
            print(
                "Enter the number of seconds for each idle period in decimal "
                + "notation:",
            )
            idlesec = input("")
            if (
                all(d in string.digits for d in idlesec)
                and int(idlesec, 10) < 4294967296
            ):
                break

    try:
        args = [
            "make",
            "clean",
        ]
        cp = subprocess.run(args, capture_output=True, check=False)
        if cp.returncode != 0:
            logging.error("Failed at cleaning up the firmware source code")
            return
        logging.info("Successfully cleaned up the firmware source code")
    except Exception:
        logging.error(
            "An exception was raised while trying to clean up "
            + "the firmware source code",
        )
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
        if shortdstaddr is not None:
            args.append("SHORTDSTADDR=0x{}".format(shortdstaddr))
        if shortsrcaddr is not None:
            args.append("SHORTSRCADDR=0x{}".format(shortsrcaddr))
        if framecounter is not None:
            args.append("FRAMECOUNTER={}".format(framecounter))
        if extendedsrcaddr is not None:
            args.append("EXTENDEDSRCADDR=0x{}".format(extendedsrcaddr))
        if keyseqnum is not None:
            args.append("KEYSEQNUM={}".format(keyseqnum))
        if activesec is not None:
            args.append("ACTIVESEC={}".format(activesec))
        if idlesec is not None:
            args.append("IDLESEC={}".format(idlesec))
        cp = subprocess.run(args, check=False)
        if cp.returncode != 0:
            logging.error(
                "Failed at compiling the firmware image and "
                + "flashing it to an ATUSB",
            )
            return
        logging.info(
            "Successfully compiled the firmware image and flashed "
            + "it to an ATUSB",
        )
    except Exception:
        logging.error(
            "An exception was raised while trying to compile "
            + "the firmware image and flash it to an ATUSB",
        )
        return
