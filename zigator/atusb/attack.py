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
import re
import subprocess


def attack():
    try:
        args = [
            "which",
            "iwpan",
        ]
        cp = subprocess.run(args, capture_output=True)
        if cp.returncode != 0:
            logging.error("Failed at locating the iwpan command")
            return
        logging.debug("Successfully located the iwpan command")
    except Exception:
        logging.error("An exception was raised while trying to locate "
                      "the iwpan command")
        return

    try:
        args = [
            "which",
            "ip",
        ]
        cp = subprocess.run(args, capture_output=True)
        if cp.returncode != 0:
            logging.error("Failed at locating the ip command")
            return
        logging.debug("Successfully located the ip command")
    except Exception:
        logging.error("An exception was raised while trying to locate "
                      "the ip command")
        return

    try:
        args = [
            "iwpan",
            "dev",
        ]
        cp = subprocess.run(args, capture_output=True)
        if cp.returncode != 0:
            logging.error("Failed at listing all WPAN interfaces")
            return
        interfaces = re.findall(r"phy\#[0-9]+\n\tInterface [a-zA-Z0-9]+\n",
                                cp.stdout.decode())
        if not interfaces:
            logging.error("Did not detect any WPAN interface")
            return
        menu = {}
        for i, interface in enumerate(interfaces, start=1):
            match = re.search(r"phy\#([0-9]+)\n\tInterface ([a-zA-Z0-9]+)\n",
                              interface)
            if not match:
                logging.error("Failed at extracting the phyname and devname")
                return
            menu[str(i)] = ("phy" + match.group(1), match.group(2))
        logging.debug("Successfully listed all WPAN interfaces")
    except Exception:
        logging.error("An exception was raised while trying to list "
                      "all WPAN interfaces")
        return

    phyname = None
    devname = None
    print("Enter the number of an available phyname and devname:")
    for key in sorted(menu.keys()):
        print("{}) {} and {}".format(key, menu[key][0], menu[key][1]))
    while True:
        option = input("#? ")
        if option in menu.keys():
            phyname = menu[option][0]
            devname = menu[option][1]
            break

    iface = None
    while True:
        iface = input("Enter a name for the new interface: ")
        if len(iface) < 1:
            print("The name of the new interface must consist of "
                  "at least 1 character")
        elif len(iface) > 15:
            print("The name of the new interface must consist of "
                  "at most 15 characters")
        elif not re.search(r"^[a-zA-Z0-9]+$", iface):
            print("The name of the new interface should consist of "
                  "ASCII letters and numerical digits only")
        else:
            break

    try:
        args = [
            "sudo",
            "iwpan",
            "dev",
            devname,
            "del",
        ]
        cp = subprocess.run(args, capture_output=True)
        if cp.returncode != 0:
            logging.error("Failed at deleting the {} interface"
                          "".format(devname))
            return
        logging.info("Successfully deleted the {} interface".format(devname))
    except Exception:
        logging.error("An exception was raised while trying to delete "
                      "the {} interface".format(devname))
        return

    try:
        args = [
            "sudo",
            "iwpan",
            "phy",
            phyname,
            "interface",
            "add",
            iface,
            "type",
            "monitor",
        ]
        cp = subprocess.run(args, capture_output=True)
        if cp.returncode != 0:
            logging.error("Failed at creating the {} interface"
                          "".format(iface))
            return
        logging.info("Successfully created the {} interface".format(iface))
    except Exception:
        logging.error("An exception was raised while trying to create "
                      "the {} interface".format(iface))
        return

    channel_num = None
    menu = {
        "11": "2.405 GHz",
        "12": "2.410 GHz",
        "13": "2.415 GHz",
        "14": "2.420 GHz",
        "15": "2.425 GHz",
        "16": "2.430 GHz",
        "17": "2.435 GHz",
        "18": "2.440 GHz",
        "19": "2.445 GHz",
        "20": "2.450 GHz",
        "21": "2.455 GHz",
        "22": "2.460 GHz",
        "23": "2.465 GHz",
        "24": "2.470 GHz",
        "25": "2.475 GHz",
        "26": "2.480 GHz",
    }
    print("Enter the number of an available channel on page 0 for {}:"
          "".format(phyname))
    for key in sorted(menu.keys()):
        print("{}) {}".format(key, menu[key]))
    while True:
        option = input("#? ")
        if option in menu.keys():
            channel_num = option
            break

    try:
        args = [
            "sudo",
            "iwpan",
            "phy",
            phyname,
            "set",
            "channel",
            "0",
            channel_num,
        ]
        cp = subprocess.run(args, capture_output=True)
        if cp.returncode != 0:
            logging.error("Failed at setting the channel of {} as number {} "
                          "on page 0".format(phyname, channel_num))
            return
        logging.info("Successfully set the channel of {} as number {} "
                     "on page 0".format(phyname, channel_num))
    except Exception:
        logging.error("An exception was raised while trying to set "
                      "the channel of {} as number {} on page 0"
                      "".format(phyname, channel_num))
        return

    print("############################################################")
    print("#                        DISCLAIMER                        #")
    print("#                                                          #")
    print("# Enabling the WPAN interface that was created will launch #")
    print("# the attack of the flashed firmware image on the selected #")
    print("# channel, which may result in interfering with the        #")
    print("# operation of legitimate IEEE 802.15.4-based networks.    #")
    print("# The users of this tool are responsible for making sure   #")
    print("# that they are compliant with their local laws and that   #")
    print("# they have proper permission from the affected network    #")
    print("# owners.                                                  #")
    print("############################################################")
    answer = input("Are you sure that you want to proceed? [y/N] ")
    if answer == "y":
        print("You accepted responsibility for your actions")
    else:
        logging.info("Canceling the launching of the attack...")
        return

    try:
        args = [
            "sudo",
            "ip",
            "link",
            "set",
            iface,
            "up",
        ]
        cp = subprocess.run(args, capture_output=True)
        if cp.returncode != 0:
            logging.error("Failed at enabling the {} interface".format(iface))
            return
        logging.info("Successfully enabled the {} interface".format(iface))
    except Exception:
        logging.error("An exception was raised while trying to enable "
                      "the {} interface".format(iface))
        return

    menu = {
        "1": "Pause the attack",
        "2": "Resume the attack",
        "3": "Stop the attack",
    }
    while True:
        print("Enter the number of an available option:")
        for key in sorted(menu.keys()):
            print("{}) {}".format(key, menu[key]))
        while True:
            option = input("#? ")
            if option == "1":
                try:
                    args = [
                        "sudo",
                        "ip",
                        "link",
                        "set",
                        iface,
                        "down",
                    ]
                    cp = subprocess.run(args, capture_output=True)
                    if cp.returncode != 0:
                        logging.error("Failed at disabling the {} interface"
                                      "".format(iface))
                    else:
                        logging.info("Successfully disabled the {} interface"
                                     "".format(iface))
                except Exception:
                    logging.error("An exception was raised while trying to "
                                  "disable the {} interface".format(iface))
                break
            elif option == "2":
                try:
                    args = [
                        "sudo",
                        "ip",
                        "link",
                        "set",
                        iface,
                        "up",
                    ]
                    cp = subprocess.run(args, capture_output=True)
                    if cp.returncode != 0:
                        logging.error("Failed at enabling the {} interface"
                                      "".format(iface))
                    else:
                        logging.info("Successfully enabled the {} interface"
                                     "".format(iface))
                except Exception:
                    logging.error("An exception was raised while trying to "
                                  "enable the {} interface".format(iface))
                break
            elif option == "3":
                try:
                    args = [
                        "sudo",
                        "ip",
                        "link",
                        "set",
                        iface,
                        "down",
                    ]
                    cp = subprocess.run(args, capture_output=True)
                    if cp.returncode != 0:
                        logging.error("Failed at disabling the {} interface"
                                      "".format(iface))
                    else:
                        logging.info("Successfully disabled the {} interface"
                                     "".format(iface))
                except Exception:
                    logging.error("An exception was raised while trying to "
                                  "disable the {} interface".format(iface))
                return
