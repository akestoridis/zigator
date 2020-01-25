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

import os
import zigator


def parse_pcap_files():
    while True:
        dirpath = input("Enter the directory with the pcap files: ")
        if os.path.isdir(dirpath):
            zigator.parsing.pcap_directory(dirpath)
            return
        else:
            print("The provided directory \"{}\" does not exist"
                  "".format(dirpath))


def main():
    """Generate the main menu and handle user input."""
    menu = {
        "1": ("Parse pcap files", parse_pcap_files),
        "2": ("Exit this program", exit)
    }
    while True:
        print("\nEnter the number of an available option:")
        for key in sorted(menu.keys()):
            print("{}) {}".format(key, menu[key][0]))
        while True:
            option = input("#? ")
            if option in menu.keys():
                menu[option][1]()
                break


if __name__ == "__main__":
    main()
