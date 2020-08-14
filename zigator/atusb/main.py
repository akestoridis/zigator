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

from .attack import attack
from .make import make


REPO_URL = "https://github.com/akestoridis/atusb-attacks.git"


def main(repo_dirpath):
    """Interact with an ATUSB."""
    if not os.path.isdir(repo_dirpath):
        try:
            args = [
                "which",
                "git",
            ]
            cp = subprocess.run(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if cp.returncode != 0:
                logging.error("Failed at locating the git command")
                return
            logging.debug("Successfully located the git command")
        except Exception:
            logging.error("An exception was raised while trying to locate "
                          "the git command")
            return

        try:
            args = [
                "git",
                "clone",
                REPO_URL,
                repo_dirpath,
            ]
            cp = subprocess.run(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if cp.returncode != 0:
                logging.error("Failed at cloning the {} repository "
                              "into the \"{}\" directory"
                              "".format(REPO_URL, repo_dirpath))
                return
            logging.info("Successfully cloned the {} repository into the "
                         "\"{}\" directory".format(REPO_URL, repo_dirpath))
        except Exception:
            logging.error("An exception was raised while trying to clone "
                          "the {} repository into the \"{}\" directory"
                          "".format(REPO_URL, repo_dirpath))
            return
    else:
        logging.debug("Successfully located the \"{}\" directory"
                      "".format(repo_dirpath))

    fw_dirpath = os.path.join(repo_dirpath, "fw")
    if not os.path.isdir(fw_dirpath):
        logging.error("Failed at locating the firmware directory at \"{}\""
                      "".format(fw_dirpath))
        return
    else:
        logging.debug("Successfully located the \"{}\" directory"
                      "".format(fw_dirpath))

    make_filepath = os.path.join(fw_dirpath, "Makefile")
    if not os.path.isfile(make_filepath):
        logging.error("Failed at locating the \"{}\" file"
                      "".format(make_filepath))
        return
    else:
        logging.debug("Successfully located the \"{}\" file"
                      "".format(make_filepath))

    os.chdir(fw_dirpath)
    menu = {
        "1": ("Compile and flash a firmware image to an ATUSB", make),
        "2": ("Launch the attack of the flashed firmware image", attack),
        "3": ("Exit this program", exit),
    }
    while True:
        print("Enter the number of an available option:")
        for key in sorted(menu.keys()):
            print("{}) {}".format(key, menu[key][0]))
        while True:
            option = input("#? ")
            if option in menu.keys():
                menu[option][1]()
                break
