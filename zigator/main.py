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

import logging
import sys

import zigator


def main():
    """Handle user input and call the required functions."""
    # Parse the provided command-line arguments
    if len(sys.argv) > 1:
        args = zigator.cli.parse_args(sys.argv[1:])
    else:
        zigator.cli.print_help()
        return

    # Configure the logging system
    if args.debug:
        logging.basicConfig(format="[%(asctime)s %(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S",
                            level=logging.DEBUG)
    else:
        logging.basicConfig(format="[%(asctime)s %(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S",
                            level=logging.INFO)
    logging.info("Started Zigator version {}".format(zigator.__version__))

    # Initialize the configuration of Zigator
    zigator.config.init()

    # Process the user's input
    if args.subcommand == "print-config":
        zigator.config.print_config()
    elif args.subcommand == "add-config-entry":
        zigator.config.add_config_entry(args.ENTRY_TYPE,
                                        args.ENTRY_VALUE,
                                        args.ENTRY_NAME)
    elif args.subcommand == "rm-config-entry":
        zigator.config.rm_config_entry(args.ENTRY_TYPE,
                                       args.ENTRY_NAME)
    elif args.subcommand == "parse":
        zigator.parsing.main(args.PCAP_DIRECTORY,
                             args.DATABASE_FILEPATH,
                             args.num_workers)
    elif args.subcommand == "analyze":
        zigator.analysis.main(args.DATABASE_FILEPATH,
                              args.OUTPUT_DIRECTORY,
                              args.num_workers)
    elif args.subcommand == "visualize":
        zigator.visualization.main(args.DATABASE_FILEPATH,
                                   args.OUTPUT_DIRECTORY)
    elif args.subcommand == "train":
        zigator.training.main("enc-nwk-cmd",
                              args.DATABASE_FILEPATH,
                              args.OUTPUT_DIRECTORY,
                              args.seed,
                              args.restricted)
    elif args.subcommand == "inject":
        zigator.injection.main(args.PKT_TYPE,
                               args.ipaddr,
                               args.portnum,
                               args.raw,
                               args.mac_seqnum,
                               args.panid,
                               args.dstshortaddr,
                               args.srcshortaddr,
                               args.srcextendedaddr,
                               args.pancoord,
                               args.assocpermit,
                               args.devdepth,
                               args.epid,
                               args.updateid,
                               args.nwk_seqnum,
                               args.devtype,
                               args.powsrc,
                               args.rxidle)
    elif args.subcommand == "atusb":
        zigator.atusb.main(args.REPO_DIRECTORY)
    else:
        raise ValueError("Unknown subcommand \"{}\"".format(args.subcommand))


if __name__ == "__main__":
    main()
