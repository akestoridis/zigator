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

from . import cli
from . import config

from . import analysis
from . import atusb
from . import injection
from . import parsing
from . import training
from . import visualization


def main(argv):
    """Handle user input and call the required functions."""
    # Sanity check
    if argv is None:
        cli.print_help()
        return

    # Parse the provided list of arguments
    if len(argv) > 1:
        args = cli.parse_args(argv[1:])
    else:
        cli.print_help()
        return

    # Check whether the logging level should be set to DEBUG or not
    if args.debug:
        config.enable_debug_logging()

    # Make sure that a subcommand was selected
    if args.subcommand is None:
        cli.print_help()
        return

    # Load Zigator's configuration files
    config.load_config_files()

    # Process the user's input
    if args.subcommand == "print-config":
        config.print_config()
    elif args.subcommand == "add-config-entry":
        config.add_config_entry(args.ENTRY_TYPE,
                                args.ENTRY_VALUE,
                                args.ENTRY_NAME)
    elif args.subcommand == "rm-config-entry":
        config.rm_config_entry(args.ENTRY_TYPE,
                               args.ENTRY_NAME)
    elif args.subcommand == "parse":
        parsing.main(args.PCAP_DIRECTORY,
                     args.DATABASE_FILEPATH,
                     args.num_workers)
    elif args.subcommand == "analyze":
        analysis.main(args.DATABASE_FILEPATH,
                      args.OUTPUT_DIRECTORY,
                      args.num_workers)
    elif args.subcommand == "visualize":
        visualization.main(args.DATABASE_FILEPATH,
                           args.OUTPUT_DIRECTORY)
    elif args.subcommand == "train":
        training.main("enc-nwk-cmd",
                      args.DATABASE_FILEPATH,
                      args.OUTPUT_DIRECTORY,
                      args.seed,
                      args.restricted)
    elif args.subcommand == "inject":
        injection.main(args.PKT_TYPE,
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
        atusb.main(args.REPO_DIRECTORY)
    else:
        raise ValueError("Unknown subcommand \"{}\"".format(args.subcommand))
