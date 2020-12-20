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
from . import monitoring
from . import parsing
from . import training
from . import visualization


def main(argv):
    """Handle user input and call the required functions."""
    # Sanity check
    if argv is None:
        cli.print_zigator_help()
        return

    # Parse the provided list of arguments
    if len(argv) > 1:
        args = cli.parse_args(argv[1:])
    else:
        cli.print_zigator_help()
        return

    # Check whether the logging level should be set to DEBUG or not
    if args.debug:
        config.enable_debug_logging()

    # Make sure that a subcommand was selected
    if args.SUBCOMMAND is None:
        cli.print_zigator_help()
        return

    # Make sure that a packet type was selected when needed
    if args.SUBCOMMAND == "inject" and args.PKT_TYPE is None:
        cli.print_zigator_inject_help()
        return

    # Load Zigator's configuration files
    config.load_config_files()

    # Process the user's input
    if args.SUBCOMMAND == "print-config":
        config.print_config()
    elif args.SUBCOMMAND == "add-config-entry":
        config.add_config_entry(
            args.ENTRY_TYPE,
            args.ENTRY_VALUE,
            args.ENTRY_NAME)
    elif args.SUBCOMMAND == "rm-config-entry":
        config.rm_config_entry(
            args.ENTRY_TYPE,
            args.ENTRY_NAME)
    elif args.SUBCOMMAND == "parse":
        parsing.main(
            args.PCAP_DIRECTORY,
            args.DATABASE_FILEPATH,
            None if not hasattr(args, "num_workers") else args.num_workers)
    elif args.SUBCOMMAND == "analyze":
        analysis.main(
            args.DATABASE_FILEPATH,
            args.OUTPUT_DIRECTORY,
            None if not hasattr(args, "num_workers") else args.num_workers)
    elif args.SUBCOMMAND == "visualize":
        visualization.main(
            args.DATABASE_FILEPATH,
            args.OUTPUT_DIRECTORY)
    elif args.SUBCOMMAND == "train":
        training.main(
            "enc-nwk-cmd",
            args.DATABASE_FILEPATH,
            args.OUTPUT_DIRECTORY,
            None if not hasattr(args, "seed") else args.seed,
            args.restricted)
    elif args.SUBCOMMAND == "inject":
        injection.main(
            args)
    elif args.SUBCOMMAND == "atusb":
        atusb.main(
            args.REPO_DIRECTORY)
    elif args.SUBCOMMAND == "monitor":
        monitoring.main(
            args.PCAP_FILEPATH)
    else:
        raise ValueError("Unknown subcommand \"{}\"".format(args.SUBCOMMAND))
