# Copyright (C) 2020-2022 Dimitrios-Georgios Akestoridis
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

from . import (
    analysis,
    atusb,
    cli,
    config,
    injection,
    parsing,
    training,
    visualization,
    wids,
)
from .enums import Subcommand


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
    if args.SUBCOMMAND == Subcommand.INJECT and args.PKT_TYPE is None:
        cli.print_zigator_inject_help()
        return

    # Update the expected networking protocol
    if hasattr(args, "NWK_PROTOCOL"):
        config.nwk_protocol = args.NWK_PROTOCOL

    # Load Zigator's configuration files
    config.load_config_files()

    # Process the user's input
    if args.SUBCOMMAND == Subcommand.PRINT_CONFIG:
        config.print_config()
    elif args.SUBCOMMAND == Subcommand.ADD_CONFIG:
        config.add_config_entry(
            args.ENTRY_TYPE,
            args.ENTRY_VALUE,
            args.ENTRY_NAME,
        )
    elif args.SUBCOMMAND == Subcommand.RM_CONFIG:
        config.rm_config_entry(args.ENTRY_TYPE, args.ENTRY_NAME)
    elif args.SUBCOMMAND == Subcommand.PARSE:
        parsing.main(
            args.PCAP_DIRECTORY,
            args.DATABASE_FILEPATH,
            None if not hasattr(args, "num_workers") else args.num_workers,
        )
    elif args.SUBCOMMAND == Subcommand.ANALYZE:
        analysis.main(
            args.DATABASE_FILEPATH,
            args.OUTPUT_DIRECTORY,
            None if not hasattr(args, "num_workers") else args.num_workers,
        )
    elif args.SUBCOMMAND == Subcommand.VISUALIZE:
        visualization.main(args.DATABASE_FILEPATH, args.OUTPUT_DIRECTORY)
    elif args.SUBCOMMAND == Subcommand.TRAIN:
        training.main(
            "enc-nwk-cmd",
            args.DATABASE_FILEPATH,
            args.OUTPUT_DIRECTORY,
            None if not hasattr(args, "seed") else args.seed,
            args.restricted,
        )
    elif args.SUBCOMMAND == Subcommand.INJECT:
        injection.main(args)
    elif args.SUBCOMMAND == Subcommand.ATUSB:
        atusb.main(args.REPO_DIRECTORY)
    elif args.SUBCOMMAND == Subcommand.WIDS:
        wids.main(
            args.SENSOR_ID,
            args.PANID,
            args.EPID,
            args.DATABASE_FILEPATH,
            args.OUTPUT_DIRECTORY,
            args.ifname,
            args.max_pcap_duration,
            args.max_zip_files,
            args.max_queue_size,
            args.link_key_names,
            args.max_uncommitted_entries,
            args.batch_delay,
            None if not hasattr(args, "table_thres") else args.table_thres,
            None if not hasattr(args, "table_reduct") else args.table_reduct,
            None if not hasattr(args, "ipaddr") else args.ipaddr,
            None if not hasattr(args, "portnum") else args.portnum,
        )
    else:
        raise ValueError("Unknown subcommand \"{}\"".format(args.SUBCOMMAND))
