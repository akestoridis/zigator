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

"""
Database module for the ``zigator`` package.
"""

import sqlite3
import string


# Define the columns of the packets table in the database
PKT_COLUMNS = [
    ("pcap_directory", "TEXT"),
    ("pcap_filename", "TEXT"),
    ("pkt_num", "INTEGER"),
    ("pkt_time", "REAL"),
    ("sll_pkttype", "TEXT"),
    ("sll_arphrdtype", "INTEGER"),
    ("sll_addrlength", "INTEGER"),
    ("sll_addr", "TEXT"),
    ("sll_protocoltype", "INTEGER"),
    ("phy_length", "INTEGER"),
    ("phy_payload", "TEXT"),
    ("mac_show", "TEXT"),
    ("mac_fcs", "TEXT"),
    ("mac_frametype", "TEXT"),
    ("mac_security", "TEXT"),
    ("mac_framepending", "TEXT"),
    ("mac_ackreq", "TEXT"),
    ("mac_panidcomp", "TEXT"),
    ("mac_dstaddrmode", "TEXT"),
    ("mac_frameversion", "TEXT"),
    ("mac_srcaddrmode", "TEXT"),
    ("mac_seqnum", "INTEGER"),
    ("mac_dstpanid", "TEXT"),
    ("mac_dstshortaddr", "TEXT"),
    ("mac_dstextendedaddr", "TEXT"),
    ("mac_srcpanid", "TEXT"),
    ("mac_srcshortaddr", "TEXT"),
    ("mac_srcextendedaddr", "TEXT"),
    ("mac_cmd_id", "TEXT"),
    ("mac_cmd_payloadlength", "INTEGER"),
    ("mac_assocreq_apc", "TEXT"),
    ("mac_assocreq_devtype", "TEXT"),
    ("mac_assocreq_powsrc", "TEXT"),
    ("mac_assocreq_rxidle", "TEXT"),
    ("mac_assocreq_seccap", "TEXT"),
    ("mac_assocreq_allocaddr", "TEXT"),
    ("mac_assocrsp_shortaddr", "TEXT"),
    ("mac_assocrsp_status", "TEXT"),
    ("mac_disassoc_reason", "TEXT"),
    ("mac_realign_panid", "TEXT"),
    ("mac_realign_coordaddr", "TEXT"),
    ("mac_realign_channel", "INTEGER"),
    ("mac_realign_shortaddr", "TEXT"),
    ("mac_realign_page", "INTEGER"),
    ("mac_gtsreq_length", "INTEGER"),
    ("mac_gtsreq_dir", "TEXT"),
    ("mac_gtsreq_chartype", "TEXT"),
    ("mac_beacon_beaconorder", "INTEGER"),
    ("mac_beacon_sforder", "INTEGER"),
    ("mac_beacon_finalcap", "INTEGER"),
    ("mac_beacon_ble", "INTEGER"),
    ("mac_beacon_pancoord", "TEXT"),
    ("mac_beacon_assocpermit", "TEXT"),
    ("mac_beacon_gtsnum", "INTEGER"),
    ("mac_beacon_gtspermit", "INTEGER"),
    ("mac_beacon_gtsmask", "INTEGER"),
    ("mac_beacon_nsap", "INTEGER"),
    ("mac_beacon_neap", "INTEGER"),
    ("mac_beacon_shortaddresses", "TEXT"),
    ("mac_beacon_extendedaddresses", "TEXT"),
    ("nwk_beacon_protocolid", "INTEGER"),
    ("nwk_beacon_stackprofile", "INTEGER"),
    ("nwk_beacon_protocolversion", "TEXT"),
    ("nwk_beacon_routercap", "TEXT"),
    ("nwk_beacon_devdepth", "INTEGER"),
    ("nwk_beacon_edcap", "TEXT"),
    ("nwk_beacon_epid", "TEXT"),
    ("nwk_beacon_txoffset", "INTEGER"),
    ("nwk_beacon_updateid", "INTEGER"),
    ("nwk_frametype", "TEXT"),
    ("nwk_protocolversion", "TEXT"),
    ("nwk_discroute", "TEXT"),
    ("nwk_multicast", "TEXT"),
    ("nwk_security", "TEXT"),
    ("nwk_srcroute", "TEXT"),
    ("nwk_extendeddst", "TEXT"),
    ("nwk_extendedsrc", "TEXT"),
    ("nwk_edinitiator", "TEXT"),
    ("nwk_dstshortaddr", "TEXT"),
    ("nwk_srcshortaddr", "TEXT"),
    ("nwk_radius", "INTEGER"),
    ("nwk_seqnum", "INTEGER"),
    ("nwk_dstextendedaddr", "TEXT"),
    ("nwk_srcextendedaddr", "TEXT"),
    ("nwk_srcroute_relaycount", "INTEGER"),
    ("nwk_srcroute_relayindex", "INTEGER"),
    ("nwk_srcroute_relaylist", "TEXT"),
    ("nwk_aux_seclevel", "TEXT"),
    ("nwk_aux_keytype", "TEXT"),
    ("nwk_aux_extnonce", "TEXT"),
    ("nwk_aux_framecounter", "INTEGER"),
    ("nwk_aux_srcaddr", "TEXT"),
    ("nwk_aux_keyseqnum", "INTEGER"),
    ("nwk_aux_deckey", "TEXT"),
    ("nwk_aux_decsrc", "TEXT"),
    ("nwk_aux_decpayload", "TEXT"),
    ("nwk_aux_decshow", "TEXT"),
    ("nwk_cmd_id", "TEXT"),
    ("nwk_cmd_payloadlength", "INTEGER"),
    ("nwk_routerequest_mto", "TEXT"),
    ("nwk_routerequest_ed", "TEXT"),
    ("nwk_routerequest_mc", "TEXT"),
    ("nwk_routerequest_id", "INTEGER"),
    ("nwk_routerequest_dstshortaddr", "TEXT"),
    ("nwk_routerequest_pathcost", "INTEGER"),
    ("nwk_routerequest_dstextendedaddr", "TEXT"),
    ("nwk_routereply_eo", "TEXT"),
    ("nwk_routereply_er", "TEXT"),
    ("nwk_routereply_mc", "TEXT"),
    ("nwk_routereply_id", "INTEGER"),
    ("nwk_routereply_origshortaddr", "TEXT"),
    ("nwk_routereply_respshortaddr", "TEXT"),
    ("nwk_routereply_pathcost", "INTEGER"),
    ("nwk_routereply_origextendedaddr", "TEXT"),
    ("nwk_routereply_respextendedaddr", "TEXT"),
    ("nwk_networkstatus_code", "TEXT"),
    ("nwk_networkstatus_dstshortaddr", "TEXT"),
    ("nwk_leave_rejoin", "TEXT"),
    ("nwk_leave_request", "TEXT"),
    ("nwk_leave_rmch", "TEXT"),
    ("nwk_routerecord_relaycount", "INTEGER"),
    ("nwk_routerecord_relaylist", "TEXT"),
    ("nwk_rejoinreq_apc", "TEXT"),
    ("nwk_rejoinreq_devtype", "TEXT"),
    ("nwk_rejoinreq_powsrc", "TEXT"),
    ("nwk_rejoinreq_rxidle", "TEXT"),
    ("nwk_rejoinreq_seccap", "TEXT"),
    ("nwk_rejoinreq_allocaddr", "TEXT"),
    ("nwk_rejoinrsp_shortaddr", "TEXT"),
    ("nwk_rejoinrsp_status", "TEXT"),
    ("nwk_linkstatus_count", "INTEGER"),
    ("nwk_linkstatus_first", "TEXT"),
    ("nwk_linkstatus_last", "TEXT"),
    ("nwk_linkstatus_addresses", "TEXT"),
    ("nwk_linkstatus_incomingcosts", "TEXT"),
    ("nwk_linkstatus_outgoingcosts", "TEXT"),
    ("nwk_networkreport_count", "INTEGER"),
    ("nwk_networkreport_type", "TEXT"),
    ("nwk_networkreport_epid", "TEXT"),
    ("nwk_networkreport_info", "TEXT"),
    ("nwk_networkupdate_count", "INTEGER"),
    ("nwk_networkupdate_type", "TEXT"),
    ("nwk_networkupdate_epid", "TEXT"),
    ("nwk_networkupdate_updateid", "INTEGER"),
    ("nwk_networkupdate_newpanid", "TEXT"),
    ("nwk_edtimeoutreq_reqtime", "TEXT"),
    ("nwk_edtimeoutreq_edconf", "INTEGER"),
    ("nwk_edtimeoutrsp_status", "TEXT"),
    ("nwk_edtimeoutrsp_poll", "TEXT"),
    ("nwk_edtimeoutrsp_timeout", "TEXT"),
    ("aps_frametype", "TEXT"),
    ("aps_delmode", "TEXT"),
    ("aps_ackformat", "TEXT"),
    ("aps_security", "TEXT"),
    ("aps_ackreq", "TEXT"),
    ("aps_exthdr", "TEXT"),
    ("aps_dstendpoint", "INTEGER"),
    ("aps_groupaddr", "TEXT"),
    ("aps_cluster_id", "TEXT"),
    ("aps_profile_id", "TEXT"),
    ("aps_srcendpoint", "INTEGER"),
    ("aps_counter", "INTEGER"),
    ("aps_fragmentation", "TEXT"),
    ("aps_blocknumber", "INTEGER"),
    ("aps_ackbitfield", "INTEGER"),
    ("aps_tunnel_dstextendedaddr", "TEXT"),
    ("aps_tunnel_frametype", "TEXT"),
    ("aps_tunnel_delmode", "TEXT"),
    ("aps_tunnel_ackformat", "TEXT"),
    ("aps_tunnel_security", "TEXT"),
    ("aps_tunnel_ackreq", "TEXT"),
    ("aps_tunnel_exthdr", "TEXT"),
    ("aps_tunnel_counter", "INTEGER"),
    ("aps_aux_seclevel", "TEXT"),
    ("aps_aux_keytype", "TEXT"),
    ("aps_aux_extnonce", "TEXT"),
    ("aps_aux_framecounter", "INTEGER"),
    ("aps_aux_srcaddr", "TEXT"),
    ("aps_aux_keyseqnum", "INTEGER"),
    ("aps_aux_deckey", "TEXT"),
    ("aps_aux_decsrc", "TEXT"),
    ("aps_aux_decpayload", "TEXT"),
    ("aps_aux_decshow", "TEXT"),
    ("aps_cmd_id", "TEXT"),
    ("aps_tunnel_cmd_id", "TEXT"),
    ("aps_transportkey_stdkeytype", "TEXT"),
    ("aps_transportkey_key", "TEXT"),
    ("aps_transportkey_keyseqnum", "INTEGER"),
    ("aps_transportkey_dstextendedaddr", "TEXT"),
    ("aps_transportkey_srcextendedaddr", "TEXT"),
    ("aps_transportkey_prtextendedaddr", "TEXT"),
    ("aps_transportkey_initflag", "TEXT"),
    ("aps_updatedevice_extendedaddr", "TEXT"),
    ("aps_updatedevice_shortaddr", "TEXT"),
    ("aps_updatedevice_status", "TEXT"),
    ("aps_removedevice_extendedaddr", "TEXT"),
    ("aps_requestkey_reqkeytype", "TEXT"),
    ("aps_requestkey_prtextendedaddr", "TEXT"),
    ("aps_switchkey_keyseqnum", "INTEGER"),
    ("aps_verifykey_stdkeytype", "TEXT"),
    ("aps_verifykey_extendedaddr", "TEXT"),
    ("aps_verifykey_keyhash", "TEXT"),
    ("aps_confirmkey_status", "TEXT"),
    ("aps_confirmkey_stdkeytype", "TEXT"),
    ("aps_confirmkey_extendedaddr", "TEXT"),
    ("zdp_seqnum", "INTEGER"),
    ("zdp_activeepreq_nwkaddr", "TEXT"),
    ("zdp_deviceannce_nwkaddr", "TEXT"),
    ("zdp_deviceannce_ieeeaddr", "TEXT"),
    ("zdp_deviceannce_apc", "TEXT"),
    ("zdp_deviceannce_devtype", "TEXT"),
    ("zdp_deviceannce_powsrc", "TEXT"),
    ("zdp_deviceannce_rxidle", "TEXT"),
    ("zdp_deviceannce_seccap", "TEXT"),
    ("zdp_deviceannce_allocaddr", "TEXT"),
    ("zcl_frametype", "TEXT"),
    ("zcl_manufspecific", "TEXT"),
    ("zcl_direction", "TEXT"),
    ("zcl_disdefrsp", "TEXT"),
    ("zcl_manufcode", "TEXT"),
    ("zcl_seqnum", "INTEGER"),
    ("zcl_cmd_id", "TEXT"),
    ("zcl_readattributes_identifiers", "TEXT"),
    ("zcl_readattributesresponse_identifiers", "TEXT"),
    ("zcl_readattributesresponse_statuses", "TEXT"),
    ("zcl_readattributesresponse_datatypes", "TEXT"),
    ("zcl_readattributesresponse_values", "TEXT"),
    ("zcl_writeattributes_identifiers", "TEXT"),
    ("zcl_writeattributes_datatypes", "TEXT"),
    ("zcl_writeattributes_data", "TEXT"),
    ("zcl_writeattributesresponse_statuses", "TEXT"),
    ("zcl_writeattributesresponse_identifiers", "TEXT"),
    ("zcl_configurereporting_directions", "TEXT"),
    ("zcl_configurereporting_identifiers", "TEXT"),
    ("zcl_configurereporting_datatypes", "TEXT"),
    ("zcl_configurereporting_minintervals", "TEXT"),
    ("zcl_configurereporting_maxintervals", "TEXT"),
    ("zcl_configurereporting_changes", "TEXT"),
    ("zcl_configurereporting_timeoutperiods", "TEXT"),
    ("zcl_configurereportingresponse_statuses", "TEXT"),
    ("zcl_configurereportingresponse_directions", "TEXT"),
    ("zcl_configurereportingresponse_identifiers", "TEXT"),
    ("zcl_reportattributes_identifiers", "TEXT"),
    ("zcl_reportattributes_datatypes", "TEXT"),
    ("zcl_reportattributes_data", "TEXT"),
    ("zcl_defaultresponse_rspcmdid", "TEXT"),
    ("zcl_defaultresponse_status", "TEXT"),
    ("zcl_iaszone_zoneenrollrsp_code", "TEXT"),
    ("zcl_iaszone_zoneenrollrsp_zoneid", "TEXT"),
    ("zcl_iaszone_zonestatuschangenotif_zonestatus", "TEXT"),
    ("zcl_iaszone_zonestatuschangenotif_extendedstatus", "TEXT"),
    ("zcl_iaszone_zonestatuschangenotif_zoneid", "TEXT"),
    ("zcl_iaszone_zonestatuschangenotif_delay", "TEXT"),
    ("zcl_iaszone_zoneenrollreq_zonetype", "TEXT"),
    ("zcl_iaszone_zoneenrollreq_manufcode", "TEXT"),
    ("der_same_macnwkdst", "TEXT"),
    ("der_same_macnwksrc", "TEXT"),
    ("der_tx_type", "TEXT"),
    ("der_mac_dsttype", "TEXT"),
    ("der_mac_srctype", "TEXT"),
    ("der_nwk_dsttype", "TEXT"),
    ("der_nwk_srctype", "TEXT"),
    ("der_mac_dstpanid", "TEXT"),
    ("der_mac_dstshortaddr", "TEXT"),
    ("der_mac_dstextendedaddr", "TEXT"),
    ("der_mac_srcpanid", "TEXT"),
    ("der_mac_srcshortaddr", "TEXT"),
    ("der_mac_srcextendedaddr", "TEXT"),
    ("der_nwk_dstpanid", "TEXT"),
    ("der_nwk_dstshortaddr", "TEXT"),
    ("der_nwk_dstextendedaddr", "TEXT"),
    ("der_nwk_srcpanid", "TEXT"),
    ("der_nwk_srcshortaddr", "TEXT"),
    ("der_nwk_srcextendedaddr", "TEXT"),
    ("warning_msg", "TEXT"),
    ("error_msg", "TEXT"),
]

# Define the columns of the basic_information table in the database
BASIC_INFO_COLUMNS = [
    ("pkt_time", "REAL"),
    ("phy_length", "INTEGER"),
    ("mac_frametype", "TEXT"),
    ("mac_seqnum", "INTEGER"),
    ("nwk_seqnum", "INTEGER"),
    ("nwk_aux_framecounter", "INTEGER"),
    ("der_same_macnwksrc", "TEXT"),
    ("der_mac_srcpanid", "TEXT"),
    ("der_mac_srcshortaddr", "TEXT"),
    ("der_mac_srcextendedaddr", "TEXT"),
    ("error_msg", "TEXT"),
]

# Define the columns of the battery_percentages table in the database
BTRY_PERC_COLUMNS = [
    ("pkt_time", "REAL"),
    ("srcpanid", "TEXT"),
    ("srcshortaddr", "TEXT"),
    ("percentage", "REAL"),
]

# Define the columns of the events table in the database
EVENTS_COLUMNS = [
    ("pkt_time", "REAL"),
    ("description", "TEXT"),
]

# Define a list that contains only the column names for each table
PKT_COLUMN_NAMES = [column[0] for column in PKT_COLUMNS]
BASIC_INFO_COLUMN_NAMES = [column[0] for column in BASIC_INFO_COLUMNS]
BTRY_PERC_COLUMN_NAMES = [column[0] for column in BTRY_PERC_COLUMNS]
EVENTS_COLUMN_NAMES = [column[0] for column in EVENTS_COLUMNS]

# Define sets that will be used to construct valid column definitions
ALLOWED_CHARACTERS = set(string.ascii_letters + string.digits + "_")
ALLOWED_TYPES = {
    "TEXT",
    "INTEGER",
    "REAL",
    "BLOB",
}
CONSTRAINED_PKT_COLUMNS = {
    "pcap_directory",
    "pcap_filename",
    "pkt_num",
    "pkt_time",
}
CONSTRAINED_BASIC_INFO_COLUMNS = {
    "pkt_time",
}
CONSTRAINED_BTRY_PERC_COLUMNS = {
    "pkt_time",
    "srcpanid",
    "srcshortaddr",
    "percentage",
}
CONSTRAINED_EVENTS_COLUMNS = {
    "pkt_time",
    "description",
}

# Initialize global variables for interacting with the database
connection = None
cursor = None


def connect(db_filepath):
    global connection
    global cursor

    # Open a connection with the database
    connection = sqlite3.connect(db_filepath)
    connection.text_factory = str
    cursor = connection.cursor()


def create_table(tablename):
    # Use the variables of the corresponding table
    if tablename == "packets":
        table_columns = PKT_COLUMNS
        constrained_table_columns = CONSTRAINED_PKT_COLUMNS
    elif tablename == "basic_information":
        table_columns = BASIC_INFO_COLUMNS
        constrained_table_columns = CONSTRAINED_BASIC_INFO_COLUMNS
    elif tablename == "battery_percentages":
        table_columns = BTRY_PERC_COLUMNS
        constrained_table_columns = CONSTRAINED_BTRY_PERC_COLUMNS
    elif tablename == "events":
        table_columns = EVENTS_COLUMNS
        constrained_table_columns = CONSTRAINED_EVENTS_COLUMNS
    else:
        raise ValueError("Unknown table name \"{}\"".format(tablename))

    # Drop the table if it already exists
    table_drop_command = "DROP TABLE IF EXISTS {}".format(tablename)
    cursor.execute(table_drop_command)

    # Create the table
    table_creation_command = "CREATE TABLE {}(".format(tablename)
    delimiter_needed = False
    for column in table_columns:
        if delimiter_needed:
            table_creation_command += ", "
        else:
            delimiter_needed = True

        column_name = column[0]
        column_type = column[1]

        for i in range(len(column_name)):
            if column_name[i] not in ALLOWED_CHARACTERS:
                raise ValueError(
                    "The character \"{}\" ".format(column_name[i])
                    + "in the name of the column \"{}\" ".format(column_name)
                    + "is not allowed",
                )

        if column_name[0].isdigit():
            raise ValueError(
                "The name of the column \"{}\" ".format(column_name)
                + "is not allowed because it starts with a digit",
            )

        table_creation_command += column_name

        if column_type not in ALLOWED_TYPES:
            raise ValueError(
                "The column type \"{}\" is not in the ".format(column_type)
                + "set of allowed column types {}".format(ALLOWED_TYPES),
            )

        table_creation_command += " " + column_type

        if column_name in constrained_table_columns:
            table_creation_command += " NOT NULL"
    table_creation_command += ")"

    # Execute the constructed command
    cursor.execute(table_creation_command)


def create_count_trigger(tablename, table_thres, table_reduct):
    # Make sure that the table name is valid
    valid_tablenames = {
        "basic_information",
        "battery_percentages",
        "events",
    }
    if tablename not in valid_tablenames:
        raise ValueError("Invalid table name \"{}\"".format(tablename))

    # Derive the trigger name
    triggername = tablename + "_count"

    # Drop the trigger if it already exists
    cursor.execute("DROP TRIGGER IF EXISTS {}".format(triggername))

    # Create the trigger only if the table threshold and the table reduction
    # are positive integers
    if (
        type(table_thres) is int
        and type(table_reduct) is int
        and table_thres > 0
        and table_reduct > 0
    ):
        cursor.execute(
            "CREATE TRIGGER {} ".format(triggername)
            + "AFTER INSERT ON {} WHEN ".format(tablename)
            + "(SELECT COUNT(*) FROM {})={} ".format(tablename, table_thres)
            + "BEGIN DELETE FROM {} ".format(tablename)
            + "WHERE pkt_time IN "
            + "(SELECT pkt_time FROM {} ".format(tablename)
            + "ORDER BY pkt_time LIMIT {}); END".format(table_reduct)
        )


def insert(tablename, row_data):
    # Use the variables of the corresponding table
    if tablename == "packets":
        table_columns = PKT_COLUMNS
        table_column_names = PKT_COLUMN_NAMES
    elif tablename == "basic_information":
        table_columns = BASIC_INFO_COLUMNS
        table_column_names = BASIC_INFO_COLUMN_NAMES
    elif tablename == "battery_percentages":
        table_columns = BTRY_PERC_COLUMNS
        table_column_names = BTRY_PERC_COLUMN_NAMES
    elif tablename == "events":
        table_columns = EVENTS_COLUMNS
        table_column_names = EVENTS_COLUMN_NAMES
    else:
        raise ValueError("Unknown table name \"{}\"".format(tablename))

    # Sanity check
    if len(row_data.keys()) != len(table_column_names):
        raise ValueError(
            "Unexpected number of data entries: {}".format(
                len(row_data.keys()),
            ),
        )

    # Insert the provided data entries into the corresponding table
    cursor.execute(
        "INSERT INTO {} VALUES ({})".format(
            tablename,
            ", ".join("?"*len(table_columns)),
        ),
        tuple([row_data[column_name] for column_name in table_column_names]),
    )


def commit():
    connection.commit()


def grouped_count(tablename, selected_columns, count_errors):
    # Use the variables of the corresponding table
    if tablename == "packets":
        table_column_names = PKT_COLUMN_NAMES
    elif tablename == "basic_information":
        table_column_names = BASIC_INFO_COLUMN_NAMES
    elif tablename == "battery_percentages":
        table_column_names = BTRY_PERC_COLUMN_NAMES
    elif tablename == "events":
        table_column_names = EVENTS_COLUMN_NAMES
    else:
        raise ValueError("Unknown table name \"{}\"".format(tablename))

    # Sanity checks
    if len(selected_columns) == 0:
        raise ValueError("At least one selected column is required")
    for column_name in selected_columns:
        if column_name not in table_column_names:
            raise ValueError("Unknown column name \"{}\"".format(column_name))

    # Construct the selection command
    column_csv = ", ".join(selected_columns)
    select_command = "SELECT {}, COUNT(*)".format(column_csv)
    select_command += " FROM {}".format(tablename)
    if not count_errors:
        select_command += " WHERE error_msg IS NULL"
    select_command += " GROUP BY {}".format(column_csv)

    # Return the results of the constructed command
    cursor.execute(select_command)
    return cursor.fetchall()


def fetch_values(tablename, selected_columns, conditions, distinct):
    # Use the variables of the corresponding table
    if tablename == "packets":
        table_column_names = PKT_COLUMN_NAMES
    elif tablename == "basic_information":
        table_column_names = BASIC_INFO_COLUMN_NAMES
    elif tablename == "battery_percentages":
        table_column_names = BTRY_PERC_COLUMN_NAMES
    elif tablename == "events":
        table_column_names = EVENTS_COLUMN_NAMES
    else:
        raise ValueError("Unknown table name \"{}\"".format(tablename))

    # Sanity checks
    if len(selected_columns) == 0:
        raise ValueError("At least one selected column is required")
    for column_name in selected_columns:
        if column_name not in table_column_names:
            raise ValueError("Unknown column name \"{}\"".format(column_name))

    # Construct the selection command
    column_csv = ", ".join(selected_columns)
    select_command = "SELECT"
    if distinct:
        select_command += " DISTINCT"
    select_command += " {} FROM {}".format(column_csv, tablename)
    expr_statements = []
    expr_values = []
    if conditions is not None:
        select_command += " WHERE "
        for condition in conditions:
            param = condition[0]
            value = condition[1]
            if param[0] == "!":
                neq = True
                param = param[1:]
            else:
                neq = False
            if param not in table_column_names:
                raise ValueError("Unknown column name \"{}\"".format(param))
            elif value is None:
                if neq:
                    expr_statements.append("{} IS NOT NULL".format(param))
                else:
                    expr_statements.append("{} IS NULL".format(param))
            else:
                if neq:
                    expr_statements.append("{}!=?".format(param))
                else:
                    expr_statements.append("{}=?".format(param))
                expr_values.append(value)
        select_command += " AND ".join(expr_statements)

    # Return the results of the constructed command
    cursor.execute(select_command, tuple(expr_values))
    return cursor.fetchall()


def matching_frequency(tablename, conditions):
    # Use the variables of the corresponding table
    if tablename == "packets":
        table_column_names = PKT_COLUMN_NAMES
    elif tablename == "basic_information":
        table_column_names = BASIC_INFO_COLUMN_NAMES
    elif tablename == "battery_percentages":
        table_column_names = BTRY_PERC_COLUMN_NAMES
    elif tablename == "events":
        table_column_names = EVENTS_COLUMN_NAMES
    else:
        raise ValueError("Unknown table name \"{}\"".format(tablename))

    # Construct the selection command
    select_command = "SELECT COUNT(*) FROM {}".format(tablename)
    expr_statements = []
    expr_values = []
    if conditions is not None:
        select_command += " WHERE "
        for condition in conditions:
            param = condition[0]
            value = condition[1]
            if param[0] == "!":
                neq = True
                param = param[1:]
            else:
                neq = False
            if param not in table_column_names:
                raise ValueError("Unknown column name \"{}\"".format(param))
            elif value is None:
                if neq:
                    expr_statements.append("{} IS NOT NULL".format(param))
                else:
                    expr_statements.append("{} IS NULL".format(param))
            else:
                if neq:
                    expr_statements.append("{}!=?".format(param))
                else:
                    expr_statements.append("{}=?".format(param))
                expr_values.append(value)
        select_command += " AND ".join(expr_statements)

    # Return the results of the constructed command
    cursor.execute(select_command, tuple(expr_values))
    return cursor.fetchall()[0][0]


def store_networks(networks):
    # Drop the table if it already exists
    cursor.execute("DROP TABLE IF EXISTS networks")

    # Create the table
    cursor.execute(
        "CREATE TABLE networks("
        + "panid TEXT NOT NULL, "
        + "epidset TEXT NOT NULL, "
        + "earliest REAL, "
        + "latest REAL)",
    )

    # Insert the data into the table
    for panid in networks.keys():
        cursor.execute(
            "INSERT INTO networks VALUES (?, ?, ?, ?)",
            (
                panid,
                ";".join(sorted(networks[panid]["epidset"])),
                networks[panid]["earliest"],
                networks[panid]["latest"],
            ),
        )


def store_short_addresses(short_addresses):
    # Drop the table if it already exists
    cursor.execute("DROP TABLE IF EXISTS short_addresses")

    # Create the table
    cursor.execute(
        "CREATE TABLE short_addresses("
        + "panid TEXT NOT NULL, "
        + "shortaddr TEXT NOT NULL, "
        + "altset TEXT NOT NULL, "
        + "macset TEXT NOT NULL, "
        + "nwkset TEXT NOT NULL, "
        + "earliest REAL, "
        + "latest REAL)",
    )

    # Insert the data into the table
    for (panid, shortaddr) in short_addresses.keys():
        cursor.execute(
            "INSERT INTO short_addresses VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                panid,
                shortaddr,
                ";".join(
                    sorted(short_addresses[(panid, shortaddr)]["altset"]),
                ),
                ";".join(
                    sorted(short_addresses[(panid, shortaddr)]["macset"]),
                ),
                ";".join(
                    sorted(short_addresses[(panid, shortaddr)]["nwkset"]),
                ),
                short_addresses[(panid, shortaddr)]["earliest"],
                short_addresses[(panid, shortaddr)]["latest"],
             ),
        )


def store_extended_addresses(extended_addresses):
    # Drop the table if it already exists
    cursor.execute("DROP TABLE IF EXISTS extended_addresses")

    # Create the table
    cursor.execute(
        "CREATE TABLE extended_addresses("
        + "extendedaddr TEXT NOT NULL, "
        + "altset TEXT NOT NULL, "
        + "macset TEXT NOT NULL, "
        + "nwkset TEXT NOT NULL, "
        + "earliest REAL, "
        + "latest REAL)",
    )

    # Insert the data into the table
    for extendedaddr in extended_addresses.keys():
        cursor.execute(
            "INSERT INTO extended_addresses VALUES (?, ?, ?, ?, ?, ?)",
            (
                extendedaddr,
                ";".join(
                    [
                        str(localaddr)
                        for localaddr in sorted(
                            extended_addresses[extendedaddr]["altset"],
                        )
                    ],
                ),
                ";".join(
                    sorted(extended_addresses[extendedaddr]["macset"]),
                ),
                ";".join(
                    sorted(extended_addresses[extendedaddr]["nwkset"]),
                ),
                extended_addresses[extendedaddr]["earliest"],
                extended_addresses[extendedaddr]["latest"],
            ),
        )


def store_pairs(pairs):
    # Drop the table if it already exists
    cursor.execute("DROP TABLE IF EXISTS pairs")

    # Create the table
    cursor.execute(
        "CREATE TABLE pairs("
        + "panid TEXT NOT NULL, "
        + "srcaddr TEXT NOT NULL, "
        + "dstaddr TEXT NOT NULL, "
        + "earliest REAL NOT NULL, "
        + "latest REAL NOT NULL)",
    )

    # Insert the data into the table
    for (panid, srcaddr, dstaddr) in pairs.keys():
        cursor.execute(
            "INSERT INTO pairs VALUES (?, ?, ?, ?, ?)",
            (
                panid,
                srcaddr,
                dstaddr,
                pairs[(panid, srcaddr, dstaddr)]["earliest"],
                pairs[(panid, srcaddr, dstaddr)]["latest"],
            ),
        )


def get_nwkdevtype(panid, shortaddr, extendedaddr):
    nwkset = set()

    if panid is not None and shortaddr is not None:
        cursor.execute(
            "SELECT nwkset FROM short_addresses "
            + "WHERE panid=? AND shortaddr=?",
            (panid, shortaddr),
        )
        results = cursor.fetchall()
        if len(results) > 1 or (len(results) == 1 and ";" in results[0][0]):
            return "Conflicting Data"
        elif len(results) == 1:
            nwkset.add(results[0][0])

    if extendedaddr is not None:
        cursor.execute(
            "SELECT nwkset FROM extended_addresses "
            + "WHERE extendedaddr=?",
            (extendedaddr,),
        )
        results = cursor.fetchall()
        if len(results) > 1 or (len(results) == 1 and ";" in results[0][0]):
            return "Conflicting Data"
        elif len(results) == 1:
            nwkset.add(results[0][0])

    if len(nwkset) == 0:
        return None
    elif len(nwkset) == 1:
        return list(nwkset)[0]
    else:
        return "Conflicting Data"


def update_packets(selected_columns, selected_values, conditions):
    # Sanity checks
    if len(selected_columns) == 0:
        raise ValueError("At least one selected column is required")
    elif len(selected_columns) != len(selected_values):
        raise ValueError(
            "The number of selected columns does not match "
            + "the number of selected values",
        )
    for column_name in selected_columns:
        if column_name not in PKT_COLUMN_NAMES:
            raise ValueError("Unknown column name \"{}\"".format(column_name))

    # Update the packets table
    update_command = "UPDATE packets SET {}".format(
        ", ".join(["{} = ?".format(x) for x in selected_columns]),
    )
    expr_statements = []
    expr_values = list(selected_values)
    if conditions is not None:
        update_command += " WHERE "
        for condition in conditions:
            param = condition[0]
            value = condition[1]
            if param[0] == "!":
                neq = True
                param = param[1:]
            else:
                neq = False
            if param not in PKT_COLUMN_NAMES:
                raise ValueError("Unknown column name \"{}\"".format(param))
            elif value is None:
                if neq:
                    expr_statements.append("{} IS NOT NULL".format(param))
                else:
                    expr_statements.append("{} IS NULL".format(param))
            else:
                if neq:
                    expr_statements.append("{}!=?".format(param))
                else:
                    expr_statements.append("{}=?".format(param))
                expr_values.append(value)
        update_command += " AND ".join(expr_statements)

    # Execute the constructed command
    cursor.execute(update_command, tuple(expr_values))


def disconnect():
    global connection
    global cursor

    # Close the connection with the database
    cursor.close()
    connection.close()
    connection = None
    cursor = None
