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

"""
Database module for the zigator package
"""

import sqlite3
import string


# Define the columns of the packets table in the database
PKT_COLUMNS = [
    ("pcap_directory", "TEXT"),
    ("pcap_filename", "TEXT"),
    ("pkt_num", "INTEGER"),
    ("pkt_time", "REAL"),
    ("pkt_raw", "TEXT"),
    ("pkt_show", "TEXT"),
    ("phy_length", "INTEGER"),
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
    ("aps_clusterid", "TEXT"),
    ("aps_clustername", "TEXT"),
    ("aps_profileid", "TEXT"),
    ("aps_profilename", "TEXT"),
    ("aps_srcendpoint", "INTEGER"),
    ("aps_counter", "INTEGER"),
    ("aps_fragmentation", "TEXT"),
    ("aps_blocknumber", "INTEGER"),
    ("aps_ackbitfield", "INTEGER"),
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
    ("aps_tunnel_dstextendedaddr", "TEXT"),
    ("aps_tunnel_frametype", "TEXT"),
    ("aps_tunnel_delmode", "TEXT"),
    ("aps_tunnel_ackformat", "TEXT"),
    ("aps_tunnel_security", "TEXT"),
    ("aps_tunnel_ackreq", "TEXT"),
    ("aps_tunnel_exthdr", "TEXT"),
    ("aps_tunnel_counter", "INTEGER"),
    ("aps_verifykey_stdkeytype", "TEXT"),
    ("aps_verifykey_extendedaddr", "TEXT"),
    ("aps_verifykey_keyhash", "TEXT"),
    ("aps_confirmkey_status", "TEXT"),
    ("aps_confirmkey_stdkeytype", "TEXT"),
    ("aps_confirmkey_extendedaddr", "TEXT"),
    ("zdp_seqnum", "INTEGER"),
    ("zcl_frametype", "TEXT"),
    ("zcl_manufspecific", "TEXT"),
    ("zcl_direction", "TEXT"),
    ("zcl_disdefrsp", "TEXT"),
    ("zcl_manufcode", "TEXT"),
    ("zcl_seqnum", "INTEGER"),
    ("zcl_cmd_id", "TEXT"),
    ("warning_msg", "TEXT"),
    ("error_msg", "TEXT"),
]

# Define a list that contains only the column names for each table
PKT_COLUMN_NAMES = [column[0] for column in PKT_COLUMNS]

# Define sets that will be used to construct valid column definitions
ALLOWED_CHARACTERS = set(string.ascii_letters + string.digits + "_")
ALLOWED_TYPES = set(["TEXT", "INTEGER", "REAL", "BLOB"])
CONSTRAINED_PKT_COLUMNS = set([
    "pcap_directory",
    "pcap_filename",
    "pkt_num",
    "pkt_time",
    "pkt_raw",
    "pkt_show",
])

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
    global connection
    global cursor

    if tablename == "packets":
        columns = PKT_COLUMNS
        constrained_columns = CONSTRAINED_PKT_COLUMNS
    else:
        raise ValueError("Unknown table name \"{}\"".format(tablename))

    # Drop the table if it already exists
    table_drop_command = "DROP TABLE IF EXISTS {}".format(tablename)
    cursor.execute(table_drop_command)
    connection.commit()

    # Create the table
    table_creation_command = "CREATE TABLE {}(".format(tablename)
    delimiter_needed = False
    for column in columns:
        if delimiter_needed:
            table_creation_command += ", "
        else:
            delimiter_needed = True

        column_name = column[0]
        column_type = column[1]

        for i in range(len(column_name)):
            if column_name[i] not in ALLOWED_CHARACTERS:
                raise ValueError("The character \"{}\" in the name of the "
                                 "column \"{}\" is not allowed"
                                 "".format(column_name[i], column_name))

        if column_name[0].isdigit():
            raise ValueError("The name of the column \"{}\" is not allowed "
                             "because it starts with a digit"
                             "".format(column_name))

        table_creation_command += column_name

        if column_type not in ALLOWED_TYPES:
            raise ValueError("The column type \"{}\" is not in the "
                             "set of allowed column types {}"
                             "".format(column_type, ALLOWED_TYPES))

        table_creation_command += " " + column_type

        if column_name in constrained_columns:
            table_creation_command += " NOT NULL"
    table_creation_command += ")"

    cursor.execute(table_creation_command)
    connection.commit()


def insert_pkt(entry):
    global connection
    global cursor

    # Insert the parsed data into the database
    cursor.execute("INSERT INTO packets VALUES ({})"
                   "".format(", ".join("?"*len(PKT_COLUMNS))),
                   tuple(entry[column_name]
                         for column_name in PKT_COLUMN_NAMES))
    connection.commit()


def merge_old_rows(panid, shortaddr, extendedaddr):
    global connection
    global cursor

    # Fetch the row that contains only the short address
    short_command = (
        "SELECT panid, epid, shortaddr, extendedaddr, macdevtype, nwkdevtype "
        "FROM devices WHERE panid=? AND shortaddr=? AND extendedaddr IS NULL"
    )
    cursor.execute(short_command, tuple([panid, shortaddr]))
    short_row = cursor.fetchall()
    if len(short_row) == 0:
        # There is no need to merge any rows
        return
    elif len(short_row) != 1:
        raise ValueError("Multiple entries for a device in the database")

    # Fetch the row that contains only the extended address
    extended_command = (
        "SELECT panid, epid, shortaddr, extendedaddr, macdevtype, nwkdevtype "
        "FROM devices WHERE panid=? AND shortaddr IS NULL AND extendedaddr=?"
    )
    cursor.execute(short_command, tuple([panid, extendedaddr]))
    extended_row = cursor.fetchall()
    if len(extended_row) == 0:
        # There is no need to merge any rows
        return
    elif len(extended_row) != 1:
        raise ValueError("Multiple entries for a device in the database")

    # Merge the information of the two rows
    if short_row[0][1] is not None and extended_row[0][1] is None:
        epid = short_row[0][1]
    elif short_row[0][1] is None and extended_row[0][1] is not None:
        epid = extended_row[0][1]
    elif short_row[0][1] != extended_row[0][1]:
        raise ValueError("Conflicting EPID values")
    else:
        epid = short_row[0][1]

    if short_row[0][4] is not None and extended_row[0][4] is None:
        macdevtype = short_row[0][4]
    elif short_row[0][4] is None and extended_row[0][4] is not None:
        macdevtype = extended_row[0][4]
    elif short_row[0][4] != extended_row[0][4]:
        raise ValueError("Conflicting MAC device type values")
    else:
        macdevtype = short_row[0][4]

    if short_row[0][5] is not None and extended_row[0][5] is None:
        nwkdevtype = short_row[0][5]
    elif short_row[0][5] is None and extended_row[0][5] is not None:
        nwkdevtype = extended_row[0][5]
    elif short_row[0][5] != extended_row[0][5]:
        raise ValueError("Conflicting NWK device type values")
    else:
        nwk_devtype = short_row[0][5]

    # Delete the rows from the table
    delete_command = (
        "DELETE FROM devices "
        "WHERE panid=? AND shortaddr=? AND extendedaddr IS NULL"
    )
    cursor.execute(delete_command, tuple([panid, shortaddr]))
    connection.commit()
    delete_command = (
        "DELETE FROM devices "
        "WHERE panid=? AND shortaddr IS NULL AND extendedaddr=?"
    )
    cursor.execute(delete_command, tuple([panid, extendedaddr]))
    connection.commit()

    # Insert the merged row into the table
    cursor.execute("INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?)",
                   tuple([panid, epid,
                          shortaddr, extendedaddr,
                          macdevtype, nwkdevtype]))
    connection.commit()


def merge_short_row(panid, shortaddr, extendedaddr):
    global connection
    global cursor

    # Fetch the row that contains only the short address
    short_command = (
        "SELECT panid, epid, shortaddr, extendedaddr, macdevtype, nwkdevtype "
        "FROM devices WHERE panid=? AND shortaddr=? AND extendedaddr IS NULL"
    )
    cursor.execute(short_command, tuple([panid, shortaddr]))
    short_row = cursor.fetchall()
    if len(short_row) == 0:
        # There is no need to merge any rows
        return
    elif len(short_row) != 1:
        raise ValueError("Multiple entries for a device in the database")

    # Fetch the row that contains both addresses
    merged_command = (
        "SELECT panid, epid, shortaddr, extendedaddr, macdevtype, nwkdevtype "
        "FROM devices WHERE panid=? AND shortaddr=? AND extendedaddr=?"
    )
    cursor.execute(merged_command, tuple([panid, shortaddr, extendedaddr]))
    merged_row = cursor.fetchall()
    if len(merged_row) == 0:
        raise ValueError("Unable to fetch the merged row")
    elif len(merged_row) != 1:
        raise ValueError("Multiple entries for a device in the database")

    # Merge the information of the two rows
    if short_row[0][1] is not None and merged_row[0][1] is None:
        update_command = (
            "UPDATE devices SET epid=? "
            "WHERE panid=? AND shortaddr=? AND extendedaddr=?"
        )
        cursor.execute(update_command, tuple([short_row[0][1], panid,
                                              shortaddr, extendedaddr]))
        connection.commit()
    elif short_row[0][1] is not None and merged_row[0][1] is not None:
        if short_row[0][1] != merged_row[0][1]:
            raise ValueError("Conflicting EPID values")

    if short_row[0][4] is not None and merged_row[0][4] is None:
        update_command = (
            "UPDATE devices SET macdevtype=? "
            "WHERE panid=? AND shortaddr=? AND extendedaddr=?"
        )
        cursor.execute(update_command, tuple([short_row[0][4], panid,
                                              shortaddr, extendedaddr]))
        connection.commit()
    elif short_row[0][4] is not None and merged_row[0][4] is not None:
        if short_row[0][4] != merged_row[0][4]:
            raise ValueError("Conflicting MAC device type values")

    if short_row[0][5] is not None and merged_row[0][5] is None:
        update_command = (
            "UPDATE devices SET nwkdevtype=? "
            "WHERE panid=? AND shortaddr=? AND extendedaddr=?"
        )
        cursor.execute(update_command, tuple([short_row[0][5], panid,
                                              shortaddr, extendedaddr]))
        connection.commit()
    elif short_row[0][5] is not None and merged_row[0][5] is not None:
        if short_row[0][5] != merged_row[0][5]:
            raise ValueError("Conflicting NWK device type values")

    # Delete the row that contains only the short address
    delete_command = (
        "DELETE FROM devices "
        "WHERE panid=? AND shortaddr=? AND extendedaddr IS NULL"
    )
    cursor.execute(delete_command, tuple([panid, shortaddr]))
    connection.commit()


def merge_extended_row(panid, shortaddr, extendedaddr):
    global connection
    global cursor

    # Fetch the row that contains only the extended address
    extended_command = (
        "SELECT panid, epid, shortaddr, extendedaddr, macdevtype, nwkdevtype "
        "FROM devices WHERE panid=? AND shortaddr IS NULL AND extendedaddr=?"
    )
    cursor.execute(extended_command, tuple([panid, extendedaddr]))
    extended_row = cursor.fetchall()
    if len(extended_row) == 0:
        # There is no need to merge any rows
        return
    elif len(extended_row) != 1:
        raise ValueError("Multiple entries for a device in the database")

    # Fetch the row that contains both addresses
    merged_command = (
        "SELECT panid, epid, shortaddr, extendedaddr, macdevtype, nwkdevtype "
        "FROM devices WHERE panid=? AND shortaddr=? AND extendedaddr=?"
    )
    cursor.execute(merged_command, tuple([panid, shortaddr, extendedaddr]))
    merged_row = cursor.fetchall()
    if len(merged_row) == 0:
        raise ValueError("Unable to fetch the merged row")
    elif len(merged_row) != 1:
        raise ValueError("Multiple entries for a device in the database")

    # Merge the information of the two rows
    if extended_row[0][1] is not None and merged_row[0][1] is None:
        update_command = (
            "UPDATE devices SET epid=? "
            "WHERE panid=? AND shortaddr=? AND extendedaddr=?"
        )
        cursor.execute(update_command, tuple([short_row[0][1], panid,
                                              shortaddr, extendedaddr]))
        connection.commit()
    elif extended_row[0][1] is not None and merged_row[0][1] is not None:
        if extended_row[0][1] != merged_row[0][1]:
            raise ValueError("Conflicting EPID values")

    if extended_row[0][4] is not None and merged_row[0][4] is None:
        update_command = (
            "UPDATE devices SET macdevtype=? "
            "WHERE panid=? AND shortaddr=? AND extendedaddr=?"
        )
        cursor.execute(update_command, tuple([short_row[0][4], panid,
                                              shortaddr, extendedaddr]))
        connection.commit()
    elif extended_row[0][4] is not None and merged_row[0][4] is not None:
        if extended_row[0][4] != merged_row[0][4]:
            raise ValueError("Conflicting MAC device type values")

    if extended_row[0][5] is not None and merged_row[0][5] is None:
        update_command = (
            "UPDATE devices SET nwkdevtype=? "
            "WHERE panid=? AND shortaddr=? AND extendedaddr=?"
        )
        cursor.execute(update_command, tuple([short_row[0][5], panid,
                                              shortaddr, extendedaddr]))
        connection.commit()
    elif extended_row[0][5] is not None and merged_row[0][5] is not None:
        if extended_row[0][5] != merged_row[0][5]:
            raise ValueError("Conflicting NWK device type values")

    # Delete the row that contains only the extended address
    delete_command = (
        "DELETE FROM devices "
        "WHERE panid=? AND shortaddr IS NULL AND extendedaddr=?"
    )
    cursor.execute(delete_command, tuple([panid, extendedaddr]))
    connection.commit()


def grouped_count(selected_columns, count_errors):
    global cursor

    # Sanity check
    for column_name in selected_columns:
        if column_name not in PKT_COLUMN_NAMES:
            raise ValueError("Unknown column name \"{}\"".format(column_name))

    # Construct the selection command
    column_csv = ", ".join(selected_columns)
    select_command = "SELECT {}, COUNT(*) FROM packets".format(column_csv)
    if not count_errors:
        select_command += " WHERE error_msg IS NULL"
    select_command += " GROUP BY {}".format(column_csv)

    # Return the results of the constructed command
    cursor.execute(select_command)
    return cursor.fetchall()


def distinct_values(selected_columns, conditions):
    global cursor

    # Sanity check
    for column_name in selected_columns:
        if column_name not in PKT_COLUMN_NAMES:
            raise ValueError("Unknown column name \"{}\"".format(column_name))

    # Construct the selection command
    column_csv = ", ".join(selected_columns)
    select_command = "SELECT DISTINCT {} FROM packets".format(column_csv)
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
        select_command += " AND ".join(expr_statements)

    # Return the results of the constructed command
    cursor.execute(select_command, tuple(expr_values))
    return cursor.fetchall()


def matching_frequency(conditions):
    global cursor

    # Construct the selection command
    select_command = "SELECT COUNT(*) FROM packets"
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
        select_command += " AND ".join(expr_statements)

    # Return the results of the constructed command
    cursor.execute(select_command, tuple(expr_values))
    return cursor.fetchall()[0][0]


def disconnect():
    global connection
    global cursor

    # Close the connection with the database
    connection.close()
    connection = None
    cursor = None
