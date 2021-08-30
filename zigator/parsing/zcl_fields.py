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

from scapy.all import ZCLGeneralConfigureReporting
from scapy.all import ZCLGeneralConfigureReportingResponse
from scapy.all import ZCLGeneralDefaultResponse
from scapy.all import ZCLGeneralReadAttributes
from scapy.all import ZCLGeneralReadAttributesResponse
from scapy.all import ZCLGeneralReportAttributes
from scapy.all import ZCLGeneralWriteAttributes
from scapy.all import ZCLGeneralWriteAttributesResponse
from scapy.all import ZCLIASZoneZoneEnrollRequest
from scapy.all import ZCLIASZoneZoneEnrollResponse
from scapy.all import ZCLIASZoneZoneStatusChangeNotification
from scapy.all import ZigbeeClusterLibrary

from .. import config


ZCL_FRAME_TYPES = {
    0: "0b00: Global Command",
    1: "0b01: Cluster-Specific Command",
}

MS_STATES = {
    0: "0b0: The command is not manufacturer-specific",
    1: "0b1: The command is manufacturer-specific",
}

DIRECTION_STATES = {
    0: "0b0: From the client to the server",
    1: "0b1: From the server to the client",
}

DR_STATES = {
    0: "0b0: A Default Response will be returned",
    1: "0b1: A Default Response will be returned only if there is an error",
}

GLOBAL_COMMANDS = {
    0x00: "0x00: Read Attributes",
    0x01: "0x01: Read Attributes Response",
    0x02: "0x02: Write Attributes",
    0x03: "0x03: Write Attributes Undivided",
    0x04: "0x04: Write Attributes Response",
    0x05: "0x05: Write Attributes No Response",
    0x06: "0x06: Configure Reporting",
    0x07: "0x07: Configure Reporting Response",
    0x08: "0x08: Read Reporting Configuration",
    0x09: "0x09: Read Reporting Configuration Response",
    0x0a: "0x0a: Report Attributes",
    0x0b: "0x0b: Default Response",
    0x0c: "0x0c: Discover Attributes",
    0x0d: "0x0d: Discover Attributes Response",
    0x0e: "0x0e: Read Attributes Structured",
    0x0f: "0x0f: Write Attributes Structured",
    0x10: "0x10: Write Attributes Structured Response",
    0x11: "0x11: Discover Commands Received",
    0x12: "0x12: Discover Commands Received Response",
    0x13: "0x13: Discover Commands Generated",
    0x14: "0x14: Discover Commands Generated Response",
    0x15: "0x15: Discover Commands Extended",
    0x16: "0x16: Discover Commands Extended Response",
}

ZCL_CMD_STATUSES = {
    0x00: "0x00: SUCCESS",
    0x01: "0x01: FAILURE",
    0x7e: "0x7e: NOT_AUTHORIZED",
    0x7f: "0x7f: RESERVED_FIELD_NOT_ZERO",
    0x80: "0x80: MALFORMED_COMMAND",
    0x81: "0x81: UNSUP_CLUSTER_COMMAND",
    0x82: "0x82: UNSUP_GENERAL_COMMAND",
    0x83: "0x83: UNSUP_MANUF_CLUSTER_COMMAND",
    0x84: "0x84: UNSUP_MANUF_GENERAL_COMMAND",
    0x85: "0x85: INVALID_FIELD",
    0x86: "0x86: UNSUPPORTED_ATTRIBUTE",
    0x87: "0x87: INVALID_VALUE",
    0x88: "0x88: READ_ONLY",
    0x89: "0x89: INSUFFICIENT_SPACE",
    0x8a: "0x8a: DUPLICATE_EXISTS",
    0x8b: "0x8b: NOT_FOUND",
    0x8c: "0x8c: UNREPORTABLE_ATTRIBUTE",
    0x8d: "0x8d: INVALID_DATA_TYPE",
    0x8e: "0x8e: INVALID_SELECTOR",
    0x8f: "0x8f: WRITE_ONLY",
    0x90: "0x90: INCONSISTENT_STARTUP_STATE",
    0x91: "0x91: DEFINED_OUT_OF_BAND",
    0x92: "0x92: INCONSISTENT",
    0x93: "0x93: ACTION_DENIED",
    0x94: "0x94: TIMEOUT",
    0x95: "0x95: ABORT",
    0x96: "0x96: INVALID_IMAGE",
    0x97: "0x97: WAIT_FOR_DATA",
    0x98: "0x98: NO_IMAGE_AVAILABLE",
    0x99: "0x99: REQUIRE_MORE_IMAGE",
    0x9a: "0x9a: NOTIFICATION_PENDING",
    0xc0: "0xc0: HARDWARE_FAILURE",
    0xc1: "0xc1: SOFTWARE_FAILURE",
    0xc2: "0xc2: CALIBRATION_ERROR",
    0xc3: "0xc3: UNSUPPORTED_CLUSTER",
}

ZCL_ATTR_DATATYPES = {
    0x00: "0x00: No data",
    0x08: "0x08: 8-bit data",
    0x09: "0x09: 16-bit data",
    0x0a: "0x0a: 24-bit data",
    0x0b: "0x0b: 32-bit data",
    0x0c: "0x0c: 40-bit data",
    0x0d: "0x0d: 48-bit data",
    0x0e: "0x0e: 56-bit data",
    0x0f: "0x0f: 64-bit data",
    0x10: "0x10: Boolean",
    0x18: "0x18: 8-bit bitmap",
    0x19: "0x19: 16-bit bitmap",
    0x1a: "0x1a: 24-bit bitmap",
    0x1b: "0x1b: 32-bit bitmap",
    0x1c: "0x1c: 40-bit bitmap",
    0x1d: "0x1d: 48-bit bitmap",
    0x1e: "0x1e: 56-bit bitmap",
    0x1f: "0x1f: 64-bit bitmap",
    0x20: "0x20: Unsigned 8-bit integer",
    0x21: "0x21: Unsigned 16-bit integer",
    0x22: "0x22: Unsigned 24-bit integer",
    0x23: "0x23: Unsigned 32-bit integer",
    0x24: "0x24: Unsigned 40-bit integer",
    0x25: "0x25: Unsigned 48-bit integer",
    0x26: "0x26: Unsigned 56-bit integer",
    0x27: "0x27: Unsigned 64-bit integer",
    0x28: "0x28: Signed 8-bit integer",
    0x29: "0x29: Signed 16-bit integer",
    0x2a: "0x2a: Signed 24-bit integer",
    0x2b: "0x2b: Signed 32-bit integer",
    0x2c: "0x2c: Signed 40-bit integer",
    0x2d: "0x2d: Signed 48-bit integer",
    0x2e: "0x2e: Signed 56-bit integer",
    0x2f: "0x2f: Signed 64-bit integer",
    0x30: "0x30: 8-bit enumeration",
    0x31: "0x31: 16-bit enumeration",
    0x38: "0x38: Semi-precision",
    0x39: "0x39: Single precision",
    0x3a: "0x3a: Double precision",
    0x41: "0x41: Octet string",
    0x42: "0x42: Character string",
    0x43: "0x43: Long octet string",
    0x44: "0x44: Long character string",
    0x48: "0x48: Array",
    0x4c: "0x4c: Structure",
    0x50: "0x50: Set",
    0x51: "0x51: Bag",
    0xe0: "0xe0: Time of day",
    0xe1: "0xe1: Date",
    0xe2: "0xe2: UTCTime",
    0xe8: "0xe8: Cluster ID",
    0xe9: "0xe9: Attribute ID",
    0xea: "0xea: BACnet OID",
    0xf0: "0xf0: IEEE address",
    0xf1: "0xf1: 128-bit security key",
    0xff: "0xff: Unknown",
}

ZCL_ATTR_DIRECTIONS = {
    0x00: "0x00: Reported attribute",
    0x01: "0x01: Received attribute",
}

ZCL_IASZONE_RECEIVED_COMMANDS = {
    0x00: "0x00: Zone Enroll Response",
    0x01: "0x01: Initiate Normal Operation Mode",
    0x02: "0x02: Initiate Test Mode",
}

ZCL_IASZONE_ENROLLRESPONSECODES = {
    0x00: "0x00: Success",
    0x01: "0x01: Not supported",
    0x02: "0x02: No enroll permit",
    0x03: "0x03: Too many zones",
}

ZCL_IASZONE_GENERATED_COMMANDS = {
    0x00: "0x00: Zone Status Change Notification",
    0x01: "0x01: Zone Enroll Request",
}

ZCL_IASZONE_ZONETYPES = {
    0x0000: "0x0000: Standard CIE",
    0x000d: "0x000d: Motion sensor",
    0x0015: "0x0015: Contact switch",
    0x0028: "0x0028: Fire sensor",
    0x002a: "0x002a: Water sensor",
    0x002b: "0x002b: Carbon Monoxide (CO) sensor",
    0x002c: "0x002c: Personal emergency device",
    0x002d: "0x002d: Vibration/Movement sensor",
    0x010f: "0x010f: Remote Control",
    0x0115: "0x0115: Key fob",
    0x021d: "0x021d: Keypad",
    0x0225: "0x0225: Standard Warning Device",
    0x0226: "0x0226: Glass break sensor",
    0x0229: "0x0229: Security repeater",
    0xffff: "0xffff: Invalid Zone Type",
}


def zcl_readattributes(pkt):
    # Attribute Identifiers field (variable)
    config.entry["zcl_readattributes_identifiers"] = (
        ",".join("0x{:04x}".format(identifier) for identifier
                 in pkt[ZCLGeneralReadAttributes].attribute_identifiers)
    )

    # ZCL Read Attributes commands do not contain any other fields
    if len(bytes(pkt[ZCLGeneralReadAttributes].payload)) != 0:
        config.entry["error_msg"] = "Unexpected payload"
        return


def zcl_readattributesresponse(pkt):
    # Read Attribute Status Records field (variable)
    num_records = len(pkt[
        ZCLGeneralReadAttributesResponse].read_attribute_status_record)
    tmp_identifiers = []
    tmp_statuses = []
    tmp_datatypes = []
    tmp_values = []
    for i in range(num_records):
        tmp_record = pkt[
            ZCLGeneralReadAttributesResponse].read_attribute_status_record[i]

        # Attribute Identifier subfield (2 bytes)
        tmp_identifiers.append("0x{:04x}".format(
            tmp_record.attribute_identifier))

        # Status subfield (1 byte)
        if tmp_record.status in ZCL_CMD_STATUSES.keys():
            tmp_statuses.append(ZCL_CMD_STATUSES[tmp_record.status])
        else:
            tmp_statuses.append("0x{:02x}: Unknown ZCL command status".format(
                tmp_record.status))
            config.entry["warning_msg"] = "Unknown ZCL command status"

        # Attribute Data Type subfield (0/1 byte)
        if tmp_statuses[-1].startswith("0x00:"):
            if tmp_record.attribute_data_type in ZCL_ATTR_DATATYPES.keys():
                tmp_datatypes.append(
                    ZCL_ATTR_DATATYPES[tmp_record.attribute_data_type])
            else:
                config.entry["error_msg"] = "Unknown ZCL attribute data type"
                return
        else:
            tmp_datatypes.append("Omitted")

        # Attribute Value subfield (variable)
        if tmp_statuses[-1].startswith("0x00:"):
            tmp_values.append("0x" + tmp_record.attribute_value.hex())
        else:
            tmp_values.append("Omitted")
    config.entry["zcl_readattributesresponse_identifiers"] = (
        ",".join(identifier for identifier in tmp_identifiers)
    )
    config.entry["zcl_readattributesresponse_statuses"] = (
        ",".join(status for status in tmp_statuses)
    )
    config.entry["zcl_readattributesresponse_datatypes"] = (
        ",".join(datatype for datatype in tmp_datatypes)
    )
    config.entry["zcl_readattributesresponse_values"] = (
        ",".join(value for value in tmp_values)
    )

    # ZCL Read Attributes Response commands do not contain any other fields
    if len(bytes(pkt[ZCLGeneralReadAttributesResponse].payload)) != 0:
        config.entry["error_msg"] = "Unexpected payload"
        return


def zcl_writeattributes(pkt):
    # Write Attribute Records field (variable)
    num_records = len(pkt[ZCLGeneralWriteAttributes].write_records)
    tmp_identifiers = []
    tmp_datatypes = []
    tmp_data = []
    for i in range(num_records):
        tmp_record = pkt[ZCLGeneralWriteAttributes].write_records[i]

        # Attribute Identifier subfield (2 bytes)
        tmp_identifiers.append("0x{:04x}".format(
            tmp_record.attribute_identifier))

        # Attribute Data Type subfield (1 byte)
        if tmp_record.attribute_data_type in ZCL_ATTR_DATATYPES.keys():
            tmp_datatypes.append(
                ZCL_ATTR_DATATYPES[tmp_record.attribute_data_type])
        else:
            config.entry["error_msg"] = "Unknown ZCL attribute data type"
            return

        # Attribute Data subfield (variable)
        tmp_data.append("0x" + tmp_record.attribute_data.hex())
    config.entry["zcl_writeattributes_identifiers"] = (
        ",".join(identifier for identifier in tmp_identifiers)
    )
    config.entry["zcl_writeattributes_datatypes"] = (
        ",".join(datatype for datatype in tmp_datatypes)
    )
    config.entry["zcl_writeattributes_data"] = (
        ",".join(data for data in tmp_data)
    )

    # ZCL Write Attributes commands do not contain any other fields
    if len(bytes(pkt[ZCLGeneralWriteAttributes].payload)) != 0:
        config.entry["error_msg"] = "Unexpected payload"
        return


def zcl_writeattributesresponse(pkt):
    # Write Attribute Status Records field (variable)
    num_records = len(pkt[ZCLGeneralWriteAttributesResponse].status_records)
    tmp_statuses = []
    tmp_identifiers = []
    for i in range(num_records):
        tmp_record = pkt[ZCLGeneralWriteAttributesResponse].status_records[i]

        # Status subfield (1 byte)
        if tmp_record.status in ZCL_CMD_STATUSES.keys():
            tmp_statuses.append(ZCL_CMD_STATUSES[tmp_record.status])
        else:
            tmp_statuses.append("0x{:02x}: Unknown ZCL command status".format(
                tmp_record.status))
            config.entry["warning_msg"] = "Unknown ZCL command status"

        # Attribute Identifier subfield (0/2 bytes)
        if not tmp_statuses[-1].startswith("0x00:"):
            tmp_identifiers.append("0x{:04x}".format(
                tmp_record.attribute_identifier))
        else:
            tmp_identifiers.append("Omitted")
    config.entry["zcl_writeattributesresponse_statuses"] = (
        ",".join(status for status in tmp_statuses)
    )
    config.entry["zcl_writeattributesresponse_identifiers"] = (
        ",".join(identifier for identifier in tmp_identifiers)
    )

    # ZCL Write Attributes Response commands do not contain any other fields
    if len(bytes(pkt[ZCLGeneralWriteAttributesResponse].payload)) != 0:
        config.entry["error_msg"] = "Unexpected payload"
        return


def zcl_configurereporting(pkt):
    # Attribute Reporting Configuration Records field (variable)
    num_records = len(pkt[ZCLGeneralConfigureReporting].config_records)
    tmp_directions = []
    tmp_identifiers = []
    tmp_datatypes = []
    tmp_minintervals = []
    tmp_maxintervals = []
    tmp_changes = []
    tmp_timeoutperiods = []
    for i in range(num_records):
        tmp_record = pkt[ZCLGeneralConfigureReporting].config_records[i]

        # Direction subfield (1 byte)
        if tmp_record.attribute_direction in ZCL_ATTR_DIRECTIONS.keys():
            tmp_directions.append(
                ZCL_ATTR_DIRECTIONS[tmp_record.attribute_direction])
        else:
            config.entry["error_msg"] = "Unknown ZCL attribute direction"
            return

        # Attribute Identifier subfield (2 bytes)
        tmp_identifiers.append("0x{:04x}".format(
            tmp_record.attribute_identifier))

        # Attribute Data Type subfield (0/1 byte)
        if tmp_directions[-1].startswith("0x00:"):
            if tmp_record.attribute_data_type in ZCL_ATTR_DATATYPES.keys():
                tmp_datatypes.append(
                    ZCL_ATTR_DATATYPES[tmp_record.attribute_data_type])
            else:
                config.entry["error_msg"] = "Unknown ZCL attribute data type"
                return
        else:
            tmp_datatypes.append("Omitted")

        # Minimum Reporting Interval subfield (0/2 bytes)
        if tmp_directions[-1].startswith("0x00:"):
            tmp_minintervals.append(str(tmp_record.min_reporting_interval))
        else:
            tmp_minintervals.append("Omitted")

        # Maximum Reporting Interval subfield (0/2 bytes)
        if tmp_directions[-1].startswith("0x00:"):
            tmp_maxintervals.append(str(tmp_record.max_reporting_interval))
        else:
            tmp_maxintervals.append("Omitted")

        # Reportable Change subfield (variable)
        if tmp_directions[-1].startswith("0x00:"):
            tmp_changes.append("0x" + tmp_record.reportable_change.hex())
        else:
            tmp_changes.append("Omitted")

        # Timeout Period subfield (0/2 bytes)
        if tmp_directions[-1].startswith("0x01:"):
            tmp_timeoutperiods.append(str(tmp_record.timeout_period))
        else:
            tmp_timeoutperiods.append("Omitted")
    config.entry["zcl_configurereporting_directions"] = (
        ",".join(direction for direction in tmp_directions)
    )
    config.entry["zcl_configurereporting_identifiers"] = (
        ",".join(identifier for identifier in tmp_identifiers)
    )
    config.entry["zcl_configurereporting_datatypes"] = (
        ",".join(datatype for datatype in tmp_datatypes)
    )
    config.entry["zcl_configurereporting_minintervals"] = (
        ",".join(mininterval for mininterval in tmp_minintervals)
    )
    config.entry["zcl_configurereporting_maxintervals"] = (
        ",".join(maxinterval for maxinterval in tmp_maxintervals)
    )
    config.entry["zcl_configurereporting_changes"] = (
        ",".join(change for change in tmp_changes)
    )
    config.entry["zcl_configurereporting_timeoutperiods"] = (
        ",".join(timeoutperiod for timeoutperiod in tmp_timeoutperiods)
    )

    # ZCL Configure Reporting commands do not contain any other fields
    if len(bytes(pkt[ZCLGeneralConfigureReporting].payload)) != 0:
        config.entry["error_msg"] = "Unexpected payload"
        return


def zcl_configurereportingresponse(pkt):
    # Attribute Status Records field (variable)
    num_records = len(pkt[
        ZCLGeneralConfigureReportingResponse].status_records)
    tmp_statuses = []
    tmp_directions = []
    tmp_identifiers = []
    for i in range(num_records):
        tmp_record = pkt[
            ZCLGeneralConfigureReportingResponse].status_records[i]

        # Status subfield (1 byte)
        if tmp_record.status in ZCL_CMD_STATUSES.keys():
            tmp_statuses.append(ZCL_CMD_STATUSES[tmp_record.status])
        else:
            tmp_statuses.append("0x{:02x}: Unknown ZCL command status".format(
                tmp_record.status))
            config.entry["warning_msg"] = "Unknown ZCL command status"

        # Direction subfield (0/1 byte)
        if not tmp_statuses[-1].startswith("0x00:"):
            if tmp_record.attribute_direction in ZCL_ATTR_DIRECTIONS.keys():
                tmp_directions.append(
                    ZCL_ATTR_DIRECTIONS[tmp_record.attribute_direction])
            else:
                config.entry["error_msg"] = "Unknown ZCL attribute direction"
                return
        else:
            tmp_directions.append("Omitted")

        # Attribute Identifier subfield (0/2 bytes)
        if not tmp_statuses[-1].startswith("0x00:"):
            tmp_identifiers.append("0x{:04x}".format(
                tmp_record.attribute_identifier))
        else:
            tmp_identifiers.append("Omitted")
    config.entry["zcl_configurereportingresponse_statuses"] = (
        ",".join(status for status in tmp_statuses)
    )
    config.entry["zcl_configurereportingresponse_directions"] = (
        ",".join(direction for direction in tmp_directions)
    )
    config.entry["zcl_configurereportingresponse_identifiers"] = (
        ",".join(identifier for identifier in tmp_identifiers)
    )

    # ZCL Configure Reporting Response commands
    # do not contain any other fields
    if len(bytes(pkt[ZCLGeneralConfigureReportingResponse].payload)) != 0:
        config.entry["error_msg"] = "Unexpected payload"
        return


def zcl_reportattributes(pkt):
    # Attribute Reports field (variable)
    num_reports = len(pkt[ZCLGeneralReportAttributes].attribute_reports)
    tmp_identifiers = []
    tmp_datatypes = []
    tmp_data = []
    for i in range(num_reports):
        tmp_report = pkt[ZCLGeneralReportAttributes].attribute_reports[i]

        # Attribute Identifier subfield (2 bytes)
        tmp_identifiers.append("0x{:04x}".format(
            tmp_report.attribute_identifier))

        # Attribute Data Type subfield (1 byte)
        if tmp_report.attribute_data_type in ZCL_ATTR_DATATYPES.keys():
            tmp_datatypes.append(
                ZCL_ATTR_DATATYPES[tmp_report.attribute_data_type])
        else:
            config.entry["error_msg"] = "Unknown ZCL attribute data type"
            return

        # Attribute Data subfield (variable)
        tmp_data.append("0x" + tmp_report.attribute_data.hex())
    config.entry["zcl_reportattributes_identifiers"] = (
        ",".join(identifier for identifier in tmp_identifiers)
    )
    config.entry["zcl_reportattributes_datatypes"] = (
        ",".join(datatype for datatype in tmp_datatypes)
    )
    config.entry["zcl_reportattributes_data"] = (
        ",".join(data for data in tmp_data)
    )

    # ZCL Report Attributes commands do not contain any other fields
    if len(bytes(pkt[ZCLGeneralReportAttributes].payload)) != 0:
        config.entry["error_msg"] = "Unexpected payload"
        return


def zcl_defaultresponse(pkt):
    # Response Command Identifier field (1 byte)
    config.entry["zcl_defaultresponse_rspcmdid"] = "0x{:02x}".format(
        pkt[ZCLGeneralDefaultResponse].response_command_identifier)

    # Status field (1 byte)
    if pkt[ZCLGeneralDefaultResponse].status in ZCL_CMD_STATUSES.keys():
        config.entry["zcl_defaultresponse_status"] = (
            ZCL_CMD_STATUSES[pkt[ZCLGeneralDefaultResponse].status]
        )
    else:
        config.entry["zcl_defaultresponse_status"] = (
            "0x{:02x}: Unknown ZCL command status".format(
                pkt[ZCLGeneralDefaultResponse].status)
        )
        config.entry["warning_msg"] = "Unknown ZCL command status"

    # ZCL Default Response commands do not contain any other fields
    if len(bytes(pkt[ZCLGeneralDefaultResponse].payload)) != 0:
        config.entry["error_msg"] = "Unexpected payload"
        return


def zcl_iaszone_zoneenrollrsp(pkt):
    # Enroll Response Code field (1 byte)
    if not config.set_entry(
            "zcl_iaszone_zoneenrollrsp_code",
            pkt[ZCLIASZoneZoneEnrollResponse].rsp_code,
            ZCL_IASZONE_ENROLLRESPONSECODES):
        config.entry["error_msg"] = (
            "Unknown ZCL IAS Zone enroll response code"
        )
        return

    # Zone ID field (1 byte)
    config.entry["zcl_iaszone_zoneenrollrsp_zoneid"] = "0x{:02x}".format(
        pkt[ZCLIASZoneZoneEnrollResponse].zone_id)

    # ZCL IAS Zone: Zone Enroll Response commands
    # do not contain any other fields
    if len(bytes(pkt[ZCLIASZoneZoneEnrollResponse].payload)) != 0:
        config.entry["error_msg"] = "Unexpected payload"
        return


def zcl_iaszone_zonestatuschangenotif(pkt):
    # Zone Status field (2 bytes)
    config.entry["zcl_iaszone_zonestatuschangenotif_zonestatus"] = (
        "0x" + pkt[
            ZCLIASZoneZoneStatusChangeNotification].zone_status.hex()
    )

    # Extended Status field (1 byte)
    config.entry["zcl_iaszone_zonestatuschangenotif_extendedstatus"] = (
        "0x" + pkt[
            ZCLIASZoneZoneStatusChangeNotification].extended_status.hex()
    )

    # Zone ID field (1 byte)
    config.entry["zcl_iaszone_zonestatuschangenotif_zoneid"] = (
        "0x{:02x}".format(pkt[
            ZCLIASZoneZoneStatusChangeNotification].zone_id)
    )

    # Delay (2 bytes)
    config.entry["zcl_iaszone_zonestatuschangenotif_delay"] = (
        "0x{:04x}".format(pkt[
            ZCLIASZoneZoneStatusChangeNotification].delay)
    )

    # ZCL IAS Zone: Zone Status Change Notification commands
    # do not contain any other fields
    if len(bytes(pkt[ZCLIASZoneZoneStatusChangeNotification].payload)) != 0:
        config.entry["error_msg"] = "Unexpected payload"
        return


def zcl_iaszone_zoneenrollreq(pkt):
    # Zone Type (2 bytes)
    if (pkt[ZCLIASZoneZoneEnrollRequest].zone_type
            in ZCL_IASZONE_ZONETYPES.keys()):
        config.entry["zcl_iaszone_zoneenrollreq_zonetype"] = (
            ZCL_IASZONE_ZONETYPES[pkt[ZCLIASZoneZoneEnrollRequest].zone_type]
        )
    else:
        config.entry["zcl_iaszone_zoneenrollreq_zonetype"] = (
            "0x{:04x}: Unknown zone type".format(
                pkt[ZCLIASZoneZoneEnrollRequest].zone_type)
        )
        config.entry["warning_msg"] = "Unknown zone type"

    # Manufacturer Code (2 bytes)
    config.entry["zcl_iaszone_zoneenrollreq_manufcode"] = "0x{:04x}".format(
        pkt[ZCLIASZoneZoneEnrollRequest].manuf_code)

    # ZCL IAS Zone: Zone Enroll Request commands
    # do not contain any other fields
    if len(bytes(pkt[ZCLIASZoneZoneEnrollRequest].payload)) != 0:
        config.entry["error_msg"] = "Unexpected payload"
        return


def zcl_fields(pkt):
    """Parse Zigbee Cluster Library fields."""
    # Frame Control field (1 byte)
    # Frame Type subfield (2 bits)
    if not config.set_entry(
            "zcl_frametype",
            pkt[ZigbeeClusterLibrary].zcl_frametype,
            ZCL_FRAME_TYPES):
        config.entry["error_msg"] = "PE601: Unknown ZCL frame type"
        return
    # Manufacturer Specific subfield (1 bit)
    if not config.set_entry(
            "zcl_manufspecific",
            pkt[ZigbeeClusterLibrary].manufacturer_specific,
            MS_STATES):
        config.entry["error_msg"] = "PE602: Unknown ZCL MS state"
        return
    # Direction subfield (1 bit)
    if not config.set_entry(
            "zcl_direction",
            pkt[ZigbeeClusterLibrary].command_direction,
            DIRECTION_STATES):
        config.entry["error_msg"] = "PE603: Unknown ZCL direction state"
        return
    # Default Response subfield (1 bit)
    if not config.set_entry(
            "zcl_disdefrsp",
            pkt[ZigbeeClusterLibrary].disable_default_response,
            DR_STATES):
        config.entry["error_msg"] = "PE604: Unknown ZCL DR state"
        return

    # Manufacturer Code field (0/2 bytes)
    if config.entry["zcl_manufspecific"].startswith("0b1:"):
        config.entry["zcl_manufcode"] = "0x{:04x}".format(
            pkt[ZigbeeClusterLibrary].manufacturer_code)
    elif not config.entry["zcl_manufspecific"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid manufacturer-specific state"
        return

    # Transaction Sequence Number field (1 byte)
    config.entry["zcl_seqnum"] = (
        pkt[ZigbeeClusterLibrary].transaction_sequence
    )

    if config.entry["zcl_frametype"].startswith("0b00:"):
        # Command Identifier field (1 byte)
        if not config.set_entry(
                "zcl_cmd_id",
                pkt[ZigbeeClusterLibrary].command_identifier,
                GLOBAL_COMMANDS):
            config.entry["error_msg"] = "PE605: Unknown global command"
            return

        # ZCL Payload field (variable)
        if config.entry["zcl_cmd_id"].startswith("0x00:"):
            if pkt.haslayer(ZCLGeneralReadAttributes):
                zcl_readattributes(pkt)
            else:
                config.entry["error_msg"] = (
                    "There are no ZCL Read Attributes fields"
                )
                return
        elif config.entry["zcl_cmd_id"].startswith("0x01:"):
            if pkt.haslayer(ZCLGeneralReadAttributesResponse):
                zcl_readattributesresponse(pkt)
            else:
                config.entry["error_msg"] = (
                    "There are no ZCL Read Attributes Response fields"
                )
                return
        elif config.entry["zcl_cmd_id"].startswith("0x02:"):
            if pkt.haslayer(ZCLGeneralWriteAttributes):
                zcl_writeattributes(pkt)
            else:
                config.entry["error_msg"] = (
                    "There are no ZCL Write Attributes fields"
                )
                return
        elif config.entry["zcl_cmd_id"].startswith("0x04:"):
            if pkt.haslayer(ZCLGeneralWriteAttributesResponse):
                zcl_writeattributesresponse(pkt)
            else:
                config.entry["error_msg"] = (
                    "There are no ZCL Write Attributes Response fields"
                )
                return
        elif config.entry["zcl_cmd_id"].startswith("0x06:"):
            if pkt.haslayer(ZCLGeneralConfigureReporting):
                zcl_configurereporting(pkt)
            else:
                config.entry["error_msg"] = (
                    "There are no ZCL Configure Reporting fields"
                )
                return
        elif config.entry["zcl_cmd_id"].startswith("0x07:"):
            if pkt.haslayer(ZCLGeneralConfigureReportingResponse):
                zcl_configurereportingresponse(pkt)
            else:
                config.entry["error_msg"] = (
                    "There are no ZCL Configure Reporting Response fields"
                )
                return
        elif config.entry["zcl_cmd_id"].startswith("0x0a:"):
            if pkt.haslayer(ZCLGeneralReportAttributes):
                zcl_reportattributes(pkt)
            else:
                config.entry["error_msg"] = (
                    "There are no ZCL Report Attributes fields"
                )
                return
        elif config.entry["zcl_cmd_id"].startswith("0x0b:"):
            if pkt.haslayer(ZCLGeneralDefaultResponse):
                zcl_defaultresponse(pkt)
            else:
                config.entry["error_msg"] = (
                    "There are no ZCL Default Response fields"
                )
                return
        else:
            config.entry["warning_msg"] = "Unsupported global command"
            return
    elif config.entry["zcl_frametype"].startswith("0b01:"):
        if config.entry["aps_cluster_id"].startswith("0x0500:"):
            if config.entry["zcl_direction"].startswith("0b0:"):
                # Command Identifier field (1 byte)
                if not config.set_entry(
                        "zcl_cmd_id",
                        pkt[ZigbeeClusterLibrary].command_identifier,
                        ZCL_IASZONE_RECEIVED_COMMANDS):
                    config.entry["error_msg"] = (
                        "Unknown ZCL IAS Zone client-to-server command"
                    )
                    return

                # ZCL Payload field (variable)
                if config.entry["zcl_cmd_id"].startswith("0x00:"):
                    if pkt.haslayer(ZCLIASZoneZoneEnrollResponse):
                        zcl_iaszone_zoneenrollrsp(pkt)
                    else:
                        config.entry["error_msg"] = (
                            "There are no ZCL IAS Zone: "
                            "Zone Enroll Response fields"
                        )
                        return
                else:
                    config.entry["warning_msg"] = (
                        "Unsupported ZCL IAS Zone client-to-server command"
                    )
                    return
            elif config.entry["zcl_direction"].startswith("0b1:"):
                # Command Identifier field (1 byte)
                if not config.set_entry(
                        "zcl_cmd_id",
                        pkt[ZigbeeClusterLibrary].command_identifier,
                        ZCL_IASZONE_GENERATED_COMMANDS):
                    config.entry["error_msg"] = (
                        "Unknown ZCL IAS Zone server-to-client command"
                    )
                    return

                # ZCL Payload field (variable)
                if config.entry["zcl_cmd_id"].startswith("0x00:"):
                    if pkt.haslayer(ZCLIASZoneZoneStatusChangeNotification):
                        zcl_iaszone_zonestatuschangenotif(pkt)
                    else:
                        config.entry["error_msg"] = (
                            "There are no ZCL IAS Zone: "
                            "Zone Status Change Notification fields"
                        )
                        return
                elif config.entry["zcl_cmd_id"].startswith("0x01:"):
                    if pkt.haslayer(ZCLIASZoneZoneEnrollRequest):
                        zcl_iaszone_zoneenrollreq(pkt)
                    else:
                        config.entry["error_msg"] = (
                            "There are no ZCL IAS Zone: "
                            "Zone Enroll Request fields"
                        )
                        return
                else:
                    config.entry["warning_msg"] = (
                        "Unsupported ZCL IAS Zone server-to-client command"
                    )
                    return
            else:
                config.entry["error_msg"] = "Invalid ZCL direction state"
                return
        else:
            # Command Identifier field (1 byte)
            config.entry["zcl_cmd_id"] = (
                "0x{:02x}: Unknown cluster-specific command".format(
                    pkt[ZigbeeClusterLibrary].command_identifier)
            )

            # ZCL Payload field (variable)
            config.entry["warning_msg"] = "Unknown cluster-specific command"
            return
    else:
        config.entry["error_msg"] = "Invalid ZCL frame type"
        return
