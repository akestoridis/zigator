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
import multiprocessing as mp
import os

from .. import config


CONDITION_MATCHES = [
    (
        "phy_length--routerequest.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
    ),
    (
        "phy_length--routereply.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
    ),
    (
        "phy_length--networkstatus.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
    ),
    (
        "phy_length--leave.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Leave"),
        ),
    ),
    (
        "phy_length--routerecord.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
    ),
    (
        "phy_length--rejoinreq.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
    ),
    (
        "phy_length--rejoinrsp.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
    ),
    (
        "phy_length--linkstatus.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
    ),
    (
        "phy_length--networkreport.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
    ),
    (
        "phy_length--networkupdate.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
    ),
    (
        "phy_length--edtimeoutreq.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
    ),
    (
        "phy_length--edtimeoutrsp.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--routerequest.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--routereply.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--networkstatus.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--leave.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Leave"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--routerecord.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--rejoinreq.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--rejoinrsp.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--linkstatus.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--networkreport.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--networkupdate.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--edtimeoutreq.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--edtimeoutrsp.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
    (
        "nwk_radius--routerequest.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
    ),
    (
        "nwk_radius--routereply.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
    ),
    (
        "nwk_radius--networkstatus.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
    ),
    (
        "nwk_radius--leave.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Leave"),
        ),
    ),
    (
        "nwk_radius--routerecord.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
    ),
    (
        "nwk_radius--rejoinreq.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
    ),
    (
        "nwk_radius--rejoinrsp.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
    ),
    (
        "nwk_radius--linkstatus.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
    ),
    (
        "nwk_radius--networkreport.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
    ),
    (
        "nwk_radius--networkupdate.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
    ),
    (
        "nwk_radius--edtimeoutreq.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
    ),
    (
        "nwk_radius--edtimeoutrsp.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
    (
        "der_nwk_dsttype--routerequest.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
    ),
    (
        "der_nwk_dsttype--routereply.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
    ),
    (
        "der_nwk_dsttype--networkstatus.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
    ),
    (
        "der_nwk_dsttype--leave.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Leave"),
        ),
    ),
    (
        "der_nwk_dsttype--routerecord.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
    ),
    (
        "der_nwk_dsttype--rejoinreq.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
    ),
    (
        "der_nwk_dsttype--rejoinrsp.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
    ),
    (
        "der_nwk_dsttype--linkstatus.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
    ),
    (
        "der_nwk_dsttype--networkreport.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
    ),
    (
        "der_nwk_dsttype--networkupdate.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
    ),
    (
        "der_nwk_dsttype--edtimeoutreq.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
    ),
    (
        "der_nwk_dsttype--edtimeoutrsp.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
    (
        "der_nwk_srctype--routerequest.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
    ),
    (
        "der_nwk_srctype--routereply.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
    ),
    (
        "der_nwk_srctype--networkstatus.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
    ),
    (
        "der_nwk_srctype--leave.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Leave"),
        ),
    ),
    (
        "der_nwk_srctype--routerecord.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
    ),
    (
        "der_nwk_srctype--rejoinreq.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
    ),
    (
        "der_nwk_srctype--rejoinrsp.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
    ),
    (
        "der_nwk_srctype--linkstatus.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
    ),
    (
        "der_nwk_srctype--networkreport.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
    ),
    (
        "der_nwk_srctype--networkupdate.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
    ),
    (
        "der_nwk_srctype--edtimeoutreq.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
    ),
    (
        "der_nwk_srctype--edtimeoutrsp.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
    (
        "der_mac_dsttype--datarequest_srcshort.tsv",
        (
            "der_mac_dsttype",
        ),
        (
            ("error_msg", None),
            ("mac_cmd_id", "MAC Data Request"),
            ("mac_srcaddrmode", "Short source MAC address")
        ),
    ),
    (
        "der_mac_srctype--datarequest_srcshort.tsv",
        (
            "der_mac_srctype",
        ),
        (
            ("error_msg", None),
            ("mac_cmd_id", "MAC Data Request"),
            ("mac_srcaddrmode", "Short source MAC address")
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-01.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("nwk_cmd_payloadlength", 12),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-02.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("nwk_cmd_payloadlength", 2),
            ("der_nwk_dsttype", "NWK Dst Type: Zigbee End Device"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-03.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("nwk_cmd_payloadlength", 2),
            ("!der_nwk_dsttype", "NWK Dst Type: Zigbee End Device"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-04.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("nwk_cmd_payloadlength", 3),
            ("der_tx_type", "Single-Hop Transmission"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-05.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("nwk_cmd_payloadlength", 3),
            ("der_tx_type", "Multi-Hop Transmission"),
            ("der_nwk_dsttype", "NWK Dst Type: Zigbee End Device"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-06.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("nwk_cmd_payloadlength", 3),
            ("der_tx_type", "Multi-Hop Transmission"),
            ("der_nwk_dsttype", "NWK Dst Type: All active receivers"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-07.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("nwk_cmd_payloadlength", 3),
            ("der_tx_type", "Multi-Hop Transmission"),
            ("!der_nwk_dsttype", "NWK Dst Type: Zigbee End Device"),
            ("!der_nwk_dsttype", "NWK Dst Type: All active receivers"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-08.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("der_tx_type", "Single-Hop Transmission"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-09.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("der_tx_type", "Multi-Hop Transmission"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-10.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 5),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-11.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 9),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-12.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 1),
            ("der_tx_type", "Single-Hop Transmission"),
            ("der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-13.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 1),
            ("der_tx_type", "Single-Hop Transmission"),
            ("!der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
            ("der_nwk_dsttype", "NWK Dst Type: Zigbee End Device"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-14.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 1),
            ("der_tx_type", "Single-Hop Transmission"),
            ("!der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
            ("der_nwk_dsttype", "NWK Dst Type: All active receivers"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-15.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 1),
            ("der_tx_type", "Single-Hop Transmission"),
            ("!der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
            ("!der_nwk_dsttype", "NWK Dst Type: Zigbee End Device"),
            ("!der_nwk_dsttype", "NWK Dst Type: All active receivers"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-16.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 1),
            ("der_tx_type", "Multi-Hop Transmission"),
            ("der_nwk_dsttype", "NWK Dst Type: Zigbee End Device"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-17.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 1),
            ("der_tx_type", "Multi-Hop Transmission"),
            ("der_nwk_dsttype", "NWK Dst Type: All active receivers"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-18.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 1),
            ("der_tx_type", "Multi-Hop Transmission"),
            ("!der_nwk_dsttype", "NWK Dst Type: Zigbee End Device"),
            ("!der_nwk_dsttype", "NWK Dst Type: All active receivers"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-19.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 7),
            ("der_nwk_srctype", "NWK Src Type: Zigbee End Device"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-20.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 7),
            ("!der_nwk_srctype", "NWK Src Type: Zigbee End Device"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-21.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 15),
            ("der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
            ("der_nwk_srctype", "NWK Src Type: Zigbee End Device"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-22.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 15),
            ("der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
            ("!der_nwk_srctype", "NWK Src Type: Zigbee End Device"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-23.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 15),
            ("!der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
            ("der_nwk_srctype", "NWK Src Type: Zigbee End Device"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-24.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 15),
            ("!der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
            ("der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-25.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 15),
            ("!der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
            ("!der_nwk_srctype", "NWK Src Type: Zigbee End Device"),
            ("!der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-26.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 23),
            ("der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
            ("der_nwk_srctype", "NWK Src Type: Zigbee End Device"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-27.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 23),
            ("der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
            ("!der_nwk_srctype", "NWK Src Type: Zigbee End Device"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-28.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 23),
            ("!der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
            ("der_nwk_srctype", "NWK Src Type: Zigbee End Device"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-29.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 23),
            ("!der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
            ("der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-30.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("nwk_cmd_payloadlength", 23),
            ("!der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
            ("!der_nwk_srctype", "NWK Src Type: Zigbee End Device"),
            ("!der_nwk_srctype", "NWK Src Type: Zigbee Coordinator"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-31.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("!nwk_cmd_payloadlength", 5),
            ("!nwk_cmd_payloadlength", 9),
            ("!nwk_cmd_payloadlength", 1),
            ("!nwk_cmd_payloadlength", 7),
            ("!nwk_cmd_payloadlength", 15),
            ("!nwk_cmd_payloadlength", 23),
            ("der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-32.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("!nwk_cmd_payloadlength", 5),
            ("!nwk_cmd_payloadlength", 9),
            ("!nwk_cmd_payloadlength", 1),
            ("!nwk_cmd_payloadlength", 7),
            ("!nwk_cmd_payloadlength", 15),
            ("!nwk_cmd_payloadlength", 23),
            ("!der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
            ("der_nwk_srctype", "NWK Src Type: Zigbee Router"),
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-33.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("!nwk_cmd_id", None),
            ("!nwk_cmd_payloadlength", 12),
            ("!nwk_cmd_payloadlength", 2),
            ("!nwk_cmd_payloadlength", 3),
            ("!der_nwk_dsttype", "NWK Dst Type: All routers and coordinator"),
            ("!nwk_cmd_payloadlength", 5),
            ("!nwk_cmd_payloadlength", 9),
            ("!nwk_cmd_payloadlength", 1),
            ("!nwk_cmd_payloadlength", 7),
            ("!nwk_cmd_payloadlength", 15),
            ("!nwk_cmd_payloadlength", 23),
            ("!der_nwk_dsttype", "NWK Dst Type: Zigbee Router"),
            ("!der_nwk_srctype", "NWK Src Type: Zigbee Router"),
        ),
    ),
]


def worker(db_filepath, out_dirpath, task_index, task_lock):
    # Connect to the provided database
    config.db.connect(db_filepath)

    while True:
        with task_lock:
            # Get the next task
            if task_index.value < len(CONDITION_MATCHES):
                condition_match = CONDITION_MATCHES[task_index.value]
                task_index.value += 1
            else:
                break

        # Derive the path of the output file, the varying columns,
        # and the matching conditions
        out_filepath = os.path.join(out_dirpath, condition_match[0])
        var_columns = condition_match[1]
        conditions = condition_match[2]

        # Compute the distinct values of the varying columns
        var_values = config.db.fetch_values(
            var_columns,
            conditions,
            True)
        var_values.sort(key=config.custom_sorter)

        # Compute the matching frequency for each set of conditions
        results = []
        for var_value in var_values:
            var_conditions = list(conditions)
            for i in range(len(var_value)):
                var_conditions.append((var_columns[i], var_value[i]))
            matches = config.db.matching_frequency(var_conditions)
            results.append((var_value, matches))

        # Write the matching frequencies in the output file
        config.fs.write_tsv(results, out_filepath)

    # Disconnect from the provided database
    config.db.disconnect()


def matching_frequencies(db_filepath, out_dirpath, num_workers):
    """Compute the matching frequency of certain conditions."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Determine the number of processes that will be used
    if num_workers is None:
        if hasattr(os, "sched_getaffinity"):
            num_workers = len(os.sched_getaffinity(0))
        else:
            num_workers = mp.cpu_count()
    if num_workers < 1:
        num_workers = 1
    logging.info("Computing the matching frequency "
                 "of {} conditions using {} workers..."
                 "".format(len(CONDITION_MATCHES), num_workers))

    # Create variables that will be shared by the processes
    task_index = mp.Value("L", 0, lock=False)
    task_lock = mp.Lock()

    # Start the processes
    processes = []
    for _ in range(num_workers):
        p = mp.Process(target=worker,
                       args=(db_filepath, out_dirpath, task_index, task_lock))
        p.start()
        processes.append(p)

    # Make sure that all processes terminated
    for p in processes:
        p.join()
    logging.info("All {} workers completed their tasks".format(num_workers))
