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

ZIGBEE_IGNORED_COLUMNS = {
    "pkt_num",
    "pkt_time",
    "phy_payload",
    "mac_show",
    "mac_fcs",
    "mac_seqnum",
    "nwk_seqnum",
    "nwk_aux_framecounter",
    "nwk_aux_decpayload",
    "nwk_aux_decshow",
    "aps_counter",
    "aps_aux_framecounter",
    "aps_aux_decpayload",
    "aps_aux_decshow",
    "aps_tunnel_counter",
    "zdp_seqnum",
    "zcl_seqnum",
}


THREAD_IGNORED_COLUMNS = {
    "pkt_num",
    "pkt_time",
    "phy_payload",
    "mac_show",
    "mac_fcs",
    "mac_seqnum",
    "mac_aux_framecounter",
    "mac_aux_decpayload",
    "mac_aux_decshow",
    "thr_firstfrag_datagramtag",
    "thr_firstfrag_payload",
    "thr_subseqfrag_datagramtag",
    "thr_subseqfrag_payload",
    "thr_nhcext_data",
    "thr_decompicmpv6",
    "thr_nhcudp_checksum",
    "thr_decompudp_checksum",
    "thr_decompudp_payload",
    "mle_aux_framecounter",
    "mle_aux_decpayload",
    "mle_aux_decshow",
    "mle_cmd_payload",
}


ZIGBEE_COLUMN_GROUPS = [
    (
        "security-frequency.tsv",
        "mac_security",
        "nwk_security",
        "aps_security",
    ),
    (
        "keytype-frequency.tsv",
        "nwk_aux_keytype",
        "aps_aux_keytype",
    ),
    (
        "frametype-frequency.tsv",
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "frametype_cmdid-frequency.tsv",
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "profileid_clusterid-frequency.tsv",
        "aps_profile_id",
        "aps_cluster_id",
    ),
    (
        "nwkcmdid_addrtype-frequency.tsv",
        "nwk_cmd_id",
        "der_nwk_dsttype",
        "der_nwk_srctype",
    ),
]


THREAD_COLUMN_GROUPS = [
    (
        "security-frequency.tsv",
        "mac_security",
        "mle_secsuite",
    ),
    (
        "keyidmode-frequency.tsv",
        "mac_aux_keyidmode",
        "mle_aux_keyidmode",
    ),
    (
        "frametype_cmdid-frequency.tsv",
        "mac_frametype",
        "mac_cmd_id",
        "mle_cmd_type",
    ),
    (
        "sport_dport-frequency.tsv",
        "thr_decompudp_sport",
        "thr_decompudp_dport",
    ),
]


ZIGBEE_COLUMN_MATCHES = [
    (
        "phy_length--frametype.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "phy_length--frametype_cmdid.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "phy_length--nwk_cmd_id.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--phy_length.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "phy_length",
    ),
    (
        "nwk_radius--frametype.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "nwk_radius--frametype_cmdid.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "nwk_radius--nwk_cmd_id.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--nwk_radius.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_radius",
    ),
    (
        "mac_framepending--frametype.tsv",
        (
            "mac_framepending",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "mac_framepending--frametype_cmdid.tsv",
        (
            "mac_framepending",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "mac_framepending--nwk_cmd_id.tsv",
        (
            "mac_framepending",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--mac_framepending.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "mac_framepending",
    ),
    (
        "mac_ackreq--frametype.tsv",
        (
            "mac_ackreq",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "mac_ackreq--frametype_cmdid.tsv",
        (
            "mac_ackreq",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "mac_ackreq--nwk_cmd_id.tsv",
        (
            "mac_ackreq",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--mac_ackreq.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "mac_ackreq",
    ),
    (
        "mac_dstaddrmode--frametype.tsv",
        (
            "mac_dstaddrmode",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "mac_dstaddrmode--frametype_cmdid.tsv",
        (
            "mac_dstaddrmode",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "mac_dstaddrmode--nwk_cmd_id.tsv",
        (
            "mac_dstaddrmode",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--mac_dstaddrmode.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "mac_dstaddrmode",
    ),
    (
        "mac_srcaddrmode--frametype.tsv",
        (
            "mac_srcaddrmode",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "mac_srcaddrmode--frametype_cmdid.tsv",
        (
            "mac_srcaddrmode",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "mac_srcaddrmode--nwk_cmd_id.tsv",
        (
            "mac_srcaddrmode",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--mac_srcaddrmode.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "mac_srcaddrmode",
    ),
    (
        "nwk_srcroute--frametype.tsv",
        (
            "nwk_srcroute",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "nwk_srcroute--frametype_cmdid.tsv",
        (
            "nwk_srcroute",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "nwk_srcroute--nwk_cmd_id.tsv",
        (
            "nwk_srcroute",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--nwk_srcroute.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_srcroute",
    ),
    (
        "nwk_extendeddst--frametype.tsv",
        (
            "nwk_extendeddst",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "nwk_extendeddst--frametype_cmdid.tsv",
        (
            "nwk_extendeddst",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "nwk_extendeddst--nwk_cmd_id.tsv",
        (
            "nwk_extendeddst",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--nwk_extendeddst.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_extendeddst",
    ),
    (
        "nwk_extendedsrc--frametype.tsv",
        (
            "nwk_extendedsrc",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "nwk_extendedsrc--frametype_cmdid.tsv",
        (
            "nwk_extendedsrc",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "nwk_extendedsrc--nwk_cmd_id.tsv",
        (
            "nwk_extendedsrc",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--nwk_extendedsrc.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_extendedsrc",
    ),
    (
        "nwk_security--nwk_cmd_id.tsv",
        (
            "nwk_security",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--nwk_security.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_security",
    ),
    (
        "aps_ackreq--frametype.tsv",
        (
            "aps_ackreq",
        ),
        (
            ("error_msg", None),
            ("!aps_frametype", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "aps_ackreq--frametype_cmdid.tsv",
        (
            "aps_ackreq",
        ),
        (
            ("error_msg", None),
            ("!aps_frametype", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "aps_aux_keytype--frametype.tsv",
        (
            "aps_aux_keytype",
        ),
        (
            ("error_msg", None),
            ("aps_security", "0b1: APS Security Enabled"),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "aps_aux_keytype--frametype_cmdid.tsv",
        (
            "aps_aux_keytype",
        ),
        (
            ("error_msg", None),
            ("aps_security", "0b1: APS Security Enabled"),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "aps_aux_extnonce--frametype.tsv",
        (
            "aps_aux_extnonce",
        ),
        (
            ("error_msg", None),
            ("aps_security", "0b1: APS Security Enabled"),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "aps_aux_extnonce--frametype_cmdid.tsv",
        (
            "aps_aux_extnonce",
        ),
        (
            ("error_msg", None),
            ("aps_security", "0b1: APS Security Enabled"),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "security--frametype.tsv",
        (
            "mac_security",
            "nwk_security",
            "aps_security",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "security--frametype_cmdid.tsv",
        (
            "mac_security",
            "nwk_security",
            "aps_security",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "srcpanid--mac_frametype_cmdid.tsv",
        (
            "mac_srcpanid",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
    ),
    (
        "mac_frametype_cmdid--addrmode.tsv",
        (
            "mac_frametype",
            "mac_cmd_id",
        ),
        (
            ("error_msg", None),
        ),
        "mac_dstaddrmode",
        "mac_srcaddrmode",
    ),
    (
        "nwk_frametype_cmdid--addrmode.tsv",
        (
            "nwk_frametype",
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "nwk_extendeddst",
        "nwk_extendedsrc",
    ),
    (
        "nwk_srcshortaddr--nwk_cmdid.tsv",
        (
            "nwk_srcshortaddr",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_dstshortaddr--nwk_cmdid.tsv",
        (
            "nwk_dstshortaddr",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_srcextendedaddr--nwk_cmdid.tsv",
        (
            "nwk_srcextendedaddr",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("!nwk_srcextendedaddr", None),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_dstextendedaddr--nwk_cmdid.tsv",
        (
            "nwk_dstextendedaddr",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("!nwk_dstextendedaddr", None),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_srcextendedaddr--aps_frametype_cmdid.tsv",
        (
            "nwk_srcextendedaddr",
        ),
        (
            ("error_msg", None),
            ("!aps_frametype", None),
            ("!nwk_srcextendedaddr", None),
        ),
        "aps_frametype",
        "aps_cmd_id",
    ),
    (
        "nwk_dstextendedaddr--aps_frametype_cmdid.tsv",
        (
            "nwk_dstextendedaddr",
        ),
        (
            ("error_msg", None),
            ("!aps_frametype", None),
            ("!nwk_dstextendedaddr", None),
        ),
        "aps_frametype",
        "aps_cmd_id",
    ),
    (
        "mac_srcextendedaddr--mac_cmd_id.tsv",
        (
            "mac_srcextendedaddr",
        ),
        (
            ("error_msg", None),
            ("!mac_cmd_id", None),
        ),
        "mac_cmd_id",
    ),
    (
        "mac_srcshortaddr--mac_cmd_id.tsv",
        (
            "mac_srcshortaddr",
        ),
        (
            ("error_msg", None),
            ("!mac_cmd_id", None),
        ),
        "mac_cmd_id",
    ),
    (
        "mac_dstextendedaddr--mac_cmd_id.tsv",
        (
            "mac_dstextendedaddr",
        ),
        (
            ("error_msg", None),
            ("!mac_cmd_id", None),
        ),
        "mac_cmd_id",
    ),
    (
        "mac_dstshortaddr--mac_cmd_id.tsv",
        (
            "mac_dstshortaddr",
        ),
        (
            ("error_msg", None),
            ("!mac_cmd_id", None),
        ),
        "mac_cmd_id",
    ),
    (
        "nwk_cmd_payloadlength--nwk_cmd_id.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--nwk_cmd_payloadlength.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_payloadlength",
    ),
    (
        "der_nwk_dsttype--nwk_cmd_id.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--der_nwk_dsttype.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "der_nwk_dsttype",
    ),
    (
        "der_nwk_srctype--nwk_cmd_id.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--der_nwk_srctype.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        "der_nwk_srctype",
    ),
]


THREAD_COLUMN_MATCHES = [
    (
        "phy_length--frametype_cmdid.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "mle_cmd_type",
    ),
    (
        "frametype_cmdid--phy_length.tsv",
        (
            "mac_frametype",
            "mac_cmd_id",
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
        ),
        "phy_length",
    ),
    (
        "thr_decompipv6_hlim--mle_cmd_type.tsv",
        (
            "thr_decompipv6_hlim",
        ),
        (
            ("error_msg", None),
        ),
        "mle_cmd_type",
    ),
    (
        "mle_cmd_type--thr_decompipv6_hlim.tsv",
        (
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
        ),
        "thr_decompipv6_hlim",
    ),
    (
        "mac_framepending--mle_cmd_type.tsv",
        (
            "mac_framepending",
        ),
        (
            ("error_msg", None),
        ),
        "mle_cmd_type",
    ),
    (
        "mle_cmd_type--mac_framepending.tsv",
        (
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
        ),
        "mac_framepending",
    ),
    (
        "mac_ackreq--mle_cmd_type.tsv",
        (
            "mac_ackreq",
        ),
        (
            ("error_msg", None),
        ),
        "mle_cmd_type",
    ),
    (
        "mle_cmd_type--mac_ackreq.tsv",
        (
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
        ),
        "mac_ackreq",
    ),
    (
        "mac_dstaddrmode--mle_cmd_type.tsv",
        (
            "mac_dstaddrmode",
        ),
        (
            ("error_msg", None),
        ),
        "mle_cmd_type",
    ),
    (
        "mle_cmd_type--mac_dstaddrmode.tsv",
        (
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
        ),
        "mac_dstaddrmode",
    ),
    (
        "mac_srcaddrmode--mle_cmd_type.tsv",
        (
            "mac_srcaddrmode",
        ),
        (
            ("error_msg", None),
        ),
        "mle_cmd_type",
    ),
    (
        "mle_cmd_type--mac_srcaddrmode.tsv",
        (
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
        ),
        "mac_srcaddrmode",
    ),
    (
        "security--frametype_cmdid.tsv",
        (
            "mac_security",
            "mle_secsuite",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "mle_cmd_type",
    ),
    (
        "frametype_cmdid--security.tsv",
        (
            "mac_frametype",
            "mac_cmd_id",
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
        ),
        "mac_security",
        "mle_secsuite",
    ),
    (
        "security--mle_cmd_type.tsv",
        (
            "mac_security",
            "mle_secsuite",
        ),
        (
            ("error_msg", None),
            ("!mle_cmd_type", None),
        ),
        "mle_cmd_type",
    ),
    (
        "mle_cmd_type--security.tsv",
        (
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
            ("!mle_cmd_type", None),
        ),
        "mac_security",
        "mle_secsuite",
    ),
    (
        "mle_cmd_type--seclevel.tsv",
        (
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
            ("!mle_cmd_type", None),
        ),
        "mac_aux_seclevel",
        "mle_aux_seclevel",
    ),
    (
        "seclevel--mle_cmd_type.tsv",
        (
            "mac_aux_seclevel",
            "mle_aux_seclevel",
        ),
        (
            ("error_msg", None),
            ("!mle_cmd_type", None),
        ),
        "mle_cmd_type",
    ),
    (
        "srcpanid--frametype_cmdid.tsv",
        (
            "mac_srcpanid",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "mle_cmd_type",
    ),
    (
        "frametype_cmdid--srcpanid.tsv",
        (
            "mac_frametype",
            "mac_cmd_id",
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
        ),
        "mac_srcpanid",
    ),
    (
        "dstpanid--frametype_cmdid.tsv",
        (
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "mle_cmd_type",
    ),
    (
        "frametype_cmdid--dstpanid.tsv",
        (
            "mac_frametype",
            "mac_cmd_id",
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
        ),
        "mac_dstpanid",
    ),
    (
        "addrmode--frametype_cmdid.tsv",
        (
            "mac_dstaddrmode",
            "mac_srcaddrmode",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "mle_cmd_type",
    ),
    (
        "frametype_cmdid--addrmode.tsv",
        (
            "mac_frametype",
            "mac_cmd_id",
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
        ),
        "mac_dstaddrmode",
        "mac_srcaddrmode",
    ),
    (
        "mle_cmd_payloadlength--mle_cmd_type.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
        ),
        "mle_cmd_type",
    ),
    (
        "mle_cmd_type--mle_cmd_payloadlength.tsv",
        (
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
        ),
        "mle_cmd_payloadlength",
    ),
    (
        "der_mac_dsttype--mle_cmd_type.tsv",
        (
            "der_mac_dsttype",
        ),
        (
            ("error_msg", None),
        ),
        "mle_cmd_type",
    ),
    (
        "mle_cmd_type--der_mac_dsttype.tsv",
        (
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
        ),
        "der_mac_dsttype",
    ),
    (
        "der_mac_srctype--mle_cmd_type.tsv",
        (
            "der_mac_srctype",
        ),
        (
            ("error_msg", None),
        ),
        "mle_cmd_type",
    ),
    (
        "mle_cmd_type--der_mac_srctype.tsv",
        (
            "mle_cmd_type",
        ),
        (
            ("error_msg", None),
        ),
        "der_mac_srctype",
    ),
]


ZIGBEE_CONDITION_MATCHES = [
    (
        "phy_length--routerequest.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x01: NWK Route Request"),
        ),
    ),
    (
        "phy_length--routereply.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x02: NWK Route Reply"),
        ),
    ),
    (
        "phy_length--networkstatus.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x03: NWK Network Status"),
        ),
    ),
    (
        "phy_length--leave.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x04: NWK Leave"),
        ),
    ),
    (
        "phy_length--routerecord.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x05: NWK Route Record"),
        ),
    ),
    (
        "phy_length--rejoinreq.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x06: NWK Rejoin Request"),
        ),
    ),
    (
        "phy_length--rejoinrsp.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x07: NWK Rejoin Response"),
        ),
    ),
    (
        "phy_length--linkstatus.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x08: NWK Link Status"),
        ),
    ),
    (
        "phy_length--networkreport.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x09: NWK Network Report"),
        ),
    ),
    (
        "phy_length--networkupdate.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0a: NWK Network Update"),
        ),
    ),
    (
        "phy_length--edtimeoutreq.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0b: NWK End Device Timeout Request"),
        ),
    ),
    (
        "phy_length--edtimeoutrsp.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0c: NWK End Device Timeout Response"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--routerequest.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x01: NWK Route Request"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--routereply.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x02: NWK Route Reply"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--networkstatus.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x03: NWK Network Status"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--leave.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x04: NWK Leave"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--routerecord.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x05: NWK Route Record"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--rejoinreq.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x06: NWK Rejoin Request"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--rejoinrsp.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x07: NWK Rejoin Response"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--linkstatus.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x08: NWK Link Status"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--networkreport.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x09: NWK Network Report"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--networkupdate.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0a: NWK Network Update"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--edtimeoutreq.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0b: NWK End Device Timeout Request"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--edtimeoutrsp.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0c: NWK End Device Timeout Response"),
        ),
    ),
    (
        "nwk_radius--routerequest.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x01: NWK Route Request"),
        ),
    ),
    (
        "nwk_radius--routereply.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x02: NWK Route Reply"),
        ),
    ),
    (
        "nwk_radius--networkstatus.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x03: NWK Network Status"),
        ),
    ),
    (
        "nwk_radius--leave.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x04: NWK Leave"),
        ),
    ),
    (
        "nwk_radius--routerecord.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x05: NWK Route Record"),
        ),
    ),
    (
        "nwk_radius--rejoinreq.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x06: NWK Rejoin Request"),
        ),
    ),
    (
        "nwk_radius--rejoinrsp.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x07: NWK Rejoin Response"),
        ),
    ),
    (
        "nwk_radius--linkstatus.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x08: NWK Link Status"),
        ),
    ),
    (
        "nwk_radius--networkreport.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x09: NWK Network Report"),
        ),
    ),
    (
        "nwk_radius--networkupdate.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0a: NWK Network Update"),
        ),
    ),
    (
        "nwk_radius--edtimeoutreq.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0b: NWK End Device Timeout Request"),
        ),
    ),
    (
        "nwk_radius--edtimeoutrsp.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0c: NWK End Device Timeout Response"),
        ),
    ),
    (
        "der_nwk_dsttype--routerequest.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x01: NWK Route Request"),
        ),
    ),
    (
        "der_nwk_dsttype--routereply.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x02: NWK Route Reply"),
        ),
    ),
    (
        "der_nwk_dsttype--networkstatus.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x03: NWK Network Status"),
        ),
    ),
    (
        "der_nwk_dsttype--leave.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x04: NWK Leave"),
        ),
    ),
    (
        "der_nwk_dsttype--routerecord.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x05: NWK Route Record"),
        ),
    ),
    (
        "der_nwk_dsttype--rejoinreq.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x06: NWK Rejoin Request"),
        ),
    ),
    (
        "der_nwk_dsttype--rejoinrsp.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x07: NWK Rejoin Response"),
        ),
    ),
    (
        "der_nwk_dsttype--linkstatus.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x08: NWK Link Status"),
        ),
    ),
    (
        "der_nwk_dsttype--networkreport.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x09: NWK Network Report"),
        ),
    ),
    (
        "der_nwk_dsttype--networkupdate.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0a: NWK Network Update"),
        ),
    ),
    (
        "der_nwk_dsttype--edtimeoutreq.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0b: NWK End Device Timeout Request"),
        ),
    ),
    (
        "der_nwk_dsttype--edtimeoutrsp.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0c: NWK End Device Timeout Response"),
        ),
    ),
    (
        "der_nwk_srctype--routerequest.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x01: NWK Route Request"),
        ),
    ),
    (
        "der_nwk_srctype--routereply.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x02: NWK Route Reply"),
        ),
    ),
    (
        "der_nwk_srctype--networkstatus.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x03: NWK Network Status"),
        ),
    ),
    (
        "der_nwk_srctype--leave.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x04: NWK Leave"),
        ),
    ),
    (
        "der_nwk_srctype--routerecord.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x05: NWK Route Record"),
        ),
    ),
    (
        "der_nwk_srctype--rejoinreq.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x06: NWK Rejoin Request"),
        ),
    ),
    (
        "der_nwk_srctype--rejoinrsp.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x07: NWK Rejoin Response"),
        ),
    ),
    (
        "der_nwk_srctype--linkstatus.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x08: NWK Link Status"),
        ),
    ),
    (
        "der_nwk_srctype--networkreport.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x09: NWK Network Report"),
        ),
    ),
    (
        "der_nwk_srctype--networkupdate.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0a: NWK Network Update"),
        ),
    ),
    (
        "der_nwk_srctype--edtimeoutreq.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0b: NWK End Device Timeout Request"),
        ),
    ),
    (
        "der_nwk_srctype--edtimeoutrsp.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0c: NWK End Device Timeout Response"),
        ),
    ),
    (
        "der_mac_dsttype--datarequest_srcshort.tsv",
        (
            "der_mac_dsttype",
        ),
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x04: MAC Data Request"),
            ("mac_srcaddrmode", "0b10: Short source MAC address")
        ),
    ),
    (
        "der_mac_srctype--datarequest_srcshort.tsv",
        (
            "der_mac_srctype",
        ),
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x04: MAC Data Request"),
            ("mac_srcaddrmode", "0b10: Short source MAC address")
        ),
    ),
    (
        "enc_nwk_cmd--decision-rule-01.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
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


THREAD_CONDITION_MATCHES = [
    (
        "phy_length--linkrequest.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x00: Link Request"),
        ),
    ),
    (
        "phy_length--linkaccept.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x01: Link Accept"),
        ),
    ),
    (
        "phy_length--linkacceptandrequest.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x02: Link Accept and Request"),
        ),
    ),
    (
        "phy_length--linkreject.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x03: Link Reject"),
        ),
    ),
    (
        "phy_length--advertisement.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x04: Advertisement"),
        ),
    ),
    (
        "phy_length--update.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x05: Update"),
        ),
    ),
    (
        "phy_length--updaterequest.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x06: Update Request"),
        ),
    ),
    (
        "phy_length--datarequest.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x07: Data Request"),
        ),
    ),
    (
        "phy_length--dataresponse.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x08: Data Response"),
        ),
    ),
    (
        "phy_length--parentrequest.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x09: Parent Request"),
        ),
    ),
    (
        "phy_length--parentresponse.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0a: Parent Response"),
        ),
    ),
    (
        "phy_length--childidrequest.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0b: Child ID Request"),
        ),
    ),
    (
        "phy_length--childidresponse.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0c: Child ID Response"),
        ),
    ),
    (
        "phy_length--childupdaterequest.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0d: Child Update Request"),
        ),
    ),
    (
        "phy_length--childupdateresponse.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0e: Child Update Response"),
        ),
    ),
    (
        "phy_length--announce.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0f: Announce"),
        ),
    ),
    (
        "phy_length--discoveryrequest.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x10: Discovery Request"),
        ),
    ),
    (
        "phy_length--discoveryresponse.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x11: Discovery Response"),
        ),
    ),
    (
        "mle_cmd_payloadlength--linkrequest.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x00: Link Request"),
        ),
    ),
    (
        "mle_cmd_payloadlength--linkaccept.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x01: Link Accept"),
        ),
    ),
    (
        "mle_cmd_payloadlength--linkacceptandrequest.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x02: Link Accept and Request"),
        ),
    ),
    (
        "mle_cmd_payloadlength--linkreject.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x03: Link Reject"),
        ),
    ),
    (
        "mle_cmd_payloadlength--advertisement.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x04: Advertisement"),
        ),
    ),
    (
        "mle_cmd_payloadlength--update.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x05: Update"),
        ),
    ),
    (
        "mle_cmd_payloadlength--updaterequest.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x06: Update Request"),
        ),
    ),
    (
        "mle_cmd_payloadlength--datarequest.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x07: Data Request"),
        ),
    ),
    (
        "mle_cmd_payloadlength--dataresponse.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x08: Data Response"),
        ),
    ),
    (
        "mle_cmd_payloadlength--parentrequest.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x09: Parent Request"),
        ),
    ),
    (
        "mle_cmd_payloadlength--parentresponse.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0a: Parent Response"),
        ),
    ),
    (
        "mle_cmd_payloadlength--childidrequest.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0b: Child ID Request"),
        ),
    ),
    (
        "mle_cmd_payloadlength--childidresponse.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0c: Child ID Response"),
        ),
    ),
    (
        "mle_cmd_payloadlength--childupdaterequest.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0d: Child Update Request"),
        ),
    ),
    (
        "mle_cmd_payloadlength--childupdateresponse.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0e: Child Update Response"),
        ),
    ),
    (
        "mle_cmd_payloadlength--announce.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0f: Announce"),
        ),
    ),
    (
        "mle_cmd_payloadlength--discoveryrequest.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x10: Discovery Request"),
        ),
    ),
    (
        "mle_cmd_payloadlength--discoveryresponse.tsv",
        (
            "mle_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x11: Discovery Response"),
        ),
    ),
    (
        "thr_fields--mac_data_unsecured.tsv",
        (
            "thr_firstfrag_pattern",
            "thr_subseqfrag_pattern",
            "thr_decompudp_sport",
            "thr_decompudp_dport",
        ),
        (
            ("error_msg", None),
            ("mac_security", "0b0: MAC Security Disabled"),
            ("mac_frametype", "0b001: MAC Data"),
        ),
    ),
    (
        "nhcudp_ports--thr_firstfrag_unsecured.tsv",
        (
            "thr_nhcudp_sport",
            "thr_nhcudp_dport",
        ),
        (
            ("error_msg", None),
            ("mac_security", "0b0: MAC Security Disabled"),
            ("mac_frametype", "0b001: MAC Data"),
            ("!thr_firstfrag_pattern", None),
        ),
    ),
]


ZIGBEE_PACKET_TYPES = [
    (
        "mac_acknowledgment.tsv",
        (
            ("error_msg", None),
            ("mac_frametype", "0b010: MAC Acknowledgment"),
        ),
    ),
    (
        "mac_beacon.tsv",
        (
            ("error_msg", None),
            ("mac_frametype", "0b000: MAC Beacon"),
        ),
    ),
    (
        "mac_assocreq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x01: MAC Association Request"),
        ),
    ),
    (
        "mac_assocrsp.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x02: MAC Association Response"),
        ),
    ),
    (
        "mac_disassoc.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x03: MAC Disassociation Notification"),
        ),
    ),
    (
        "mac_datareq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x04: MAC Data Request"),
        ),
    ),
    (
        "mac_conflictnotif.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x05: MAC PAN ID Conflict Notification"),
        ),
    ),
    (
        "mac_orphannotif.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x06: MAC Orphan Notification"),
        ),
    ),
    (
        "mac_beaconreq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x07: MAC Beacon Request"),
        ),
    ),
    (
        "mac_realign.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x08: MAC Coordinator Realignment"),
        ),
    ),
    (
        "mac_gtsreq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x09: MAC GTS Request"),
        ),
    ),
    (
        "nwk_routerequest.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x01: NWK Route Request"),
        ),
    ),
    (
        "nwk_routereply.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x02: NWK Route Reply"),
        ),
    ),
    (
        "nwk_networkstatus.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x03: NWK Network Status"),
        ),
    ),
    (
        "nwk_leave.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x04: NWK Leave"),
        ),
    ),
    (
        "nwk_routerecord.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x05: NWK Route Record"),
        ),
    ),
    (
        "nwk_rejoinreq.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x06: NWK Rejoin Request"),
        ),
    ),
    (
        "nwk_rejoinrsp.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x07: NWK Rejoin Response"),
        ),
    ),
    (
        "nwk_linkstatus.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x08: NWK Link Status"),
        ),
    ),
    (
        "nwk_networkreport.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x09: NWK Network Report"),
        ),
    ),
    (
        "nwk_networkupdate.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0a: NWK Network Update"),
        ),
    ),
    (
        "nwk_edtimeoutreq.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0b: NWK End Device Timeout Request"),
        ),
    ),
    (
        "nwk_edtimeoutrsp.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0c: NWK End Device Timeout Response"),
        ),
    ),
    (
        "aps_acknowledgment.tsv",
        (
            ("error_msg", None),
            ("aps_frametype", "0b10: APS Acknowledgment"),
        ),
    ),
    (
        "aps_transportkey.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x05: APS Transport Key"),
        ),
    ),
    (
        "aps_updatedevice.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x06: APS Update Device"),
        ),
    ),
    (
        "aps_removedevice.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x07: APS Remove Device"),
        ),
    ),
    (
        "aps_requestkey.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x08: APS Request Key"),
        ),
    ),
    (
        "aps_switchkey.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x09: APS Switch Key"),
        ),
    ),
    (
        "aps_tunnel.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x0e: APS Tunnel"),
        ),
    ),
    (
        "aps_verifykey.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x0f: APS Verify Key"),
        ),
    ),
    (
        "aps_confirmkey.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x10: APS Confirm Key"),
        ),
    ),
    (
        "zdp_activeepreq.tsv",
        (
            ("error_msg", None),
            ("aps_frametype", "0b00: APS Data"),
            ("aps_profile_id", "0x0000: Zigbee Device Profile (ZDP)"),
            ("aps_cluster_id", "0x0005: Active_EP_req"),
        ),
    ),
    (
        "zdp_activeepreq_specialcase.tsv",
        (
            ("error_msg", None),
            ("nwk_srcroute", "0b0: NWK Source Route Omitted"),
            ("aps_frametype", "0b00: APS Data"),
            ("aps_profile_id", "0x0000: Zigbee Device Profile (ZDP)"),
            ("aps_cluster_id", "0x0005: Active_EP_req"),
            ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
        ),
    ),
    (
        "zdp_deviceannce.tsv",
        (
            ("error_msg", None),
            ("aps_frametype", "0b00: APS Data"),
            ("aps_profile_id", "0x0000: Zigbee Device Profile (ZDP)"),
            ("aps_cluster_id", "0x0013: Device_annce"),
        ),
    ),
    (
        "zdp_deviceannce_specialcase.tsv",
        (
            ("error_msg", None),
            ("mac_dstshortaddr", "0xffff"),
            ("nwk_extendedsrc", "0b1: NWK Extended Source Included"),
            ("aps_frametype", "0b00: APS Data"),
            ("aps_profile_id", "0x0000: Zigbee Device Profile (ZDP)"),
            ("aps_cluster_id", "0x0013: Device_annce"),
            ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
        ),
    ),
]


THREAD_PACKET_TYPES = [
    (
        "mac_acknowledgment.tsv",
        (
            ("error_msg", None),
            ("mac_frametype", "0b010: MAC Acknowledgment"),
        ),
    ),
    (
        "mac_beacon.tsv",
        (
            ("error_msg", None),
            ("mac_frametype", "0b000: MAC Beacon"),
        ),
    ),
    (
        "mac_assocreq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x01: MAC Association Request"),
        ),
    ),
    (
        "mac_assocrsp.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x02: MAC Association Response"),
        ),
    ),
    (
        "mac_disassoc.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x03: MAC Disassociation Notification"),
        ),
    ),
    (
        "mac_datareq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x04: MAC Data Request"),
        ),
    ),
    (
        "mac_conflictnotif.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x05: MAC PAN ID Conflict Notification"),
        ),
    ),
    (
        "mac_orphannotif.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x06: MAC Orphan Notification"),
        ),
    ),
    (
        "mac_beaconreq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x07: MAC Beacon Request"),
        ),
    ),
    (
        "mac_realign.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x08: MAC Coordinator Realignment"),
        ),
    ),
    (
        "mac_gtsreq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x09: MAC GTS Request"),
        ),
    ),
    (
        "thr_firstfrag.tsv",
        (
            ("error_msg", None),
            ("!thr_firstfrag_pattern", None),
        ),
    ),
    (
        "thr_firstfrag_unsecured.tsv",
        (
            ("error_msg", None),
            ("!thr_firstfrag_pattern", None),
            ("mac_security", "0b0: MAC Security Disabled"),
        ),
    ),
    (
        "thr_firstfrag_secured.tsv",
        (
            ("error_msg", None),
            ("!thr_firstfrag_pattern", None),
            ("mac_security", "0b1: MAC Security Enabled"),
        ),
    ),
    (
        "thr_subseqfrag.tsv",
        (
            ("error_msg", None),
            ("!thr_subseqfrag_pattern", None),
        ),
    ),
    (
        "thr_subseqfrag_unsecured.tsv",
        (
            ("error_msg", None),
            ("!thr_subseqfrag_pattern", None),
            ("mac_security", "0b0: MAC Security Disabled"),
        ),
    ),
    (
        "thr_subseqfrag_secured.tsv",
        (
            ("error_msg", None),
            ("!thr_subseqfrag_pattern", None),
            ("mac_security", "0b1: MAC Security Enabled"),
        ),
    ),
    (
        "mle_command.tsv",
        (
            ("error_msg", None),
            ("!mle_cmd_type", None),
        ),
    ),
    (
        "mle_linkrequest.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x00: Link Request"),
        ),
    ),
    (
        "mle_linkaccept.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x01: Link Accept"),
        ),
    ),
    (
        "mle_linkacceptandrequest.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x02: Link Accept and Request"),
        ),
    ),
    (
        "mle_linkreject.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x03: Link Reject"),
        ),
    ),
    (
        "mle_advertisement.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x04: Advertisement"),
        ),
    ),
    (
        "mle_update.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x05: Update"),
        ),
    ),
    (
        "mle_updaterequest.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x06: Update Request"),
        ),
    ),
    (
        "mle_datarequest.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x07: Data Request"),
        ),
    ),
    (
        "mle_dataresponse.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x08: Data Response"),
        ),
    ),
    (
        "mle_parentrequest.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x09: Parent Request"),
        ),
    ),
    (
        "mle_parentresponse.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0a: Parent Response"),
        ),
    ),
    (
        "mle_childidrequest.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0b: Child ID Request"),
        ),
    ),
    (
        "mle_childidresponse.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0c: Child ID Response"),
        ),
    ),
    (
        "mle_childupdaterequest.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0d: Child Update Request"),
        ),
    ),
    (
        "mle_childupdateresponse.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0e: Child Update Response"),
        ),
    ),
    (
        "mle_announce.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x0f: Announce"),
        ),
    ),
    (
        "mle_discoveryrequest.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x10: Discovery Request"),
        ),
    ),
    (
        "mle_discoveryresponse.tsv",
        (
            ("error_msg", None),
            ("mle_cmd_type", "0x11: Discovery Response"),
        ),
    ),
]


ZIGBEE_INCLUDED_COLUMNS = {
    "phy_length",
    "mac_framepending",
    "mac_ackreq",
    "mac_panidcomp",
    "mac_dstaddrmode",
    "mac_srcaddrmode",
    "nwk_discroute",
    "nwk_multicast",
    "nwk_srcroute",
    "nwk_extendeddst",
    "nwk_extendedsrc",
    "nwk_edinitiator",
    "nwk_radius",
    "nwk_aux_extnonce",
}


THREAD_INCLUDED_COLUMNS = {
    "phy_length",
    "mac_security",
    "mac_framepending",
    "mac_ackreq",
    "mac_panidcomp",
    "mac_dstaddrmode",
    "mac_frameversion",
    "mac_srcaddrmode",
    "mac_aux_seclevel",
    "mac_aux_keyidmode",
    "thr_mesh_vf",
    "thr_mesh_fd",
    "thr_mesh_hopsleft",
    "thr_mesh_deephopsleft",
    "thr_firstfrag_datagramsize",
    "thr_subseqfrag_datagramsize",
    "thr_iphc_tf",
    "thr_iphc_nh",
    "thr_iphc_hlim",
    "thr_iphc_cid",
    "thr_iphc_sac",
    "thr_iphc_sam",
    "thr_iphc_multicast",
    "thr_iphc_dac",
    "thr_iphc_dam",
    "thr_iphc_sci",
    "thr_iphc_dci",
    "thr_iphc_ecn",
    "thr_iphc_dscp",
    "thr_iphc_fl",
    "thr_iphc_nextheader",
    "thr_iphc_hoplimit",
    "thr_nhcext_id",
    "thr_nhcext_nh",
    "thr_nhcext_nextheader",
    "thr_nhcext_length",
    "thr_nhcudp_cm",
    "thr_nhcudp_pm",
    "thr_decompipv6_src",
    "thr_decompipv6_dst",
    "thr_decompudp_sport",
    "thr_decompudp_dport",
    "mle_secsuite",
    "mle_aux_seclevel",
    "mle_aux_keyidmode",
}


ZIGBEE_CONDITION_SELECTIONS = [
    (
        "packet_types.tsv",
        (
            "MAC Acknowledgment",
            ("error_msg", None),
            ("mac_frametype", "0b010: MAC Acknowledgment"),
        ),
        (
            "MAC Beacon",
            ("error_msg", None),
            ("mac_frametype", "0b000: MAC Beacon"),
        ),
        (
            "MAC Command",
            ("error_msg", None),
            ("mac_frametype", "0b011: MAC Command"),
        ),
        (
            "NWK Command",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        (
            "APS Acknowledgment",
            ("error_msg", None),
            ("aps_frametype", "0b10: APS Acknowledgment"),
        ),
        (
            "APS Command",
            ("error_msg", None),
            ("aps_frametype", "0b01: APS Command"),
        ),
        (
            "ZDP Command",
            ("error_msg", None),
            ("aps_frametype", "0b00: APS Data"),
            ("aps_profile_id", "0x0000: Zigbee Device Profile (ZDP)"),
        ),
        (
            "ZCL Command",
            ("error_msg", None),
            ("aps_frametype", "0b00: APS Data"),
            ("!aps_profile_id", "0x0000: Zigbee Device Profile (ZDP)"),
        ),
    ),
    (
        "encrypted_nwk_commands.tsv",
        (
            "NWK Route Request",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x01: NWK Route Request"),
        ),
        (
            "NWK Route Reply",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x02: NWK Route Reply"),
        ),
        (
            "NWK Network Status",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x03: NWK Network Status"),
        ),
        (
            "NWK Leave",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x04: NWK Leave"),
        ),
        (
            "NWK Route Record",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x05: NWK Route Record"),
        ),
        (
            "NWK Rejoin Request",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x06: NWK Rejoin Request"),
        ),
        (
            "NWK Rejoin Response",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x07: NWK Rejoin Response"),
        ),
        (
            "NWK Link Status",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x08: NWK Link Status"),
        ),
        (
            "NWK Network Report",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x09: NWK Network Report"),
        ),
        (
            "NWK Network Update",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x0a: NWK Network Update"),
        ),
        (
            "NWK End Device Timeout Request",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x0b: NWK End Device Timeout Request"),
        ),
        (
            "NWK End Device Timeout Response",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x0c: NWK End Device Timeout Response"),
        ),
    ),
    (
        "datarequest--srcaddrmode.tsv",
        (
            "MAC Data Request with short source address",
            ("error_msg", None),
            ("mac_cmd_id", "0x04: MAC Data Request"),
            ("mac_srcaddrmode", "0b10: Short source MAC address"),
        ),
        (
            "MAC Data Request with extended source address",
            ("error_msg", None),
            ("mac_cmd_id", "0x04: MAC Data Request"),
            ("mac_srcaddrmode", "0b11: Extended source MAC address"),
        ),
    ),
]


THREAD_CONDITION_SELECTIONS = [
    (
        "mac_frametypes.tsv",
        (
            "MAC Acknowledgment",
            ("error_msg", None),
            ("mac_frametype", "0b010: MAC Acknowledgment"),
        ),
        (
            "MAC Beacon",
            ("error_msg", None),
            ("mac_frametype", "0b000: MAC Beacon"),
        ),
        (
            "MAC Command",
            ("error_msg", None),
            ("mac_frametype", "0b011: MAC Command"),
        ),
        (
            "MAC Data",
            ("error_msg", None),
            ("mac_frametype", "0b001: MAC Data"),
        ),
    ),
    (
        "datarequest--srcaddrmode.tsv",
        (
            "MAC Data Request with short source address",
            ("error_msg", None),
            ("mac_cmd_id", "0x04: MAC Data Request"),
            ("mac_srcaddrmode", "0b10: Short source MAC address"),
        ),
        (
            "MAC Data Request with extended source address",
            ("error_msg", None),
            ("mac_cmd_id", "0x04: MAC Data Request"),
            ("mac_srcaddrmode", "0b11: Extended source MAC address"),
        ),
    ),
]
