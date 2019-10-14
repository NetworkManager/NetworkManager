// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2008 - 2013 Red Hat, Inc.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#define IFCFG_TAG "ifcfg-"
#define KEYS_TAG "keys-"
#define ROUTE_TAG "route-"
#define RULE_TAG "rule-"
#define ROUTE6_TAG "route6-"
#define RULE6_TAG "rule6-"

#define BAK_TAG ".bak"
#define TILDE_TAG "~"
#define ORIG_TAG ".orig"
#define REJ_TAG ".rej"
#define RPMNEW_TAG ".rpmnew"
#define AUGNEW_TAG ".augnew"
#define AUGTMP_TAG ".augtmp"

#define IFCFG_DIR SYSCONFDIR "/sysconfig/network-scripts"

#define TYPE_ETHERNET   "Ethernet"
#define TYPE_WIRELESS   "Wireless"
#define TYPE_INFINIBAND "InfiniBand"
#define TYPE_BRIDGE     "Bridge"
#define TYPE_BOND       "Bond"
#define TYPE_VLAN       "Vlan"
#define TYPE_TEAM       "Team"
#define TYPE_TEAM_PORT  "TeamPort"

#define SECRET_FLAG_AGENT "user"
#define SECRET_FLAG_NOT_SAVED "ask"
#define SECRET_FLAG_NOT_REQUIRED "unused"

/* DCB key names */
#define KEY_DCB_APP_FCOE_ENABLE     "DCB_APP_FCOE_ENABLE"
#define KEY_DCB_APP_FCOE_ADVERTISE  "DCB_APP_FCOE_ADVERTISE"
#define KEY_DCB_APP_FCOE_WILLING    "DCB_APP_FCOE_WILLING"
#define KEY_DCB_APP_FCOE_MODE       "DCB_APP_FCOE_MODE"
#define KEY_DCB_APP_ISCSI_ENABLE    "DCB_APP_ISCSI_ENABLE"
#define KEY_DCB_APP_ISCSI_ADVERTISE "DCB_APP_ISCSI_ADVERTISE"
#define KEY_DCB_APP_ISCSI_WILLING   "DCB_APP_ISCSI_WILLING"
#define KEY_DCB_APP_FIP_ENABLE      "DCB_APP_FIP_ENABLE"
#define KEY_DCB_APP_FIP_ADVERTISE   "DCB_APP_FIP_ADVERTISE"
#define KEY_DCB_APP_FIP_WILLING     "DCB_APP_FIP_WILLING"
#define KEY_DCB_PFC_ENABLE          "DCB_PFC_ENABLE"
#define KEY_DCB_PFC_ADVERTISE       "DCB_PFC_ADVERTISE"
#define KEY_DCB_PFC_WILLING         "DCB_PFC_WILLING"
#define KEY_DCB_PFC_UP              "DCB_PFC_UP"
#define KEY_DCB_PG_ENABLE           "DCB_PG_ENABLE"
#define KEY_DCB_PG_ADVERTISE        "DCB_PG_ADVERTISE"
#define KEY_DCB_PG_WILLING          "DCB_PG_WILLING"
#define KEY_DCB_PG_ID               "DCB_PG_ID"
#define KEY_DCB_PG_PCT              "DCB_PG_PCT"
#define KEY_DCB_PG_UPPCT            "DCB_PG_UPPCT"
#define KEY_DCB_PG_STRICT           "DCB_PG_STRICT"
#define KEY_DCB_PG_UP2TC            "DCB_PG_UP2TC"

#endif  /* __COMMON_H__ */

