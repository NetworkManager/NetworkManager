/* nmcli - command-line tool to control NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2010 - 2015 Red Hat, Inc.
 */

#include "config.h"

#include <stdlib.h>
#include <arpa/inet.h>

#include <glib.h>
#include <glib/gi18n.h>

#include "utils.h"
#include "common.h"
#include "settings.h"
#include "nm-glib-compat.h"
#include "nm-macros-internal.h"

/* Forward declarations */
static char *wep_key_type_to_string (NMWepKeyType type);

typedef enum {
	NMC_PROPERTY_GET_PRETTY,
	NMC_PROPERTY_GET_PARSABLE,
} NmcPropertyGetType;

/* Helper macro to define fields */
#define SETTING_FIELD(setting, width) { setting, N_(setting), width, NULL, FALSE, FALSE, 0 }

/* Available fields for NM_SETTING_CONNECTION_SETTING_NAME */
NmcOutputField nmc_fields_setting_connection[] = {
	SETTING_FIELD ("name",  15),                                     /* 0 */
	SETTING_FIELD (NM_SETTING_CONNECTION_ID, 25),                    /* 1 */
	SETTING_FIELD (NM_SETTING_CONNECTION_UUID, 38),                  /* 2 */
	SETTING_FIELD (NM_SETTING_CONNECTION_INTERFACE_NAME, 20),        /* 3 */
	SETTING_FIELD (NM_SETTING_CONNECTION_TYPE, 17),                  /* 4 */
	SETTING_FIELD (NM_SETTING_CONNECTION_AUTOCONNECT, 13),           /* 5 */
	SETTING_FIELD (NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY, 10),  /* 6 */
	SETTING_FIELD (NM_SETTING_CONNECTION_TIMESTAMP, 10),             /* 7 */
	SETTING_FIELD (NM_SETTING_CONNECTION_READ_ONLY, 10),             /* 8 */
	SETTING_FIELD (NM_SETTING_CONNECTION_PERMISSIONS, 30),           /* 9 */
	SETTING_FIELD (NM_SETTING_CONNECTION_ZONE, 10),                  /* 10 */
	SETTING_FIELD (NM_SETTING_CONNECTION_MASTER, 20),                /* 11 */
	SETTING_FIELD (NM_SETTING_CONNECTION_SLAVE_TYPE, 20),            /* 12 */
	SETTING_FIELD (NM_SETTING_CONNECTION_SECONDARIES, 40),           /* 13 */
	SETTING_FIELD (NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT, 30),  /* 14 */
	SETTING_FIELD (NM_SETTING_CONNECTION_METERED, 10),               /* 15 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_CONNECTION_ALL     "name"","\
                                              NM_SETTING_CONNECTION_ID","\
                                              NM_SETTING_CONNECTION_UUID","\
                                              NM_SETTING_CONNECTION_INTERFACE_NAME","\
                                              NM_SETTING_CONNECTION_TYPE","\
                                              NM_SETTING_CONNECTION_AUTOCONNECT","\
                                              NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY","\
                                              NM_SETTING_CONNECTION_TIMESTAMP","\
                                              NM_SETTING_CONNECTION_READ_ONLY","\
                                              NM_SETTING_CONNECTION_PERMISSIONS","\
                                              NM_SETTING_CONNECTION_ZONE","\
                                              NM_SETTING_CONNECTION_MASTER","\
                                              NM_SETTING_CONNECTION_SLAVE_TYPE","\
                                              NM_SETTING_CONNECTION_SECONDARIES","\
                                              NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT","\
                                              NM_SETTING_CONNECTION_METERED
#define NMC_FIELDS_SETTING_CONNECTION_COMMON  NMC_FIELDS_SETTING_CONNECTION_ALL

/* Available fields for NM_SETTING_WIRED_SETTING_NAME */
NmcOutputField nmc_fields_setting_wired[] = {
	SETTING_FIELD ("name",  17),                                  /* 0 */
	SETTING_FIELD (NM_SETTING_WIRED_PORT, 8),                     /* 1 */
	SETTING_FIELD (NM_SETTING_WIRED_SPEED, 10),                   /* 2 */
	SETTING_FIELD (NM_SETTING_WIRED_DUPLEX, 10),                  /* 3 */
	SETTING_FIELD (NM_SETTING_WIRED_AUTO_NEGOTIATE, 15),          /* 4 */
	SETTING_FIELD (NM_SETTING_WIRED_MAC_ADDRESS, 19),             /* 5 */
	SETTING_FIELD (NM_SETTING_WIRED_CLONED_MAC_ADDRESS, 19),      /* 6 */
	SETTING_FIELD (NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST, 39),   /* 7 */
	SETTING_FIELD (NM_SETTING_WIRED_MTU, 6),                      /* 8 */
	SETTING_FIELD (NM_SETTING_WIRED_S390_SUBCHANNELS, 20),        /* 9 */
	SETTING_FIELD (NM_SETTING_WIRED_S390_NETTYPE, 15),            /* 10 */
	SETTING_FIELD (NM_SETTING_WIRED_S390_OPTIONS, 20),            /* 11 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_WIRED_ALL     "name"","\
                                         NM_SETTING_WIRED_PORT","\
                                         NM_SETTING_WIRED_SPEED","\
                                         NM_SETTING_WIRED_DUPLEX","\
                                         NM_SETTING_WIRED_AUTO_NEGOTIATE","\
                                         NM_SETTING_WIRED_MAC_ADDRESS","\
                                         NM_SETTING_WIRED_CLONED_MAC_ADDRESS","\
                                         NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST","\
                                         NM_SETTING_WIRED_MTU","\
                                         NM_SETTING_WIRED_S390_SUBCHANNELS","\
                                         NM_SETTING_WIRED_S390_NETTYPE","\
                                         NM_SETTING_WIRED_S390_OPTIONS
#define NMC_FIELDS_SETTING_WIRED_COMMON  NMC_FIELDS_SETTING_WIRED_ALL

/* Available fields for NM_SETTING_802_1X_SETTING_NAME */
NmcOutputField nmc_fields_setting_8021X[] = {
	SETTING_FIELD ("name", 10),                                              /* 0 */
	SETTING_FIELD (NM_SETTING_802_1X_EAP, 10),                               /* 1 */
	SETTING_FIELD (NM_SETTING_802_1X_IDENTITY, 15),                          /* 2 */
	SETTING_FIELD (NM_SETTING_802_1X_ANONYMOUS_IDENTITY, 15),                /* 3 */
	SETTING_FIELD (NM_SETTING_802_1X_PAC_FILE, 15),                          /* 4 */
	SETTING_FIELD (NM_SETTING_802_1X_CA_CERT, 10),                           /* 5 */
	SETTING_FIELD (NM_SETTING_802_1X_CA_PATH, 10),                           /* 6 */
	SETTING_FIELD (NM_SETTING_802_1X_SUBJECT_MATCH, 10),                     /* 7 */
	SETTING_FIELD (NM_SETTING_802_1X_ALTSUBJECT_MATCHES, 10),                /* 8 */
	SETTING_FIELD (NM_SETTING_802_1X_CLIENT_CERT, 10),                       /* 9 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE1_PEAPVER, 10),                    /* 10 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE1_PEAPLABEL, 10),                  /* 11 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING, 10),          /* 12 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_AUTH, 10),                       /* 13 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_AUTHEAP, 10),                    /* 14 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_CA_CERT, 20),                    /* 15 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_CA_PATH, 20),                    /* 16 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_SUBJECT_MATCH, 10),              /* 17 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_ALTSUBJECT_MATCHES, 10),         /* 18 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_CLIENT_CERT, 20),                /* 19 */
	SETTING_FIELD (NM_SETTING_802_1X_PASSWORD, 10),                          /* 20 */
	SETTING_FIELD (NM_SETTING_802_1X_PASSWORD_FLAGS, 20),                    /* 21 */
	SETTING_FIELD (NM_SETTING_802_1X_PASSWORD_RAW, 20),                      /* 22 */
	SETTING_FIELD (NM_SETTING_802_1X_PASSWORD_RAW_FLAGS, 20),                /* 23 */
	SETTING_FIELD (NM_SETTING_802_1X_PRIVATE_KEY, 15),                       /* 24 */
	SETTING_FIELD (NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD, 20),              /* 25 */
	SETTING_FIELD (NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS, 20),        /* 26 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY, 20),                /* 27 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD, 20),       /* 28 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS, 20), /* 29 */
	SETTING_FIELD (NM_SETTING_802_1X_PIN, 8),                                /* 30 */
	SETTING_FIELD (NM_SETTING_802_1X_PIN_FLAGS, 20),                         /* 31 */
	SETTING_FIELD (NM_SETTING_802_1X_SYSTEM_CA_CERTS, 17),                   /* 32 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_802_1X_ALL     "name"","\
                                          NM_SETTING_802_1X_EAP","\
                                          NM_SETTING_802_1X_IDENTITY","\
                                          NM_SETTING_802_1X_ANONYMOUS_IDENTITY","\
                                          NM_SETTING_802_1X_PAC_FILE","\
                                          NM_SETTING_802_1X_CA_CERT","\
                                          NM_SETTING_802_1X_CA_PATH","\
                                          NM_SETTING_802_1X_SUBJECT_MATCH","\
                                          NM_SETTING_802_1X_ALTSUBJECT_MATCHES","\
                                          NM_SETTING_802_1X_CLIENT_CERT","\
                                          NM_SETTING_802_1X_PHASE1_PEAPVER","\
                                          NM_SETTING_802_1X_PHASE1_PEAPLABEL","\
                                          NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING","\
                                          NM_SETTING_802_1X_PHASE2_AUTH","\
                                          NM_SETTING_802_1X_PHASE2_AUTHEAP","\
                                          NM_SETTING_802_1X_PHASE2_CA_CERT","\
                                          NM_SETTING_802_1X_PHASE2_CA_PATH","\
                                          NM_SETTING_802_1X_PHASE2_SUBJECT_MATCH","\
                                          NM_SETTING_802_1X_PHASE2_ALTSUBJECT_MATCHES","\
                                          NM_SETTING_802_1X_PHASE2_CLIENT_CERT","\
                                          NM_SETTING_802_1X_PASSWORD","\
                                          NM_SETTING_802_1X_PASSWORD_FLAGS","\
                                          NM_SETTING_802_1X_PASSWORD_RAW","\
                                          NM_SETTING_802_1X_PASSWORD_RAW_FLAGS","\
                                          NM_SETTING_802_1X_PRIVATE_KEY","\
                                          NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD","\
                                          NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS","\
                                          NM_SETTING_802_1X_PHASE2_PRIVATE_KEY","\
                                          NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD","\
                                          NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS","\
                                          NM_SETTING_802_1X_PIN","\
                                          NM_SETTING_802_1X_PIN_FLAGS","\
                                          NM_SETTING_802_1X_SYSTEM_CA_CERTS
#define NMC_FIELDS_SETTING_802_1X_COMMON  NMC_FIELDS_SETTING_802_1X_ALL

/* Available fields for NM_SETTING_WIRELESS_SETTING_NAME */
NmcOutputField nmc_fields_setting_wireless[] = {
	SETTING_FIELD ("name", 17),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SSID, 34),                      /* 1 */
	SETTING_FIELD (NM_SETTING_WIRELESS_MODE, 15),                      /* 2 */
	SETTING_FIELD (NM_SETTING_WIRELESS_BAND, 10),                      /* 3 */
	SETTING_FIELD (NM_SETTING_WIRELESS_CHANNEL, 10),                   /* 4 */
	SETTING_FIELD (NM_SETTING_WIRELESS_BSSID, 19),                     /* 5 */
	SETTING_FIELD (NM_SETTING_WIRELESS_RATE, 10),                      /* 6 */
	SETTING_FIELD (NM_SETTING_WIRELESS_TX_POWER, 10),                  /* 7 */
	SETTING_FIELD (NM_SETTING_WIRELESS_MAC_ADDRESS, 19),               /* 8 */
	SETTING_FIELD (NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, 19),        /* 9 */
	SETTING_FIELD (NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST, 39),     /* 10 */
	SETTING_FIELD (NM_SETTING_WIRELESS_MTU, 6),                        /* 11 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SEEN_BSSIDS, 35),               /* 12 */
	SETTING_FIELD (NM_SETTING_WIRELESS_HIDDEN, 10),                    /* 13 */
	SETTING_FIELD (NM_SETTING_WIRELESS_POWERSAVE, 10),                 /* 14 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_WIRELESS_ALL     "name"","\
                                            NM_SETTING_WIRELESS_SSID","\
                                            NM_SETTING_WIRELESS_MODE","\
                                            NM_SETTING_WIRELESS_BAND","\
                                            NM_SETTING_WIRELESS_CHANNEL","\
                                            NM_SETTING_WIRELESS_BSSID","\
                                            NM_SETTING_WIRELESS_RATE","\
                                            NM_SETTING_WIRELESS_TX_POWER","\
                                            NM_SETTING_WIRELESS_MAC_ADDRESS","\
                                            NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS","\
                                            NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST","\
                                            NM_SETTING_WIRELESS_MTU","\
                                            NM_SETTING_WIRELESS_SEEN_BSSIDS","\
                                            NM_SETTING_WIRELESS_HIDDEN"," \
                                            NM_SETTING_WIRELESS_POWERSAVE
#define NMC_FIELDS_SETTING_WIRELESS_COMMON  NMC_FIELDS_SETTING_WIRELESS_ALL

/* Available fields for NM_SETTING_WIRELESS_SECURITY_SETTING_NAME */
NmcOutputField nmc_fields_setting_wireless_security[] = {
	SETTING_FIELD ("name", 25),                                           /* 0 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, 10),            /* 1 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, 15),       /* 2 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, 10),            /* 3 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_PROTO, 10),               /* 4 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_PAIRWISE, 10),            /* 5 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_GROUP, 10),               /* 6 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, 15),       /* 7 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_WEP_KEY0, 10),            /* 8 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_WEP_KEY1, 10),            /* 9 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_WEP_KEY2, 10),            /* 10 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_WEP_KEY3, 10),            /* 11 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS, 20),       /* 12 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, 15),        /* 13 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_PSK, 6),                  /* 14 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS, 20),           /* 15 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD, 15),       /* 16 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS, 20), /* 17 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_WIRELESS_SECURITY_ALL     "name"","\
                                                     NM_SETTING_WIRELESS_SECURITY_KEY_MGMT","\
                                                     NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX","\
                                                     NM_SETTING_WIRELESS_SECURITY_AUTH_ALG","\
                                                     NM_SETTING_WIRELESS_SECURITY_PROTO","\
                                                     NM_SETTING_WIRELESS_SECURITY_PAIRWISE","\
                                                     NM_SETTING_WIRELESS_SECURITY_GROUP","\
                                                     NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME","\
                                                     NM_SETTING_WIRELESS_SECURITY_WEP_KEY0","\
                                                     NM_SETTING_WIRELESS_SECURITY_WEP_KEY1","\
                                                     NM_SETTING_WIRELESS_SECURITY_WEP_KEY2","\
                                                     NM_SETTING_WIRELESS_SECURITY_WEP_KEY3","\
                                                     NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS","\
                                                     NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE","\
                                                     NM_SETTING_WIRELESS_SECURITY_PSK","\
                                                     NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS","\
                                                     NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD","\
                                                     NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS
#define NMC_FIELDS_SETTING_WIRELESS_SECURITY_COMMON  NMC_FIELDS_SETTING_WIRELESS_SECURITY_ALL

/* Available fields for NM_SETTING_IP4_CONFIG_SETTING_NAME */
NmcOutputField nmc_fields_setting_ip4_config[] = {
	SETTING_FIELD ("name", 8),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_METHOD, 10),                  /* 1 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_DNS, 20),                     /* 2 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_DNS_SEARCH, 15),              /* 3 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_DNS_OPTIONS, 15),             /* 4 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_ADDRESSES, 20),               /* 5 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_GATEWAY, 20),                 /* 6 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_ROUTES, 20),                  /* 7 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_ROUTE_METRIC, 15),            /* 8 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, 19),      /* 9 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, 16),         /* 10 */
	SETTING_FIELD (NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID, 15),         /* 11 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, 19),      /* 12 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, 14),           /* 13 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_NEVER_DEFAULT, 15),           /* 14 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_MAY_FAIL, 12),                /* 15 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_IP4_CONFIG_ALL     "name"","\
                                              NM_SETTING_IP_CONFIG_METHOD","\
                                              NM_SETTING_IP_CONFIG_DNS","\
                                              NM_SETTING_IP_CONFIG_DNS_SEARCH","\
                                              NM_SETTING_IP_CONFIG_DNS_OPTIONS","\
                                              NM_SETTING_IP_CONFIG_ADDRESSES","\
                                              NM_SETTING_IP_CONFIG_GATEWAY","\
                                              NM_SETTING_IP_CONFIG_ROUTES","\
                                              NM_SETTING_IP_CONFIG_ROUTE_METRIC","\
                                              NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES","\
                                              NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS","\
                                              NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID","\
                                              NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME","\
                                              NM_SETTING_IP_CONFIG_DHCP_HOSTNAME","\
                                              NM_SETTING_IP_CONFIG_NEVER_DEFAULT","\
                                              NM_SETTING_IP_CONFIG_MAY_FAIL
#define NMC_FIELDS_SETTING_IP4_CONFIG_COMMON  NMC_FIELDS_SETTING_IP4_CONFIG_ALL

/* Available fields for NM_SETTING_IP6_CONFIG_SETTING_NAME */
NmcOutputField nmc_fields_setting_ip6_config[] = {
	SETTING_FIELD ("name", 8),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_METHOD, 10),                  /* 1 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_DNS, 20),                     /* 2 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_DNS_SEARCH, 15),              /* 3 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_DNS_OPTIONS, 15),             /* 4 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_ADDRESSES, 20),               /* 5 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_GATEWAY, 20),                 /* 6 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_ROUTES, 20),                  /* 7 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_ROUTE_METRIC, 15),            /* 8 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, 19),      /* 9 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, 16),         /* 10 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_NEVER_DEFAULT, 15),           /* 11 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_MAY_FAIL, 12),                /* 12 */
	SETTING_FIELD (NM_SETTING_IP6_CONFIG_IP6_PRIVACY, 15),            /* 13 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, 19),      /* 14 */
	SETTING_FIELD (NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, 14),           /* 15 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_IP6_CONFIG_ALL     "name"","\
                                              NM_SETTING_IP_CONFIG_METHOD","\
                                              NM_SETTING_IP_CONFIG_DNS","\
                                              NM_SETTING_IP_CONFIG_DNS_SEARCH","\
                                              NM_SETTING_IP_CONFIG_DNS_OPTIONS","\
                                              NM_SETTING_IP_CONFIG_ADDRESSES","\
                                              NM_SETTING_IP_CONFIG_GATEWAY","\
                                              NM_SETTING_IP_CONFIG_ROUTES","\
                                              NM_SETTING_IP_CONFIG_ROUTE_METRIC","\
                                              NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES","\
                                              NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS","\
                                              NM_SETTING_IP_CONFIG_NEVER_DEFAULT","\
                                              NM_SETTING_IP_CONFIG_MAY_FAIL","\
                                              NM_SETTING_IP6_CONFIG_IP6_PRIVACY","\
                                              NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME","\
                                              NM_SETTING_IP_CONFIG_DHCP_HOSTNAME
#define NMC_FIELDS_SETTING_IP6_CONFIG_COMMON  NMC_FIELDS_SETTING_IP4_CONFIG_ALL

/* Available fields for NM_SETTING_SERIAL_SETTING_NAME */
NmcOutputField nmc_fields_setting_serial[] = {
	SETTING_FIELD ("name", 10),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_SERIAL_BAUD, 10),                        /* 1 */
	SETTING_FIELD (NM_SETTING_SERIAL_BITS, 10),                        /* 2 */
	SETTING_FIELD (NM_SETTING_SERIAL_PARITY, 10),                      /* 3 */
	SETTING_FIELD (NM_SETTING_SERIAL_STOPBITS, 10),                    /* 4 */
	SETTING_FIELD (NM_SETTING_SERIAL_SEND_DELAY, 12),                  /* 5 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_SERIAL_ALL     "name"","\
                                          NM_SETTING_SERIAL_BAUD","\
                                          NM_SETTING_SERIAL_BITS","\
                                          NM_SETTING_SERIAL_PARITY","\
                                          NM_SETTING_SERIAL_STOPBITS","\
                                          NM_SETTING_SERIAL_SEND_DELAY
#define NMC_FIELDS_SETTING_SERIAL_COMMON  NMC_FIELDS_SETTING_SERIAL_ALL

/* Available fields for NM_SETTING_PPP_SETTING_NAME */
NmcOutputField nmc_fields_setting_ppp[] = {
	SETTING_FIELD ("name", 10),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_PPP_NOAUTH, 10),                         /* 1 */
	SETTING_FIELD (NM_SETTING_PPP_REFUSE_EAP, 10),                     /* 2 */
	SETTING_FIELD (NM_SETTING_PPP_REFUSE_PAP, 10),                     /* 3 */
	SETTING_FIELD (NM_SETTING_PPP_REFUSE_CHAP, 10),                    /* 4 */
	SETTING_FIELD (NM_SETTING_PPP_REFUSE_MSCHAP, 10),                  /* 5 */
	SETTING_FIELD (NM_SETTING_PPP_REFUSE_MSCHAPV2, 10),                /* 6 */
	SETTING_FIELD (NM_SETTING_PPP_NOBSDCOMP, 10),                      /* 7 */
	SETTING_FIELD (NM_SETTING_PPP_NODEFLATE, 10),                      /* 8 */
	SETTING_FIELD (NM_SETTING_PPP_NO_VJ_COMP, 10),                     /* 9 */
	SETTING_FIELD (NM_SETTING_PPP_REQUIRE_MPPE, 10),                   /* 10 */
	SETTING_FIELD (NM_SETTING_PPP_REQUIRE_MPPE_128, 10),               /* 11 */
	SETTING_FIELD (NM_SETTING_PPP_MPPE_STATEFUL, 10),                  /* 12 */
	SETTING_FIELD (NM_SETTING_PPP_CRTSCTS, 10),                        /* 13 */
	SETTING_FIELD (NM_SETTING_PPP_BAUD, 10),                           /* 14 */
	SETTING_FIELD (NM_SETTING_PPP_MRU, 10),                            /* 15 */
	SETTING_FIELD (NM_SETTING_PPP_MTU, 10),                            /* 16 */
	SETTING_FIELD (NM_SETTING_PPP_LCP_ECHO_FAILURE, 17),               /* 17 */
	SETTING_FIELD (NM_SETTING_PPP_LCP_ECHO_INTERVAL, 18),              /* 18 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_PPP_ALL     "name"","\
                                       NM_SETTING_PPP_NOAUTH","\
                                       NM_SETTING_PPP_REFUSE_EAP","\
                                       NM_SETTING_PPP_REFUSE_PAP","\
                                       NM_SETTING_PPP_REFUSE_CHAP","\
                                       NM_SETTING_PPP_REFUSE_MSCHAP","\
                                       NM_SETTING_PPP_REFUSE_MSCHAPV2","\
                                       NM_SETTING_PPP_NOBSDCOMP","\
                                       NM_SETTING_PPP_NODEFLATE","\
                                       NM_SETTING_PPP_NO_VJ_COMP","\
                                       NM_SETTING_PPP_REQUIRE_MPPE","\
                                       NM_SETTING_PPP_REQUIRE_MPPE_128","\
                                       NM_SETTING_PPP_MPPE_STATEFUL","\
                                       NM_SETTING_PPP_CRTSCTS","\
                                       NM_SETTING_PPP_BAUD","\
                                       NM_SETTING_PPP_MRU","\
                                       NM_SETTING_PPP_MTU","\
                                       NM_SETTING_PPP_LCP_ECHO_FAILURE","\
                                       NM_SETTING_PPP_LCP_ECHO_INTERVAL
#define NMC_FIELDS_SETTING_PPP_COMMON  NMC_FIELDS_SETTING_PPP_ALL

/* Available fields for NM_SETTING_PPPOE_SETTING_NAME */
NmcOutputField nmc_fields_setting_pppoe[] = {
	SETTING_FIELD ("name", 10),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_PPPOE_SERVICE, 12),                      /* 1 */
	SETTING_FIELD (NM_SETTING_PPPOE_USERNAME, 15),                     /* 2 */
	SETTING_FIELD (NM_SETTING_PPPOE_PASSWORD, 15),                     /* 3 */
	SETTING_FIELD (NM_SETTING_PPPOE_PASSWORD_FLAGS, 20),               /* 4 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_PPPOE_ALL     "name"","\
                                         NM_SETTING_PPPOE_SERVICE","\
                                         NM_SETTING_PPPOE_USERNAME","\
                                         NM_SETTING_PPPOE_PASSWORD","\
                                         NM_SETTING_PPPOE_PASSWORD_FLAGS
#define NMC_FIELDS_SETTING_PPPOE_COMMON  NMC_FIELDS_SETTING_PPPOE_ALL

/* Available fields for NM_SETTING_ADSL_SETTING_NAME */
NmcOutputField nmc_fields_setting_adsl[] = {
	SETTING_FIELD ("name", 10),                                /* 0 */
	SETTING_FIELD (NM_SETTING_ADSL_USERNAME, 15),              /* 1 */
	SETTING_FIELD (NM_SETTING_ADSL_PASSWORD, 15),              /* 2 */
	SETTING_FIELD (NM_SETTING_ADSL_PASSWORD_FLAGS, 20),        /* 3 */
	SETTING_FIELD (NM_SETTING_ADSL_PROTOCOL, 10),              /* 4 */
	SETTING_FIELD (NM_SETTING_ADSL_ENCAPSULATION, 10),         /* 5 */
	SETTING_FIELD (NM_SETTING_ADSL_VPI, 10),                   /* 6 */
	SETTING_FIELD (NM_SETTING_ADSL_VCI, 10),                   /* 7 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_ADSL_ALL     "name"","\
                                        NM_SETTING_ADSL_USERNAME","\
                                        NM_SETTING_ADSL_PASSWORD","\
                                        NM_SETTING_ADSL_PASSWORD_FLAGS","\
                                        NM_SETTING_ADSL_PROTOCOL","\
                                        NM_SETTING_ADSL_ENCAPSULATION","\
                                        NM_SETTING_ADSL_VPI","\
                                        NM_SETTING_ADSL_VCI
#define NMC_FIELDS_SETTING_ADSL_COMMON  NMC_FIELDS_SETTING_ADSL_ALL

/* Available fields for NM_SETTING_GSM_SETTING_NAME */
NmcOutputField nmc_fields_setting_gsm[] = {
	SETTING_FIELD ("name", 10),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_GSM_NUMBER, 10),                         /* 1 */
	SETTING_FIELD (NM_SETTING_GSM_USERNAME, 15),                       /* 2 */
	SETTING_FIELD (NM_SETTING_GSM_PASSWORD, 15),                       /* 3 */
	SETTING_FIELD (NM_SETTING_GSM_PASSWORD_FLAGS, 20),                 /* 4 */
	SETTING_FIELD (NM_SETTING_GSM_APN, 25),                            /* 5 */
	SETTING_FIELD (NM_SETTING_GSM_NETWORK_ID, 12),                     /* 6 */
	SETTING_FIELD (NM_SETTING_GSM_PIN, 10),                            /* 7 */
	SETTING_FIELD (NM_SETTING_GSM_PIN_FLAGS, 20),                      /* 8 */
	SETTING_FIELD (NM_SETTING_GSM_HOME_ONLY, 10),                      /* 9 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_GSM_ALL     "name"","\
                                       NM_SETTING_GSM_NUMBER","\
                                       NM_SETTING_GSM_USERNAME","\
                                       NM_SETTING_GSM_PASSWORD","\
                                       NM_SETTING_GSM_PASSWORD_FLAGS","\
                                       NM_SETTING_GSM_APN","\
                                       NM_SETTING_GSM_NETWORK_ID","\
                                       NM_SETTING_GSM_PIN","\
                                       NM_SETTING_GSM_PIN_FLAGS","\
                                       NM_SETTING_GSM_HOME_ONLY
#define NMC_FIELDS_SETTING_GSM_COMMON  NMC_FIELDS_SETTING_GSM_ALL

/* Available fields for NM_SETTING_CDMA_SETTING_NAME */
NmcOutputField nmc_fields_setting_cdma[] = {
	SETTING_FIELD ("name", 10),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_CDMA_NUMBER, 15),                        /* 1 */
	SETTING_FIELD (NM_SETTING_CDMA_USERNAME, 15),                      /* 2 */
	SETTING_FIELD (NM_SETTING_CDMA_PASSWORD, 15),                      /* 3 */
	SETTING_FIELD (NM_SETTING_CDMA_PASSWORD_FLAGS, 20),                /* 4 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_CDMA_ALL     "name"","\
                                        NM_SETTING_CDMA_NUMBER","\
                                        NM_SETTING_CDMA_USERNAME","\
                                        NM_SETTING_CDMA_PASSWORD","\
                                        NM_SETTING_CDMA_PASSWORD_FLAGS
#define NMC_FIELDS_SETTING_CDMA_COMMON  NMC_FIELDS_SETTING_CDMA_ALL

/* Available fields for NM_SETTING_BLUETOOTH_SETTING_NAME */
NmcOutputField nmc_fields_setting_bluetooth[] = {
	SETTING_FIELD ("name", 11),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_BLUETOOTH_BDADDR, 19),                   /* 1 */
	SETTING_FIELD (NM_SETTING_BLUETOOTH_TYPE, 10),                     /* 2 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_BLUETOOTH_ALL     "name"","\
                                             NM_SETTING_BLUETOOTH_BDADDR","\
                                             NM_SETTING_BLUETOOTH_TYPE
#define NMC_FIELDS_SETTING_BLUETOOTH_COMMON  NMC_FIELDS_SETTING_BLUETOOTH_ALL

/* Available fields for NM_SETTING_OLPC_MESH_SETTING_NAME */
NmcOutputField nmc_fields_setting_olpc_mesh[] = {
	SETTING_FIELD ("name", 18),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_OLPC_MESH_SSID, 34),                     /* 1 */
	SETTING_FIELD (NM_SETTING_OLPC_MESH_CHANNEL, 12),                  /* 2 */
	SETTING_FIELD (NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS, 17),     /* 3 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_OLPC_MESH_ALL     "name"","\
                                             NM_SETTING_OLPC_MESH_SSID","\
                                             NM_SETTING_OLPC_MESH_CHANNEL","\
                                             NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS
#define NMC_FIELDS_SETTING_OLPC_MESH_COMMON  NMC_FIELDS_SETTING_OLPC_MESH_ALL

/* Available fields for NM_SETTING_VPN_SETTING_NAME */
NmcOutputField nmc_fields_setting_vpn[] = {
	SETTING_FIELD ("name", 6),                                         /* 0 */
	SETTING_FIELD (NM_SETTING_VPN_SERVICE_TYPE, 40),                   /* 1 */
	SETTING_FIELD (NM_SETTING_VPN_USER_NAME, 12),                      /* 2 */
	SETTING_FIELD (NM_SETTING_VPN_DATA, 30),                           /* 3 */
	SETTING_FIELD (NM_SETTING_VPN_SECRETS, 15),                        /* 4 */
	SETTING_FIELD (NM_SETTING_VPN_PERSISTENT, 15),                     /* 5 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_VPN_ALL     "name"","\
                                       NM_SETTING_VPN_SERVICE_TYPE","\
                                       NM_SETTING_VPN_USER_NAME","\
                                       NM_SETTING_VPN_DATA","\
                                       NM_SETTING_VPN_SECRETS","\
                                       NM_SETTING_VPN_PERSISTENT
#define NMC_FIELDS_SETTING_VPN_COMMON  NMC_FIELDS_SETTING_VPN_ALL

/* Available fields for NM_SETTING_WIMAX_SETTING_NAME */
NmcOutputField nmc_fields_setting_wimax[] = {
	SETTING_FIELD ("name", 6),                                         /* 0 */
	SETTING_FIELD (NM_SETTING_WIMAX_MAC_ADDRESS, 19),                  /* 1 */
	SETTING_FIELD (NM_SETTING_WIMAX_NETWORK_NAME, 40),                 /* 2 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_WIMAX_ALL     "name"","\
                                         NM_SETTING_WIMAX_MAC_ADDRESS","\
                                         NM_SETTING_WIMAX_NETWORK_NAME
#define NMC_FIELDS_SETTING_WIMAX_COMMON  NMC_FIELDS_SETTING_WIMAX_ALL

/* Available fields for NM_SETTING_INFINIBAND_SETTING_NAME */
NmcOutputField nmc_fields_setting_infiniband[] = {
	SETTING_FIELD ("name",  12),                                       /* 0 */
	SETTING_FIELD (NM_SETTING_INFINIBAND_MAC_ADDRESS, 61),             /* 1 */
	SETTING_FIELD (NM_SETTING_INFINIBAND_MTU, 6),                      /* 2 */
	SETTING_FIELD (NM_SETTING_INFINIBAND_TRANSPORT_MODE, 12),          /* 3 */
	SETTING_FIELD (NM_SETTING_INFINIBAND_P_KEY, 6),                    /* 4 */
	SETTING_FIELD (NM_SETTING_INFINIBAND_PARENT, 16),                  /* 5 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_INFINIBAND_ALL     "name"","\
                                              NM_SETTING_INFINIBAND_MAC_ADDRESS","\
                                              NM_SETTING_INFINIBAND_MTU"," \
                                              NM_SETTING_INFINIBAND_TRANSPORT_MODE"," \
                                              NM_SETTING_INFINIBAND_P_KEY"," \
                                              NM_SETTING_INFINIBAND_PARENT
#define NMC_FIELDS_SETTING_INFINIBAND_COMMON  NMC_FIELDS_SETTING_INFINIBAND_ALL \

/* Available fields for NM_SETTING_BOND_SETTING_NAME */
NmcOutputField nmc_fields_setting_bond[] = {
	SETTING_FIELD ("name",  8),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_BOND_OPTIONS, 30),                       /* 1 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_BOND_ALL     "name"","\
                                        NM_SETTING_BOND_OPTIONS
#define NMC_FIELDS_SETTING_BOND_COMMON  NMC_FIELDS_SETTING_BOND_ALL

/* Available fields for NM_SETTING_VLAN_SETTING_NAME */
NmcOutputField nmc_fields_setting_vlan[] = {
	SETTING_FIELD ("name",  6),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_VLAN_PARENT, 8),                         /* 1 */
	SETTING_FIELD (NM_SETTING_VLAN_ID, 6),                             /* 2 */
	SETTING_FIELD (NM_SETTING_VLAN_FLAGS, 45),                         /* 3 */
	SETTING_FIELD (NM_SETTING_VLAN_INGRESS_PRIORITY_MAP, 22),          /* 4 */
	SETTING_FIELD (NM_SETTING_VLAN_EGRESS_PRIORITY_MAP, 22),           /* 5 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_VLAN_ALL     "name"","\
                                        NM_SETTING_VLAN_PARENT","\
                                        NM_SETTING_VLAN_ID","\
                                        NM_SETTING_VLAN_FLAGS","\
                                        NM_SETTING_VLAN_INGRESS_PRIORITY_MAP","\
                                        NM_SETTING_VLAN_EGRESS_PRIORITY_MAP
#define NMC_FIELDS_SETTING_VLAN_COMMON  NMC_FIELDS_SETTING_VLAN_ALL

/* Available fields for NM_SETTING_BRIDGE_SETTING_NAME */
NmcOutputField nmc_fields_setting_bridge[] = {
	SETTING_FIELD ("name",  8),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_BRIDGE_MAC_ADDRESS, 19),                 /* 1 */
	SETTING_FIELD (NM_SETTING_BRIDGE_STP, 5),                          /* 2 */
	SETTING_FIELD (NM_SETTING_BRIDGE_PRIORITY, 6),                     /* 3 */
	SETTING_FIELD (NM_SETTING_BRIDGE_FORWARD_DELAY, 6),                /* 4 */
	SETTING_FIELD (NM_SETTING_BRIDGE_HELLO_TIME, 6),                   /* 5 */
	SETTING_FIELD (NM_SETTING_BRIDGE_MAX_AGE, 6),                      /* 6 */
	SETTING_FIELD (NM_SETTING_BRIDGE_AGEING_TIME, 6),                  /* 7 */
	SETTING_FIELD (NM_SETTING_BRIDGE_MULTICAST_SNOOPING, 6),           /* 8 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_BRIDGE_ALL    "name"","\
                                         NM_SETTING_BRIDGE_MAC_ADDRESS","\
                                         NM_SETTING_BRIDGE_STP","\
                                         NM_SETTING_BRIDGE_PRIORITY","\
                                         NM_SETTING_BRIDGE_FORWARD_DELAY","\
                                         NM_SETTING_BRIDGE_HELLO_TIME","\
                                         NM_SETTING_BRIDGE_MAX_AGE","\
                                         NM_SETTING_BRIDGE_AGEING_TIME","\
                                         NM_SETTING_BRIDGE_MULTICAST_SNOOPING
#define NMC_FIELDS_SETTING_BRIDGE_COMMON NMC_FIELDS_SETTING_BRIDGE_ALL

/* Available fields for NM_SETTING_BRIDGE_PORT_SETTING_NAME */
NmcOutputField nmc_fields_setting_bridge_port[] = {
	SETTING_FIELD ("name",  8),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_BRIDGE_PORT_PRIORITY, 10),               /* 1 */
	SETTING_FIELD (NM_SETTING_BRIDGE_PORT_PATH_COST, 12),              /* 2 */
	SETTING_FIELD (NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE, 15),           /* 3 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_BRIDGE_PORT_ALL    "name"","\
                                              NM_SETTING_BRIDGE_PORT_PRIORITY","\
                                              NM_SETTING_BRIDGE_PORT_PATH_COST","\
                                              NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE
#define NMC_FIELDS_SETTING_BRIDGE_PORT_COMMON NMC_FIELDS_SETTING_BRIDGE_PORT_ALL

/* Available fields for NM_SETTING_TEAM_SETTING_NAME */
NmcOutputField nmc_fields_setting_team[] = {
	SETTING_FIELD ("name",  8),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_TEAM_CONFIG, 30),                        /* 1 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_TEAM_ALL     "name"","\
                                        NM_SETTING_TEAM_CONFIG
#define NMC_FIELDS_SETTING_TEAM_COMMON  NMC_FIELDS_SETTING_TEAM_ALL

/* Available fields for NM_SETTING_TEAM_PORT_SETTING_NAME */
NmcOutputField nmc_fields_setting_team_port[] = {
	SETTING_FIELD ("name",  8),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_TEAM_PORT_CONFIG, 30),                   /* 1 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_TEAM_PORT_ALL     "name"","\
                                             NM_SETTING_TEAM_PORT_CONFIG
#define NMC_FIELDS_SETTING_TEAM_PORT_COMMON  NMC_FIELDS_SETTING_TEAM_PORT_ALL

/* Available fields for NM_SETTING_DCB_SETTING_NAME */
NmcOutputField nmc_fields_setting_dcb[] = {
	SETTING_FIELD ("name",  8),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_DCB_APP_FCOE_FLAGS, 5),                  /* 1 */
	SETTING_FIELD (NM_SETTING_DCB_APP_FCOE_PRIORITY, 5),               /* 2 */
	SETTING_FIELD (NM_SETTING_DCB_APP_FCOE_MODE, 8),                   /* 3 */
	SETTING_FIELD (NM_SETTING_DCB_APP_ISCSI_FLAGS, 5),                 /* 4 */
	SETTING_FIELD (NM_SETTING_DCB_APP_ISCSI_PRIORITY, 5),              /* 5 */
	SETTING_FIELD (NM_SETTING_DCB_APP_FIP_FLAGS, 5),                   /* 6 */
	SETTING_FIELD (NM_SETTING_DCB_APP_FIP_PRIORITY, 5),                /* 7 */
	SETTING_FIELD (NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS, 5),     /* 8 */
	SETTING_FIELD (NM_SETTING_DCB_PRIORITY_FLOW_CONTROL, 10),          /* 9 */
	SETTING_FIELD (NM_SETTING_DCB_PRIORITY_GROUP_FLAGS, 5),            /* 10 */
	SETTING_FIELD (NM_SETTING_DCB_PRIORITY_GROUP_ID, 10),              /* 11 */
	SETTING_FIELD (NM_SETTING_DCB_PRIORITY_GROUP_BANDWIDTH, 30),       /* 12 */
	SETTING_FIELD (NM_SETTING_DCB_PRIORITY_BANDWIDTH, 30),             /* 13 */
	SETTING_FIELD (NM_SETTING_DCB_PRIORITY_STRICT_BANDWIDTH, 10),      /* 14 */
	SETTING_FIELD (NM_SETTING_DCB_PRIORITY_TRAFFIC_CLASS, 30),         /* 15 */
	{NULL, NULL, 0, NULL, FALSE, FALSE, 0}
};
#define NMC_FIELDS_SETTING_DCB_ALL     "name"","\
                                       NM_SETTING_DCB_APP_FCOE_FLAGS","\
                                       NM_SETTING_DCB_APP_FCOE_PRIORITY","\
                                       NM_SETTING_DCB_APP_FCOE_MODE","\
                                       NM_SETTING_DCB_APP_ISCSI_FLAGS","\
                                       NM_SETTING_DCB_APP_ISCSI_PRIORITY","\
                                       NM_SETTING_DCB_APP_FIP_FLAGS","\
                                       NM_SETTING_DCB_APP_FIP_PRIORITY","\
                                       NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS","\
                                       NM_SETTING_DCB_PRIORITY_FLOW_CONTROL","\
                                       NM_SETTING_DCB_PRIORITY_GROUP_FLAGS","\
                                       NM_SETTING_DCB_PRIORITY_GROUP_ID","\
                                       NM_SETTING_DCB_PRIORITY_GROUP_BANDWIDTH","\
                                       NM_SETTING_DCB_PRIORITY_BANDWIDTH","\
                                       NM_SETTING_DCB_PRIORITY_STRICT_BANDWIDTH","\
                                       NM_SETTING_DCB_PRIORITY_TRAFFIC_CLASS
#define NMC_FIELDS_SETTING_DCB_COMMON  NMC_FIELDS_SETTING_DCB_ALL

/*----------------------------------------------------------------------------*/

static char *
wep_key_type_to_string (NMWepKeyType type)
{
	switch (type) {
	case NM_WEP_KEY_TYPE_KEY:
		return g_strdup_printf (_("%d (key)"), type);
	case NM_WEP_KEY_TYPE_PASSPHRASE:
		return g_strdup_printf (_("%d (passphrase)"), type);
	case NM_WEP_KEY_TYPE_UNKNOWN:
	default:
		return g_strdup_printf (_("%d (unknown)"), type);
	}
}

static char *
bytes_to_string (GBytes *bytes)
{
	const guint8 *data;
	gsize len;
	GString *cert = NULL;
	int i;

	if (!bytes)
		return NULL;
	data = g_bytes_get_data (bytes, &len);

	cert = g_string_new (NULL);
	for (i = 0; i < len; i++)
		g_string_append_printf (cert, "%02X", data[i]);

	return g_string_free (cert, FALSE);
}

static char *
vlan_flags_to_string (guint32 flags)
{
	GString *flag_str;

	if (flags == 0)
		return g_strdup (_("0 (NONE)"));

	flag_str = g_string_new (NULL);
	g_string_printf (flag_str, "%d (", flags);

	if (flags & NM_VLAN_FLAG_REORDER_HEADERS)
		g_string_append (flag_str, _("REORDER_HEADERS, "));
	if (flags & NM_VLAN_FLAG_GVRP)
		g_string_append (flag_str, _("GVRP, "));
	if (flags & NM_VLAN_FLAG_LOOSE_BINDING)
		g_string_append (flag_str, _("LOOSE_BINDING, "));

	if (flag_str->str[flag_str->len-1] == '(')
		g_string_append (flag_str, _("unknown"));
	else
		g_string_truncate (flag_str, flag_str->len-2);  /* chop off trailing ', ' */

	g_string_append_c (flag_str, ')');

	return g_string_free (flag_str, FALSE);
}

static char *
vlan_priorities_to_string (NMSettingVlan *s_vlan, NMVlanPriorityMap map)
{
	GString *priorities;
	int i;

	priorities = g_string_new (NULL);
	for (i = 0; i < nm_setting_vlan_get_num_priorities (s_vlan, map); i++) {
		guint32 from, to;

		if (nm_setting_vlan_get_priority (s_vlan, map, i, &from, &to))
			g_string_append_printf (priorities, "%d:%d,", from, to);
	}
	if (priorities->len)
		g_string_truncate (priorities, priorities->len-1);  /* chop off trailing ',' */

	return g_string_free (priorities, FALSE);
}

static char *
ip6_privacy_to_string (NMSettingIP6ConfigPrivacy ip6_privacy, NmcPropertyGetType get_type)
{
	if (get_type == NMC_PROPERTY_GET_PARSABLE)
		return g_strdup_printf ("%d", ip6_privacy);

	switch (ip6_privacy) {
	case NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED:
		return g_strdup_printf (_("%d (disabled)"), ip6_privacy);
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR:
		return g_strdup_printf (_("%d (enabled, prefer public IP)"), ip6_privacy);
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR:
		return g_strdup_printf (_("%d (enabled, prefer temporary IP)"), ip6_privacy);
	default:
		return g_strdup_printf (_("%d (unknown)"), ip6_privacy);
	}
}

static char *
secret_flags_to_string (guint32 flags, NmcPropertyGetType get_type)
{
	GString *flag_str;

	if (get_type == NMC_PROPERTY_GET_PARSABLE)
		return g_strdup_printf ("%u", flags);

	if (flags == 0)
		return g_strdup (_("0 (none)"));

	flag_str = g_string_new (NULL);
	g_string_printf (flag_str, "%u (", flags);

	if (flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED)
		g_string_append (flag_str, _("agent-owned, "));
	if (flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
		g_string_append (flag_str, _("not saved, "));
	if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		g_string_append (flag_str, _("not required, "));

	if (flag_str->str[flag_str->len-1] == '(')
		g_string_append (flag_str, _("unknown"));
	else
		g_string_truncate (flag_str, flag_str->len-2);  /* chop off trailing ', ' */

	g_string_append_c (flag_str, ')');

	return g_string_free (flag_str, FALSE);
}

static void
vpn_data_item (const char *key, const char *value, gpointer user_data)
{
	GString *ret_str = (GString *) user_data;

	if (ret_str->len != 0)
		g_string_append (ret_str, ", ");

	g_string_append_printf (ret_str, "%s = %s", key, value);
}


/* === property get functions === */
#define DEFINE_GETTER(func_name, property_name) \
	static char * \
	func_name (NMSetting *setting, NmcPropertyGetType get_type) \
	{ \
		char *s; \
		GValue val = G_VALUE_INIT; \
		g_value_init (&val, G_TYPE_STRING); \
		g_object_get_property (G_OBJECT (setting), property_name, &val); \
		s = g_value_dup_string (&val); \
		g_value_unset (&val); \
		return s; \
	}

#define DEFINE_GETTER_WITH_DEFAULT(func_name, property_name, check_is_default) \
	static char * \
	func_name (NMSetting *setting, NmcPropertyGetType get_type) \
	{ \
		const char *s; \
		char *s_full; \
		GValue val = G_VALUE_INIT; \
		\
		if ((check_is_default)) { \
			if (get_type == NMC_PROPERTY_GET_PARSABLE) \
				return g_strdup (""); \
			return g_strdup (_("(default)")); \
		} \
		\
		g_value_init (&val, G_TYPE_STRING); \
		g_object_get_property (G_OBJECT (setting), property_name, &val); \
		s = g_value_get_string (&val); \
		if (get_type == NMC_PROPERTY_GET_PARSABLE) \
			s_full = g_strdup (s && *s ? s : " "); \
		else \
			s_full = s ? g_strdup_printf ("\"%s\"", s) : g_strdup (""); \
		g_value_unset (&val); \
		return s_full; \
	}

#define DEFINE_SECRET_FLAGS_GETTER(func_name, property_name) \
	static char * \
	func_name (NMSetting *setting, NmcPropertyGetType get_type) \
	{ \
		guint v; \
		GValue val = G_VALUE_INIT; \
		g_value_init (&val, G_TYPE_UINT); \
		g_object_get_property (G_OBJECT (setting), property_name, &val); \
		v = g_value_get_uint (&val); \
		g_value_unset (&val); \
		return secret_flags_to_string (v, get_type); \
	}

/* --- NM_SETTING_802_1X_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_802_1X_get_eap, NM_SETTING_802_1X_EAP)
DEFINE_GETTER (nmc_property_802_1X_get_identity, NM_SETTING_802_1X_IDENTITY)
DEFINE_GETTER (nmc_property_802_1X_get_anonymous_identity, NM_SETTING_802_1X_ANONYMOUS_IDENTITY)
DEFINE_GETTER (nmc_property_802_1X_get_pac_file, NM_SETTING_802_1X_PAC_FILE)
DEFINE_GETTER (nmc_property_802_1X_get_ca_path, NM_SETTING_802_1X_CA_PATH)
DEFINE_GETTER (nmc_property_802_1X_get_subject_match, NM_SETTING_802_1X_SUBJECT_MATCH)
DEFINE_GETTER (nmc_property_802_1X_get_altsubject_matches, NM_SETTING_802_1X_ALTSUBJECT_MATCHES)
DEFINE_GETTER (nmc_property_802_1X_get_phase1_peapver, NM_SETTING_802_1X_PHASE1_PEAPVER)
DEFINE_GETTER (nmc_property_802_1X_get_phase1_peaplabel, NM_SETTING_802_1X_PHASE1_PEAPLABEL)
DEFINE_GETTER (nmc_property_802_1X_get_phase1_fast_provisioning, NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING)
DEFINE_GETTER (nmc_property_802_1X_get_phase2_auth, NM_SETTING_802_1X_PHASE2_AUTH)
DEFINE_GETTER (nmc_property_802_1X_get_phase2_autheap, NM_SETTING_802_1X_PHASE2_AUTHEAP)
DEFINE_GETTER (nmc_property_802_1X_get_phase2_ca_path, NM_SETTING_802_1X_PHASE2_CA_PATH)
DEFINE_GETTER (nmc_property_802_1X_get_phase2_subject_match, NM_SETTING_802_1X_PHASE2_SUBJECT_MATCH)
DEFINE_GETTER (nmc_property_802_1X_get_phase2_altsubject_matches, NM_SETTING_802_1X_PHASE2_ALTSUBJECT_MATCHES)
DEFINE_GETTER (nmc_property_802_1X_get_password, NM_SETTING_802_1X_PASSWORD)
DEFINE_SECRET_FLAGS_GETTER (nmc_property_802_1X_get_password_flags, NM_SETTING_802_1X_PASSWORD_FLAGS)
DEFINE_SECRET_FLAGS_GETTER (nmc_property_802_1X_get_password_raw_flags, NM_SETTING_802_1X_PASSWORD_RAW_FLAGS)
DEFINE_GETTER (nmc_property_802_1X_get_private_key_password, NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD)
DEFINE_SECRET_FLAGS_GETTER (nmc_property_802_1X_get_private_key_password_flags, NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS)
DEFINE_GETTER (nmc_property_802_1X_get_phase2_private_key_password, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD)
DEFINE_SECRET_FLAGS_GETTER (nmc_property_802_1X_get_phase2_private_key_password_flags, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD_FLAGS)
DEFINE_GETTER (nmc_property_802_1X_get_pin, NM_SETTING_802_1X_PIN)
DEFINE_SECRET_FLAGS_GETTER (nmc_property_802_1X_get_pin_flags, NM_SETTING_802_1X_PIN_FLAGS)
DEFINE_GETTER (nmc_property_802_1X_get_system_ca_certs, NM_SETTING_802_1X_SYSTEM_CA_CERTS)

static char *
nmc_property_802_1X_get_ca_cert (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSetting8021x *s_8021X = NM_SETTING_802_1X (setting);
	NMSetting8021xCKScheme scheme;
	char *ca_cert_str = NULL;

	scheme = nm_setting_802_1x_get_ca_cert_scheme (s_8021X);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
		ca_cert_str = bytes_to_string (nm_setting_802_1x_get_ca_cert_blob (s_8021X));
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
		ca_cert_str = g_strdup (nm_setting_802_1x_get_ca_cert_path (s_8021X));

	return ca_cert_str;
}

static char *
nmc_property_802_1X_get_client_cert (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSetting8021x *s_8021X = NM_SETTING_802_1X (setting);
	NMSetting8021xCKScheme scheme;
	char *client_cert_str = NULL;

	scheme = nm_setting_802_1x_get_client_cert_scheme (s_8021X);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
		client_cert_str = bytes_to_string (nm_setting_802_1x_get_client_cert_blob (s_8021X));
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
		client_cert_str = g_strdup (nm_setting_802_1x_get_client_cert_path (s_8021X));

	return client_cert_str;
}

static char *
nmc_property_802_1X_get_phase2_ca_cert (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSetting8021x *s_8021X = NM_SETTING_802_1X (setting);
	NMSetting8021xCKScheme scheme;
	char *phase2_ca_cert_str = NULL;

	scheme = nm_setting_802_1x_get_phase2_ca_cert_scheme (s_8021X);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
		phase2_ca_cert_str = bytes_to_string (nm_setting_802_1x_get_phase2_ca_cert_blob (s_8021X));
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
		phase2_ca_cert_str = g_strdup (nm_setting_802_1x_get_phase2_ca_cert_path (s_8021X));

	return phase2_ca_cert_str;
}

static char *
nmc_property_802_1X_get_phase2_client_cert (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSetting8021x *s_8021X = NM_SETTING_802_1X (setting);
	NMSetting8021xCKScheme scheme;
	char *phase2_client_cert_str = NULL;

	scheme = nm_setting_802_1x_get_phase2_client_cert_scheme (s_8021X);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
		phase2_client_cert_str = bytes_to_string (nm_setting_802_1x_get_phase2_client_cert_blob (s_8021X));
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
		phase2_client_cert_str = g_strdup (nm_setting_802_1x_get_phase2_client_cert_path (s_8021X));

	return phase2_client_cert_str;
}

static char *
nmc_property_802_1X_get_password_raw (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSetting8021x *s_8021X = NM_SETTING_802_1X (setting);
	return bytes_to_string (nm_setting_802_1x_get_password_raw (s_8021X));
}

static char *
nmc_property_802_1X_get_private_key (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSetting8021x *s_8021X = NM_SETTING_802_1X (setting);
	NMSetting8021xCKScheme scheme;
	char *private_key_str = NULL;

	scheme = nm_setting_802_1x_get_private_key_scheme (s_8021X);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
		private_key_str = bytes_to_string (nm_setting_802_1x_get_private_key_blob (s_8021X));
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
		private_key_str = g_strdup (nm_setting_802_1x_get_private_key_path (s_8021X));

	return private_key_str;
}

static char *
nmc_property_802_1X_get_phase2_private_key (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSetting8021x *s_8021X = NM_SETTING_802_1X (setting);
	NMSetting8021xCKScheme scheme;
	char *phase2_private_key_str = NULL;

	scheme = nm_setting_802_1x_get_phase2_private_key_scheme (s_8021X);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
		phase2_private_key_str = bytes_to_string (nm_setting_802_1x_get_phase2_private_key_blob (s_8021X));
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
		phase2_private_key_str = g_strdup (nm_setting_802_1x_get_phase2_private_key_path (s_8021X));

	return phase2_private_key_str;
}

/* --- NM_SETTING_ADSL_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_adsl_get_username, NM_SETTING_ADSL_USERNAME)
DEFINE_GETTER (nmc_property_adsl_get_password, NM_SETTING_ADSL_PASSWORD)
DEFINE_SECRET_FLAGS_GETTER (nmc_property_adsl_get_password_flags, NM_SETTING_ADSL_PASSWORD_FLAGS)
DEFINE_GETTER (nmc_property_adsl_get_protocol, NM_SETTING_ADSL_PROTOCOL)
DEFINE_GETTER (nmc_property_adsl_get_encapsulation, NM_SETTING_ADSL_ENCAPSULATION)
DEFINE_GETTER (nmc_property_adsl_get_vpi, NM_SETTING_ADSL_VPI)
DEFINE_GETTER (nmc_property_adsl_get_vci, NM_SETTING_ADSL_VCI)

/* --- NM_SETTING_BLUETOOTH_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_bluetooth_get_bdaddr, NM_SETTING_BLUETOOTH_BDADDR)
DEFINE_GETTER (nmc_property_bluetooth_get_type, NM_SETTING_BLUETOOTH_TYPE)

static char *
nmc_property_bond_get_options (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingBond *s_bond = NM_SETTING_BOND (setting);
	GString *bond_options_s;
	int i;

	bond_options_s = g_string_new (NULL);
	for (i = 0; i < nm_setting_bond_get_num_options (s_bond); i++) {
		const char *key, *value;

		nm_setting_bond_get_option (s_bond, i, &key, &value);
		g_string_append_printf (bond_options_s, "%s=%s,", key, value);
	}
	g_string_truncate (bond_options_s, bond_options_s->len-1);  /* chop off trailing ',' */

	return g_string_free (bond_options_s, FALSE);
}

/* --- NM_SETTING_BRIDGE_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_bridge_get_mac_address, NM_SETTING_BRIDGE_MAC_ADDRESS)
DEFINE_GETTER (nmc_property_bridge_get_stp, NM_SETTING_BRIDGE_STP)
DEFINE_GETTER (nmc_property_bridge_get_priority, NM_SETTING_BRIDGE_PRIORITY)
DEFINE_GETTER (nmc_property_bridge_get_forward_delay, NM_SETTING_BRIDGE_FORWARD_DELAY)
DEFINE_GETTER (nmc_property_bridge_get_hello_time, NM_SETTING_BRIDGE_HELLO_TIME)
DEFINE_GETTER (nmc_property_bridge_get_max_age, NM_SETTING_BRIDGE_MAX_AGE)
DEFINE_GETTER (nmc_property_bridge_get_ageing_time, NM_SETTING_BRIDGE_AGEING_TIME)
DEFINE_GETTER (nmc_property_bridge_get_multicast_snooping, NM_SETTING_BRIDGE_MULTICAST_SNOOPING)

/* --- NM_SETTING_BRIDGE_PORT_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_bridge_port_get_priority, NM_SETTING_BRIDGE_PORT_PRIORITY)
DEFINE_GETTER (nmc_property_bridge_port_get_path_cost, NM_SETTING_BRIDGE_PORT_PATH_COST)
DEFINE_GETTER (nmc_property_bridge_port_get_hairpin_mode, NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE)

/* --- NM_SETTING_TEAM_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_team_get_config, NM_SETTING_TEAM_CONFIG)

/* --- NM_SETTING_TEAM_PORT_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_team_port_get_config, NM_SETTING_TEAM_PORT_CONFIG)

/* --- NM_SETTING_CDMA_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_cdma_get_number, NM_SETTING_CDMA_NUMBER)
DEFINE_GETTER (nmc_property_cdma_get_username, NM_SETTING_CDMA_USERNAME)
DEFINE_GETTER (nmc_property_cdma_get_password, NM_SETTING_CDMA_PASSWORD)

DEFINE_SECRET_FLAGS_GETTER (nmc_property_cdma_get_password_flags, NM_SETTING_CDMA_PASSWORD_FLAGS)

/* --- NM_SETTING_CONNECTION_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_connection_get_id, NM_SETTING_CONNECTION_ID)
DEFINE_GETTER (nmc_property_connection_get_uuid, NM_SETTING_CONNECTION_UUID)
DEFINE_GETTER (nmc_property_connection_get_interface_name, NM_SETTING_CONNECTION_INTERFACE_NAME)
DEFINE_GETTER (nmc_property_connection_get_type, NM_SETTING_CONNECTION_TYPE)
DEFINE_GETTER (nmc_property_connection_get_autoconnect, NM_SETTING_CONNECTION_AUTOCONNECT)
DEFINE_GETTER (nmc_property_connection_get_autoconnect_priority, NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY)
DEFINE_GETTER (nmc_property_connection_get_timestamp, NM_SETTING_CONNECTION_TIMESTAMP)
DEFINE_GETTER (nmc_property_connection_get_read_only, NM_SETTING_CONNECTION_READ_ONLY)

static char *
nmc_property_connection_get_permissions (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingConnection *s_con = NM_SETTING_CONNECTION (setting);
	GString *perm = NULL;
	const char *perm_item;
	const char *perm_type;
	int i;

	perm = g_string_new (NULL);
	for (i = 0; i < nm_setting_connection_get_num_permissions (s_con); i++) {
		if (nm_setting_connection_get_permission (s_con, i, &perm_type, &perm_item, NULL))
			g_string_append_printf (perm, "%s:%s,", perm_type, perm_item);
	}
	if (perm->len > 0)
		g_string_truncate (perm, perm->len-1); /* remove trailing , */

	return g_string_free (perm, FALSE);
}

DEFINE_GETTER (nmc_property_connection_get_zone, NM_SETTING_CONNECTION_ZONE)
DEFINE_GETTER (nmc_property_connection_get_master, NM_SETTING_CONNECTION_MASTER)
DEFINE_GETTER (nmc_property_connection_get_slave_type, NM_SETTING_CONNECTION_SLAVE_TYPE)
DEFINE_GETTER (nmc_property_connection_get_secondaries, NM_SETTING_CONNECTION_SECONDARIES)
DEFINE_GETTER (nmc_property_connection_get_gateway_ping_timeout, NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT)

/* --- NM_SETTING_DCB_SETTING_NAME property get functions --- */
static char *
dcb_flags_to_string (NMSettingDcbFlags flags)
{
	GString *flag_str;

	if (flags == 0)
		return g_strdup (_("0 (disabled)"));

	flag_str = g_string_new (NULL);
	g_string_printf (flag_str, "%d (", flags);

	if (flags & NM_SETTING_DCB_FLAG_ENABLE)
		g_string_append (flag_str, _("enabled, "));
	if (flags & NM_SETTING_DCB_FLAG_ADVERTISE)
		g_string_append (flag_str, _("advertise, "));
	if (flags & NM_SETTING_DCB_FLAG_WILLING)
		g_string_append (flag_str, _("willing, "));

	if (flag_str->str[flag_str->len-1] == '(')
		g_string_append (flag_str, _("unknown"));
	else
		g_string_truncate (flag_str, flag_str->len-2);  /* chop off trailing ', ' */

	g_string_append_c (flag_str, ')');

	return g_string_free (flag_str, FALSE);
}

#define DEFINE_DCB_FLAGS_GETTER(func_name, property_name) \
	static char * \
	func_name (NMSetting *setting, NmcPropertyGetType get_type) \
	{ \
		guint v; \
		GValue val = G_VALUE_INIT; \
		g_value_init (&val, G_TYPE_UINT); \
		g_object_get_property (G_OBJECT (setting), property_name, &val); \
		v = g_value_get_uint (&val); \
		g_value_unset (&val); \
		return dcb_flags_to_string (v); \
	}

static char *
dcb_app_priority_to_string (gint priority)
{
	return (priority == -1) ? g_strdup (_("-1 (unset)")) : g_strdup_printf ("%d", priority);
}

#define DEFINE_DCB_APP_PRIORITY_GETTER(func_name, property_name) \
	static char * \
	func_name (NMSetting *setting, NmcPropertyGetType get_type) \
	{ \
		int v; \
		GValue val = G_VALUE_INIT; \
		g_value_init (&val, G_TYPE_INT); \
		g_object_get_property (G_OBJECT (setting), property_name, &val); \
		v = g_value_get_int (&val); \
		g_value_unset (&val); \
		return dcb_app_priority_to_string (v); \
	}

#define DEFINE_DCB_BOOL_GETTER(func_name, getter_func_name) \
	static char * \
	func_name (NMSetting *setting, NmcPropertyGetType get_type) \
	{ \
		NMSettingDcb *s_dcb = NM_SETTING_DCB (setting); \
		GString *str; \
		guint i; \
 \
		str = g_string_new (NULL); \
		for (i = 0; i < 8; i++) { \
			if (getter_func_name (s_dcb,  i)) \
				g_string_append_c (str, '1'); \
			else \
				g_string_append_c (str, '0'); \
\
			if (i < 7) \
				g_string_append_c (str, ','); \
		} \
\
		return g_string_free (str, FALSE); \
	}

#define DEFINE_DCB_UINT_GETTER(func_name, getter_func_name) \
	static char * \
	func_name (NMSetting *setting, NmcPropertyGetType get_type) \
	{ \
		NMSettingDcb *s_dcb = NM_SETTING_DCB (setting); \
		GString *str; \
		guint i; \
 \
		str = g_string_new (NULL); \
		for (i = 0; i < 8; i++) { \
			g_string_append_printf (str, "%u", getter_func_name (s_dcb, i)); \
			if (i < 7) \
				g_string_append_c (str, ','); \
		} \
\
		return g_string_free (str, FALSE); \
	}

DEFINE_DCB_FLAGS_GETTER (nmc_property_dcb_get_app_fcoe_flags, NM_SETTING_DCB_APP_FCOE_FLAGS)
DEFINE_DCB_APP_PRIORITY_GETTER (nmc_property_dcb_get_app_fcoe_priority, NM_SETTING_DCB_APP_FCOE_PRIORITY)
DEFINE_GETTER (nmc_property_dcb_get_app_fcoe_mode, NM_SETTING_DCB_APP_FCOE_MODE)
DEFINE_DCB_FLAGS_GETTER (nmc_property_dcb_get_app_iscsi_flags, NM_SETTING_DCB_APP_ISCSI_FLAGS)
DEFINE_DCB_APP_PRIORITY_GETTER (nmc_property_dcb_get_app_iscsi_priority, NM_SETTING_DCB_APP_ISCSI_PRIORITY)
DEFINE_DCB_FLAGS_GETTER (nmc_property_dcb_get_app_fip_flags, NM_SETTING_DCB_APP_FIP_FLAGS)
DEFINE_DCB_APP_PRIORITY_GETTER (nmc_property_dcb_get_app_fip_priority, NM_SETTING_DCB_APP_FIP_PRIORITY)

DEFINE_DCB_FLAGS_GETTER (nmc_property_dcb_get_pfc_flags, NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS)
DEFINE_DCB_BOOL_GETTER (nmc_property_dcb_get_pfc, nm_setting_dcb_get_priority_flow_control)

DEFINE_DCB_FLAGS_GETTER (nmc_property_dcb_get_pg_flags, NM_SETTING_DCB_PRIORITY_GROUP_FLAGS)
DEFINE_DCB_UINT_GETTER (nmc_property_dcb_get_pg_group_id, nm_setting_dcb_get_priority_group_id)
DEFINE_DCB_UINT_GETTER (nmc_property_dcb_get_pg_group_bandwidth, nm_setting_dcb_get_priority_group_bandwidth)
DEFINE_DCB_UINT_GETTER (nmc_property_dcb_get_pg_bandwidth, nm_setting_dcb_get_priority_bandwidth)
DEFINE_DCB_BOOL_GETTER (nmc_property_dcb_get_pg_strict, nm_setting_dcb_get_priority_strict_bandwidth)
DEFINE_DCB_UINT_GETTER (nmc_property_dcb_get_pg_traffic_class, nm_setting_dcb_get_priority_traffic_class)

/* --- NM_SETTING_GSM_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_gsm_get_number, NM_SETTING_GSM_NUMBER)
DEFINE_GETTER (nmc_property_gsm_get_username, NM_SETTING_GSM_USERNAME)
DEFINE_GETTER (nmc_property_gsm_get_password, NM_SETTING_GSM_PASSWORD)
DEFINE_SECRET_FLAGS_GETTER (nmc_property_gsm_get_password_flags, NM_SETTING_GSM_PASSWORD_FLAGS)
DEFINE_GETTER (nmc_property_gsm_get_apn, NM_SETTING_GSM_APN)
DEFINE_GETTER (nmc_property_gsm_get_network_id, NM_SETTING_GSM_NETWORK_ID)
DEFINE_GETTER (nmc_property_gsm_get_pin, NM_SETTING_GSM_PIN)
DEFINE_SECRET_FLAGS_GETTER (nmc_property_gsm_get_pin_flags, NM_SETTING_GSM_PIN_FLAGS)
DEFINE_GETTER (nmc_property_gsm_get_home_only, NM_SETTING_GSM_HOME_ONLY)

/* --- NM_SETTING_INFINIBAND_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_ib_get_mac_address, NM_SETTING_INFINIBAND_MAC_ADDRESS)
DEFINE_GETTER (nmc_property_ib_get_transport_mode, NM_SETTING_INFINIBAND_TRANSPORT_MODE)

static char *
nmc_property_ib_get_mtu (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingInfiniband *s_infiniband = NM_SETTING_INFINIBAND (setting);
	int mtu;

	mtu = nm_setting_infiniband_get_mtu (s_infiniband);
	if (mtu == 0)
		return g_strdup (_("auto"));
	else
		return g_strdup_printf ("%d", mtu);
}

static char *
nmc_property_ib_get_p_key (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingInfiniband *s_infiniband = NM_SETTING_INFINIBAND (setting);
	int p_key;

	p_key = nm_setting_infiniband_get_p_key (s_infiniband);
	if (p_key == -1)
		return g_strdup (_("default"));
	else
		return g_strdup_printf ("0x%04x", p_key);
}

DEFINE_GETTER (nmc_property_ib_get_parent, NM_SETTING_INFINIBAND_PARENT)

/* --- NM_SETTING_IP4_CONFIG_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_ipv4_get_method, NM_SETTING_IP_CONFIG_METHOD)
DEFINE_GETTER (nmc_property_ipv4_get_dns, NM_SETTING_IP_CONFIG_DNS)
DEFINE_GETTER (nmc_property_ipv4_get_dns_search, NM_SETTING_IP_CONFIG_DNS_SEARCH)
DEFINE_GETTER_WITH_DEFAULT (nmc_property_ipv4_get_dns_options, NM_SETTING_IP_CONFIG_DNS_OPTIONS, !nm_setting_ip_config_has_dns_options ((NMSettingIPConfig *) setting))

static char *
nmc_property_ip_get_addresses (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingIPConfig *s_ip = NM_SETTING_IP_CONFIG (setting);
	GString *printable;
	guint32 num_addresses, i;
	NMIPAddress *addr;

	printable = g_string_new (NULL);

	num_addresses = nm_setting_ip_config_get_num_addresses (s_ip);
	for (i = 0; i < num_addresses; i++) {
		addr = nm_setting_ip_config_get_address (s_ip, i);

		if (printable->len > 0)
			g_string_append (printable, ", ");

		g_string_append_printf (printable, "%s/%u",
		                        nm_ip_address_get_address (addr),
		                        nm_ip_address_get_prefix (addr));
	}

	return g_string_free (printable, FALSE);
}

static char *
nmc_property_ipvx_get_routes (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingIPConfig *s_ip = NM_SETTING_IP_CONFIG (setting);
	GString *printable;
	guint32 num_routes, i;
	NMIPRoute *route;

	printable = g_string_new (NULL);

	num_routes = nm_setting_ip_config_get_num_routes (s_ip);
	for (i = 0; i < num_routes; i++) {
		route = nm_setting_ip_config_get_route (s_ip, i);

		if (get_type == NMC_PROPERTY_GET_PARSABLE) {
			if (printable->len > 0)
				g_string_append (printable, ", ");

			g_string_append_printf (printable, "%s/%u",
			                        nm_ip_route_get_dest (route),
			                        nm_ip_route_get_prefix (route));

			if (nm_ip_route_get_next_hop (route))
				g_string_append_printf (printable, " %s", nm_ip_route_get_next_hop (route));
			if (nm_ip_route_get_metric (route) != -1)
				g_string_append_printf (printable, " %u", (guint32) nm_ip_route_get_metric (route));
		} else {
			if (printable->len > 0)
				g_string_append (printable, "; ");

			g_string_append (printable, "{ ");

			g_string_append_printf (printable, "ip = %s/%u",
			                        nm_ip_route_get_dest (route),
			                        nm_ip_route_get_prefix (route));

			if (nm_ip_route_get_next_hop (route)) {
				g_string_append_printf (printable, ", nh = %s",
				                        nm_ip_route_get_next_hop (route));
			}

			if (nm_ip_route_get_metric (route) != -1)
				g_string_append_printf (printable, ", mt = %u", (guint32) nm_ip_route_get_metric (route));

			g_string_append (printable, " }");
		}
	}

	return g_string_free (printable, FALSE);
}

static char *
nmc_property_ipv4_get_routes (NMSetting *setting, NmcPropertyGetType get_type)
{
	return nmc_property_ipvx_get_routes (setting, get_type);
}

DEFINE_GETTER (nmc_property_ipv4_get_gateway, NM_SETTING_IP_CONFIG_GATEWAY)
DEFINE_GETTER (nmc_property_ipv4_get_route_metric, NM_SETTING_IP_CONFIG_ROUTE_METRIC)
DEFINE_GETTER (nmc_property_ipv4_get_ignore_auto_routes, NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES)
DEFINE_GETTER (nmc_property_ipv4_get_ignore_auto_dns, NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS)
DEFINE_GETTER (nmc_property_ipv4_get_dhcp_client_id, NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID)
DEFINE_GETTER (nmc_property_ipv4_get_dhcp_send_hostname, NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME)
DEFINE_GETTER (nmc_property_ipv4_get_dhcp_hostname, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME)
DEFINE_GETTER (nmc_property_ipv4_get_never_default, NM_SETTING_IP_CONFIG_NEVER_DEFAULT)
DEFINE_GETTER (nmc_property_ipv4_get_may_fail, NM_SETTING_IP_CONFIG_MAY_FAIL)

/* --- NM_SETTING_IP6_CONFIG_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_ipv6_get_method, NM_SETTING_IP_CONFIG_METHOD)
DEFINE_GETTER (nmc_property_ipv6_get_dns, NM_SETTING_IP_CONFIG_DNS)
DEFINE_GETTER (nmc_property_ipv6_get_dns_search, NM_SETTING_IP_CONFIG_DNS_SEARCH)
DEFINE_GETTER_WITH_DEFAULT (nmc_property_ipv6_get_dns_options, NM_SETTING_IP_CONFIG_DNS_OPTIONS, !nm_setting_ip_config_has_dns_options ((NMSettingIPConfig *) setting))

static char *
nmc_property_ipv6_get_routes (NMSetting *setting, NmcPropertyGetType get_type)
{
	return nmc_property_ipvx_get_routes (setting, get_type);
}

DEFINE_GETTER (nmc_property_ipv6_get_gateway, NM_SETTING_IP_CONFIG_GATEWAY)
DEFINE_GETTER (nmc_property_ipv6_get_route_metric, NM_SETTING_IP_CONFIG_ROUTE_METRIC)
DEFINE_GETTER (nmc_property_ipv6_get_ignore_auto_routes, NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES)
DEFINE_GETTER (nmc_property_ipv6_get_ignore_auto_dns, NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS)
DEFINE_GETTER (nmc_property_ipv6_get_never_default, NM_SETTING_IP_CONFIG_NEVER_DEFAULT)
DEFINE_GETTER (nmc_property_ipv6_get_may_fail, NM_SETTING_IP_CONFIG_MAY_FAIL)
DEFINE_GETTER (nmc_property_ipv6_get_dhcp_send_hostname, NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME)
DEFINE_GETTER (nmc_property_ipv6_get_dhcp_hostname, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME)

static char *
nmc_property_ipv6_get_ip6_privacy (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingIP6Config *s_ip6 = NM_SETTING_IP6_CONFIG (setting);
	return ip6_privacy_to_string (nm_setting_ip6_config_get_ip6_privacy (s_ip6), get_type);
}

/* --- NM_SETTING_OLPC_MESH_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_olpc_get_channel, NM_SETTING_OLPC_MESH_CHANNEL)
DEFINE_GETTER (nmc_property_olpc_get_anycast_address, NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS)

static char *
nmc_property_olpc_get_ssid (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingOlpcMesh *s_olpc_mesh = NM_SETTING_OLPC_MESH (setting);
	GBytes *ssid;
	char *ssid_str = NULL;

	ssid = nm_setting_olpc_mesh_get_ssid (s_olpc_mesh);
	if (ssid) {
		ssid_str = nm_utils_ssid_to_utf8 (g_bytes_get_data (ssid, NULL),
		                                  g_bytes_get_size (ssid));
	}

	return ssid_str;
}

/* --- NM_SETTING_PPP_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_ppp_get_noauth, NM_SETTING_PPP_NOAUTH)
DEFINE_GETTER (nmc_property_ppp_get_refuse_eap, NM_SETTING_PPP_REFUSE_EAP)
DEFINE_GETTER (nmc_property_ppp_get_refuse_pap, NM_SETTING_PPP_REFUSE_PAP)
DEFINE_GETTER (nmc_property_ppp_get_refuse_chap, NM_SETTING_PPP_REFUSE_CHAP)
DEFINE_GETTER (nmc_property_ppp_get_refuse_mschap, NM_SETTING_PPP_REFUSE_MSCHAP)
DEFINE_GETTER (nmc_property_ppp_get_refuse_mschapv2, NM_SETTING_PPP_REFUSE_MSCHAPV2)
DEFINE_GETTER (nmc_property_ppp_get_nobsdcomp, NM_SETTING_PPP_NOBSDCOMP)
DEFINE_GETTER (nmc_property_ppp_get_nodeflate, NM_SETTING_PPP_NODEFLATE)
DEFINE_GETTER (nmc_property_ppp_get_no_vj_comp, NM_SETTING_PPP_NO_VJ_COMP)
DEFINE_GETTER (nmc_property_ppp_get_require_mppe, NM_SETTING_PPP_REQUIRE_MPPE)
DEFINE_GETTER (nmc_property_ppp_get_require_mppe_128, NM_SETTING_PPP_REQUIRE_MPPE_128)
DEFINE_GETTER (nmc_property_ppp_get_mppe_stateful, NM_SETTING_PPP_MPPE_STATEFUL)
DEFINE_GETTER (nmc_property_ppp_get_crtscts, NM_SETTING_PPP_CRTSCTS)
DEFINE_GETTER (nmc_property_ppp_get_baud, NM_SETTING_PPP_BAUD)
DEFINE_GETTER (nmc_property_ppp_get_mru, NM_SETTING_PPP_MRU)
DEFINE_GETTER (nmc_property_ppp_get_mtu, NM_SETTING_PPP_MTU)
DEFINE_GETTER (nmc_property_ppp_get_lcp_echo_failure, NM_SETTING_PPP_LCP_ECHO_FAILURE)
DEFINE_GETTER (nmc_property_ppp_get_lcp_echo_interval, NM_SETTING_PPP_LCP_ECHO_INTERVAL)

/* --- NM_SETTING_PPPOE_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_pppoe_get_service, NM_SETTING_PPPOE_SERVICE)
DEFINE_GETTER (nmc_property_pppoe_get_username, NM_SETTING_PPPOE_USERNAME)
DEFINE_GETTER (nmc_property_pppoe_get_password, NM_SETTING_PPPOE_PASSWORD)
DEFINE_SECRET_FLAGS_GETTER (nmc_property_pppoe_get_password_flags, NM_SETTING_PPPOE_PASSWORD_FLAGS)

/* --- NM_SETTING_SERIAL_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_serial_get_baud, NM_SETTING_SERIAL_BAUD)
DEFINE_GETTER (nmc_property_serial_get_bits, NM_SETTING_SERIAL_BITS)
DEFINE_GETTER (nmc_property_serial_get_stopbits, NM_SETTING_SERIAL_STOPBITS)
DEFINE_GETTER (nmc_property_serial_get_send_delay, NM_SETTING_SERIAL_SEND_DELAY)

/* --- NM_SETTING_VLAN_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_vlan_get_parent, NM_SETTING_VLAN_PARENT)
DEFINE_GETTER (nmc_property_vlan_get_id, NM_SETTING_VLAN_ID)


static char *
nmc_property_vlan_get_flags (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingVlan *s_vlan = NM_SETTING_VLAN (setting);
	return vlan_flags_to_string (nm_setting_vlan_get_flags (s_vlan));
}

static char *
nmc_property_vlan_get_ingress_priority_map (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingVlan *s_vlan = NM_SETTING_VLAN (setting);
	return vlan_priorities_to_string (s_vlan, NM_VLAN_INGRESS_MAP);
}

static char *
nmc_property_vlan_get_egress_priority_map (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingVlan *s_vlan = NM_SETTING_VLAN (setting);
	return vlan_priorities_to_string (s_vlan, NM_VLAN_EGRESS_MAP);
}

/* --- NM_SETTING_VPN_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_vpn_get_service_type, NM_SETTING_VPN_SERVICE_TYPE)
DEFINE_GETTER (nmc_property_vpn_get_user_name, NM_SETTING_VPN_USER_NAME)

static char *
nmc_property_vpn_get_data (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingVpn *s_vpn = NM_SETTING_VPN (setting);
	GString *data_item_str;

	data_item_str = g_string_new (NULL);
	nm_setting_vpn_foreach_data_item (s_vpn, &vpn_data_item, data_item_str);

	return g_string_free (data_item_str, FALSE);
}

static char *
nmc_property_vpn_get_secrets (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingVpn *s_vpn = NM_SETTING_VPN (setting);
	GString *secret_str;

	secret_str = g_string_new (NULL);
	nm_setting_vpn_foreach_secret (s_vpn, &vpn_data_item, secret_str);

	return g_string_free (secret_str, FALSE);
}

DEFINE_GETTER (nmc_property_vpn_get_persistent, NM_SETTING_VPN_PERSISTENT)

/* --- NM_SETTING_WIMAX_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_wimax_get_network_name, NM_SETTING_WIMAX_NETWORK_NAME)
DEFINE_GETTER (nmc_property_wimax_get_mac_address, NM_SETTING_WIMAX_MAC_ADDRESS)

/* --- NM_SETTING_WIRED_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_wired_get_port, NM_SETTING_WIRED_PORT)
DEFINE_GETTER (nmc_property_wired_get_speed, NM_SETTING_WIRED_SPEED)
DEFINE_GETTER (nmc_property_wired_get_duplex, NM_SETTING_WIRED_DUPLEX)
DEFINE_GETTER (nmc_property_wired_get_auto_negotiate, NM_SETTING_WIRED_AUTO_NEGOTIATE)
DEFINE_GETTER (nmc_property_wired_get_mac_address, NM_SETTING_WIRED_MAC_ADDRESS)
DEFINE_GETTER (nmc_property_wired_get_cloned_mac_address, NM_SETTING_WIRED_CLONED_MAC_ADDRESS)
DEFINE_GETTER (nmc_property_wired_get_mac_address_blacklist, NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST)
DEFINE_GETTER (nmc_property_wired_get_s390_subchannels, NM_SETTING_WIRED_S390_SUBCHANNELS)
DEFINE_GETTER (nmc_property_wired_get_s390_nettype, NM_SETTING_WIRED_S390_NETTYPE)
DEFINE_GETTER (nmc_property_wired_get_s390_options, NM_SETTING_WIRED_S390_OPTIONS)

static char *
nmc_property_wired_get_mtu (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingWired *s_wired = NM_SETTING_WIRED (setting);
	int mtu;

	mtu = nm_setting_wired_get_mtu (s_wired);
	if (mtu == 0)
		return g_strdup (_("auto"));
	else
		return g_strdup_printf ("%d", mtu);
}

/* --- NM_SETTING_WIRELESS_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_wireless_get_mode, NM_SETTING_WIRELESS_MODE)
DEFINE_GETTER (nmc_property_wireless_get_band, NM_SETTING_WIRELESS_BAND)
DEFINE_GETTER (nmc_property_wireless_get_channel, NM_SETTING_WIRELESS_CHANNEL)
DEFINE_GETTER (nmc_property_wireless_get_bssid, NM_SETTING_WIRELESS_BSSID)
DEFINE_GETTER (nmc_property_wireless_get_rate, NM_SETTING_WIRELESS_RATE)
DEFINE_GETTER (nmc_property_wireless_get_tx_power, NM_SETTING_WIRELESS_TX_POWER)
DEFINE_GETTER (nmc_property_wireless_get_mac_address, NM_SETTING_WIRELESS_MAC_ADDRESS)
DEFINE_GETTER (nmc_property_wireless_get_cloned_mac_address, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS)
DEFINE_GETTER (nmc_property_wireless_get_mac_address_blacklist, NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST)
DEFINE_GETTER (nmc_property_wireless_get_seen_bssids, NM_SETTING_WIRELESS_SEEN_BSSIDS)
DEFINE_GETTER (nmc_property_wireless_get_hidden, NM_SETTING_WIRELESS_HIDDEN)

static char *
nmc_property_wireless_get_ssid (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingWireless *s_wireless = NM_SETTING_WIRELESS (setting);
	GBytes *ssid;
	char *ssid_str = NULL;

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	if (ssid) {
		ssid_str = nm_utils_ssid_to_utf8 (g_bytes_get_data (ssid, NULL),
		                                  g_bytes_get_size (ssid));
	}

	return ssid_str;
}

static char *
nmc_property_wireless_get_mtu (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingWireless *s_wireless = NM_SETTING_WIRELESS (setting);
	int mtu;

	mtu = nm_setting_wireless_get_mtu (s_wireless);
	if (mtu == 0)
		return g_strdup (_("auto"));
	else
		return g_strdup_printf ("%d", mtu);
}

static char *
nmc_property_wireless_get_powersave (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingWireless *s_wireless = NM_SETTING_WIRELESS (setting);
	guint powersave = nm_setting_wireless_get_powersave (s_wireless);

	if (powersave == 0)
		return g_strdup (_("no"));
	else if (powersave == 1)
		return g_strdup (_("yes"));
	else
		return g_strdup_printf (_("yes (%u)"), powersave);
}

/* --- NM_SETTING_WIRELESS_SECURITY_SETTING_NAME property get functions --- */
DEFINE_GETTER (nmc_property_wifi_sec_get_key_mgmt, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT)
DEFINE_GETTER (nmc_property_wifi_sec_get_wep_tx_keyidx, NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX)
DEFINE_GETTER (nmc_property_wifi_sec_get_auth_alg, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG)
DEFINE_GETTER (nmc_property_wifi_sec_get_proto, NM_SETTING_WIRELESS_SECURITY_PROTO)
DEFINE_GETTER (nmc_property_wifi_sec_get_pairwise, NM_SETTING_WIRELESS_SECURITY_PAIRWISE)
DEFINE_GETTER (nmc_property_wifi_sec_get_group, NM_SETTING_WIRELESS_SECURITY_GROUP)
DEFINE_GETTER (nmc_property_wifi_sec_get_leap_username, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME)
DEFINE_SECRET_FLAGS_GETTER (nmc_property_wifi_sec_get_wep_key_flags, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS)
DEFINE_GETTER (nmc_property_wifi_sec_get_psk, NM_SETTING_WIRELESS_SECURITY_PSK)
DEFINE_SECRET_FLAGS_GETTER (nmc_property_wifi_sec_get_psk_flags, NM_SETTING_WIRELESS_SECURITY_PSK_FLAGS)
DEFINE_GETTER (nmc_property_wifi_sec_get_leap_password, NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD)
DEFINE_SECRET_FLAGS_GETTER (nmc_property_wifi_sec_get_leap_password_flags, NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS)

static char *
nmc_property_wifi_sec_get_wep_key0 (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingWirelessSecurity *s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (setting);
	return g_strdup (nm_setting_wireless_security_get_wep_key (s_wireless_sec, 0));
}

static char *
nmc_property_wifi_sec_get_wep_key1 (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingWirelessSecurity *s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (setting);
	return g_strdup (nm_setting_wireless_security_get_wep_key (s_wireless_sec, 1));
}

static char *
nmc_property_wifi_sec_get_wep_key2 (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingWirelessSecurity *s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (setting);
	return g_strdup (nm_setting_wireless_security_get_wep_key (s_wireless_sec, 2));
}

static char *
nmc_property_wifi_sec_get_wep_key3 (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingWirelessSecurity *s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (setting);
	return g_strdup (nm_setting_wireless_security_get_wep_key (s_wireless_sec, 3));
}

static char *
nmc_property_wifi_sec_get_wep_key_type (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingWirelessSecurity *s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (setting);
	return wep_key_type_to_string (nm_setting_wireless_security_get_wep_key_type (s_wireless_sec));
}

/*----------------------------------------------------------------------------*/

static void
nmc_value_transform_bool_string (const GValue *src_value,
                                 GValue       *dest_value)
{
	dest_value->data[0].v_pointer = g_strdup (src_value->data[0].v_int ? "yes" : "no");
}

static void
nmc_value_transform_char_string (const GValue *src_value,
                                 GValue       *dest_value)
{
	dest_value->data[0].v_pointer = g_strdup_printf ("%c", src_value->data[0].v_uint);
}

static void __attribute__((constructor))
register_nmcli_value_transforms (void)
{
	g_value_register_transform_func (G_TYPE_BOOLEAN, G_TYPE_STRING, nmc_value_transform_bool_string);
	g_value_register_transform_func (G_TYPE_CHAR, G_TYPE_STRING, nmc_value_transform_char_string);
}

/*----------------------------------------------------------------------------*/

/* Main hash table storing function pointer for manipulating properties */
static GHashTable *nmc_properties = NULL;
typedef	char *        (*NmcPropertyGetFunc)      (NMSetting *, NmcPropertyGetType);
typedef	gboolean      (*NmcPropertySetFunc)      (NMSetting *, const char *, const char *, GError **);
typedef	gboolean      (*NmcPropertyRemoveFunc)   (NMSetting *, const char *, const char *, guint32, GError **);
typedef	const char *  (*NmcPropertyDescribeFunc) (NMSetting *, const char *);
typedef	const char ** (*NmcPropertyValuesFunc)   (NMSetting *, const char *);

typedef struct {
	/* The order of the fields is important as they correspond
	 * to the order as _nmc_add_prop_funcs() passes the arguments. */
#define NmcPropertyFuncsFields \
	NmcPropertyGetFunc get_func;           /* func getting property values */ \
	NmcPropertySetFunc set_func;           /* func adding/setting property values */ \
	NmcPropertyRemoveFunc remove_func;     /* func removing items from container options */ \
	NmcPropertyDescribeFunc describe_func; /* func returning property description */ \
	NmcPropertyValuesFunc values_func;     /* func returning allowed property values */ \
	;
	NmcPropertyFuncsFields
} NmcPropertyFuncs;

/*
 * We need NmCli in some _set_property functions, and they aren't passed NmCli.
 * So use the global variable.
 */
/* Global variable defined in nmcli.c */
extern NmCli nm_cli;

NMSetting *
nmc_setting_new_for_name (const char *name)
{
	GType stype;
	NMSetting *setting = NULL;

	if (name) {
		stype = nm_setting_lookup_type (name);
		if (stype != G_TYPE_INVALID) {
			setting = g_object_new (stype, NULL);
			g_warn_if_fail (NM_IS_SETTING (setting));
		}
	}
	return setting;
}

static gboolean
get_answer (const char *prop, const char *value)
{
	char *tmp_str;
	char *question;
	gboolean answer = FALSE;

	if (value)
		question = g_strdup_printf (_("Do you also want to set '%s' to '%s'? [yes]: "), prop, value);
	else
		question = g_strdup_printf (_("Do you also want to clear '%s'? [yes]: "), prop);
	tmp_str = nmc_get_user_input (question);
	if (!tmp_str || matches (tmp_str, "yes") == 0)
		answer = TRUE;
	g_free (tmp_str);
	g_free (question);
	return answer;
}

static void ipv4_method_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data);
static void ipv6_method_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data);

static void
ipv4_addresses_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	static gboolean answered = FALSE;
	static gboolean answer = FALSE;

	g_signal_handlers_block_by_func (object, G_CALLBACK (ipv4_method_changed_cb), NULL);

	/* If we have some IP addresses set method to 'manual'.
	 * Else if the method was 'manual', change it back to 'auto'.
	 */
	if (nm_setting_ip_config_get_num_addresses (NM_SETTING_IP_CONFIG (object))) {
		if (g_strcmp0 (nm_setting_ip_config_get_method (NM_SETTING_IP_CONFIG (object)), NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
			if (!answered) {
				answered = TRUE;
				answer = get_answer ("ipv4.method", "manual");
			}
			if (answer)
				g_object_set (object, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL, NULL);
		}
	} else {
		answered = FALSE;
		if (!g_strcmp0 (nm_setting_ip_config_get_method (NM_SETTING_IP_CONFIG (object)), NM_SETTING_IP4_CONFIG_METHOD_MANUAL))
			g_object_set (object, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);
	}

	g_signal_handlers_unblock_by_func (object, G_CALLBACK (ipv4_method_changed_cb), NULL);
}

static void
ipv4_method_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	static GValue value = G_VALUE_INIT;
	static gboolean answered = FALSE;
	static gboolean answer = FALSE;

	g_signal_handlers_block_by_func (object, G_CALLBACK (ipv4_addresses_changed_cb), NULL);

	/* If method != manual, remove addresses (save them for restoring them later when method becomes 'manual' */
	if (g_strcmp0 (nm_setting_ip_config_get_method (NM_SETTING_IP_CONFIG (object)), NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
		if (nm_setting_ip_config_get_num_addresses (NM_SETTING_IP_CONFIG (object))) {
			if (!answered) {
				answered = TRUE;
				answer = get_answer ("ipv4.addresses", NULL);
			}
			if (answer) {
				if (G_IS_VALUE (&value))
					g_value_unset (&value);
				nmc_property_get_gvalue (NM_SETTING (object), NM_SETTING_IP_CONFIG_ADDRESSES, &value);
				g_object_set (object, NM_SETTING_IP_CONFIG_ADDRESSES, NULL, NULL);
			}
		}
	} else {
		answered = FALSE;
		if (G_IS_VALUE (&value)) {
			nmc_property_set_gvalue (NM_SETTING (object), NM_SETTING_IP_CONFIG_ADDRESSES, &value);
			g_value_unset (&value);
		}
	}

	g_signal_handlers_unblock_by_func (object, G_CALLBACK (ipv4_addresses_changed_cb), NULL);
}

static void
ipv6_addresses_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	static gboolean answered = FALSE;
	static gboolean answer = FALSE;

	g_signal_handlers_block_by_func (object, G_CALLBACK (ipv6_method_changed_cb), NULL);

	/* If we have some IP addresses set method to 'manual'.
	 * Else if the method was 'manual', change it back to 'auto'.
	 */
	if (nm_setting_ip_config_get_num_addresses (NM_SETTING_IP_CONFIG (object))) {
		if (g_strcmp0 (nm_setting_ip_config_get_method (NM_SETTING_IP_CONFIG (object)), NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
			if (!answered) {
				answered = TRUE;
				answer = get_answer ("ipv6.method", "manual");
			}
			if (answer)
				g_object_set (object, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL, NULL);
		}
	} else {
		answered = FALSE;
		if (!g_strcmp0 (nm_setting_ip_config_get_method (NM_SETTING_IP_CONFIG (object)), NM_SETTING_IP6_CONFIG_METHOD_MANUAL))
			g_object_set (object, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO, NULL);
	}

	g_signal_handlers_unblock_by_func (object, G_CALLBACK (ipv6_method_changed_cb), NULL);
}

static void
ipv6_method_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	static GValue value = G_VALUE_INIT;
	static gboolean answered = FALSE;
	static gboolean answer = FALSE;

	g_signal_handlers_block_by_func (object, G_CALLBACK (ipv6_addresses_changed_cb), NULL);

	/* If method != manual, remove addresses (save them for restoring them later when method becomes 'manual' */
	if (g_strcmp0 (nm_setting_ip_config_get_method (NM_SETTING_IP_CONFIG (object)), NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		if (nm_setting_ip_config_get_num_addresses (NM_SETTING_IP_CONFIG (object))) {
			if (!answered) {
				answered = TRUE;
				answer = get_answer ("ipv6.addresses", NULL);
			}
			if (answer) {
				if (G_IS_VALUE (&value))
					g_value_unset (&value);
				nmc_property_get_gvalue (NM_SETTING (object), NM_SETTING_IP_CONFIG_ADDRESSES, &value);
				g_object_set (object, NM_SETTING_IP_CONFIG_ADDRESSES, NULL, NULL);
			}
		}
	} else {
		answered = FALSE;
		if (G_IS_VALUE (&value)) {
			nmc_property_set_gvalue (NM_SETTING (object), NM_SETTING_IP_CONFIG_ADDRESSES, &value);
			g_value_unset (&value);
		}
	}

	g_signal_handlers_unblock_by_func (object, G_CALLBACK (ipv6_addresses_changed_cb), NULL);
}

static void
wireless_band_channel_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	const char *value = NULL, *mode;
	char str[16];
	NMSettingWireless *s_wireless = NM_SETTING_WIRELESS (object);

	if (strcmp (g_param_spec_get_name (pspec), NM_SETTING_WIRELESS_BAND) == 0) {
		value = nm_setting_wireless_get_band (s_wireless);
		if (!value)
			return;
	} else {
		guint32 channel = nm_setting_wireless_get_channel (s_wireless);

		if (channel == 0)
			return;

		g_snprintf (str, sizeof (str), "%d", nm_setting_wireless_get_channel (s_wireless));
		value = str;
	}

	mode = nm_setting_wireless_get_mode (NM_SETTING_WIRELESS (object));
	if (!mode || !*mode || strcmp (mode, NM_SETTING_WIRELESS_MODE_INFRA) == 0) {
		g_print (_("Warning: %s.%s set to '%s', but it might be ignored in infrastructure mode\n"),
		         nm_setting_get_name (NM_SETTING (s_wireless)), g_param_spec_get_name (pspec),
		         value);
	}
}

static void
connection_master_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	NMSettingConnection *s_con = NM_SETTING_CONNECTION (object);
	NMConnection *connection = NM_CONNECTION (user_data);
	NMSetting *s_ipv4, *s_ipv6;
	const char *value, *tmp_str;

	value = nm_setting_connection_get_master (s_con);
	if (value) {
		s_ipv4 = nm_connection_get_setting_by_name (connection, NM_SETTING_IP4_CONFIG_SETTING_NAME);
		s_ipv6 = nm_connection_get_setting_by_name (connection, NM_SETTING_IP6_CONFIG_SETTING_NAME);
		if (s_ipv4 || s_ipv6) {
			g_print (_("Warning: setting %s.%s requires removing ipv4 and ipv6 settings\n"),
			         nm_setting_get_name (NM_SETTING (s_con)), g_param_spec_get_name (pspec));
			tmp_str = nmc_get_user_input (_("Do you want to remove them? [yes] "));
			if (!tmp_str || matches (tmp_str, "yes") == 0) {
				if (s_ipv4)
					nm_connection_remove_setting (connection, G_OBJECT_TYPE (s_ipv4));
				if (s_ipv6)
					nm_connection_remove_setting (connection, G_OBJECT_TYPE (s_ipv6));
			}
		}
	}
}

void
nmc_setting_ip4_connect_handlers (NMSettingIPConfig *setting)
{
	g_return_if_fail (NM_IS_SETTING_IP4_CONFIG (setting));

	g_signal_connect (setting, "notify::" NM_SETTING_IP_CONFIG_ADDRESSES,
	                  G_CALLBACK (ipv4_addresses_changed_cb), NULL);
	g_signal_connect (setting, "notify::" NM_SETTING_IP_CONFIG_METHOD,
	                  G_CALLBACK (ipv4_method_changed_cb), NULL);
}

void
nmc_setting_ip6_connect_handlers (NMSettingIPConfig *setting)
{
	g_return_if_fail (NM_IS_SETTING_IP6_CONFIG (setting));

	g_signal_connect (setting, "notify::" NM_SETTING_IP_CONFIG_ADDRESSES,
	                  G_CALLBACK (ipv6_addresses_changed_cb), NULL);
	g_signal_connect (setting, "notify::" NM_SETTING_IP_CONFIG_METHOD,
	                  G_CALLBACK (ipv6_method_changed_cb), NULL);
}

void
nmc_setting_wireless_connect_handlers (NMSettingWireless *setting)
{
	g_return_if_fail (NM_IS_SETTING_WIRELESS (setting));

	g_signal_connect (setting, "notify::" NM_SETTING_WIRELESS_BAND,
	                  G_CALLBACK (wireless_band_channel_changed_cb), NULL);
	g_signal_connect (setting, "notify::" NM_SETTING_WIRELESS_CHANNEL,
	                  G_CALLBACK (wireless_band_channel_changed_cb), NULL);
}

void
nmc_setting_connection_connect_handlers (NMSettingConnection *setting, NMConnection *connection)
{
	g_return_if_fail (NM_IS_SETTING_CONNECTION (setting));

	g_signal_connect (setting, "notify::" NM_SETTING_CONNECTION_MASTER,
	                  G_CALLBACK (connection_master_changed_cb), connection);
}

/*
 * Customize some properties of the setting so that the setting has sensible
 * values.
 */
void
nmc_setting_custom_init (NMSetting *setting)
{
	g_return_if_fail (NM_IS_SETTING (setting));

	if (NM_IS_SETTING_IP4_CONFIG (setting)) {
		g_object_set (NM_SETTING_IP_CONFIG (setting),
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
		              NULL);
		nmc_setting_ip4_connect_handlers (NM_SETTING_IP_CONFIG (setting));
	} else if (NM_IS_SETTING_IP6_CONFIG (setting)) {
		g_object_set (NM_SETTING_IP_CONFIG (setting),
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
		              NULL);
		nmc_setting_ip6_connect_handlers (NM_SETTING_IP_CONFIG (setting));
	} else if (NM_IS_SETTING_WIRELESS (setting)) {
		g_object_set (NM_SETTING_WIRELESS (setting),
		              NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA,
		              NULL);
		nmc_setting_wireless_connect_handlers (NM_SETTING_WIRELESS (setting));
	}
}

/* === SetFunc, RemoveFunc, DescribeFunc, ValuesFunc functions === */
static gboolean
verify_string_list (char **strv,
                    const char *prop,
                    gboolean (*validate_func) (const char *),
                    GError **error)
{
	char **iter;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	for (iter = strv; iter && *iter; iter++) {
		if (**iter == '\0')
			continue;
		if (validate_func) {
			if (!validate_func (*iter)) {
				g_set_error (error, 1, 0, _("'%s' is not valid"),
				             *iter);
				return FALSE;
			}
		}
	}
	return TRUE;
}

/* Validate 'val' number against to int property spec */
static gboolean
validate_int (NMSetting *setting, const char* prop, gint val, GError **error)
{
	GParamSpec *pspec;
	GValue value = G_VALUE_INIT;
	gboolean success = TRUE;

	g_value_init (&value, G_TYPE_INT);
	g_value_set_int (&value, val);
	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (setting)), prop);
	g_assert (G_IS_PARAM_SPEC (pspec));
	if (g_param_value_validate (pspec, &value)) {
		GParamSpecInt *pspec_int = (GParamSpecInt *) pspec;
		g_set_error (error, 1, 0, _("'%d' is not valid; use <%d-%d>"),
		             val, pspec_int->minimum, pspec_int->maximum);
		success = FALSE;
	}
	g_value_unset (&value);
	return success;
}

static gboolean
validate_int64 (NMSetting *setting, const char* prop, gint64 val, GError **error)
{
	GParamSpec *pspec;
	GValue value = G_VALUE_INIT;
	gboolean success = TRUE;

	g_value_init (&value, G_TYPE_INT64);
	g_value_set_int64 (&value, val);
	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (setting)), prop);
	g_assert (G_IS_PARAM_SPEC (pspec));
	if (g_param_value_validate (pspec, &value)) {
		GParamSpecInt64 *pspec_int = (GParamSpecInt64 *) pspec;
		G_STATIC_ASSERT (sizeof (long long) >= sizeof (gint64));
		g_set_error (error, 1, 0, _("'%lld' is not valid; use <%lld-%lld>"),
		             (long long) val, (long long) pspec_int->minimum, (long long) pspec_int->maximum);
		success = FALSE;
	}
	g_value_unset (&value);
	return success;
}

/* Validate 'val' number against to uint property spec */
static gboolean
validate_uint (NMSetting *setting, const char* prop, guint val, GError **error)
{
	GParamSpec *pspec;
	GValue value = G_VALUE_INIT;
	gboolean success = TRUE;

	g_value_init (&value, G_TYPE_UINT);
	g_value_set_uint (&value, val);
	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (setting)), prop);
	g_assert (G_IS_PARAM_SPEC (pspec));
	if (g_param_value_validate (pspec, &value)) {
		GParamSpecUInt *pspec_uint = (GParamSpecUInt *) pspec;
		g_set_error (error, 1, 0, _("'%u' is not valid; use <%u-%u>"),
		             val, pspec_uint->minimum, pspec_uint->maximum);
		success = FALSE;
	}
	g_value_unset (&value);
	return success;
}

static gboolean
check_and_set_string (NMSetting *setting,
                      const char *prop,
                      const char *val,
                      const char **valid_strv,
                      GError **error)
{
	const char *checked_val;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	checked_val = nmc_string_is_valid (val, valid_strv, error);
	if (!checked_val)
		return FALSE;

	g_object_set (setting, prop, checked_val, NULL);
	return TRUE;
}

#define DEFINE_SETTER_STR_LIST_MULTI(def_func, s_macro, set_func) \
	static gboolean \
	def_func (NMSetting *setting, \
	          const char *prop, \
	          const char *val, \
	          const char **valid_strv, \
	          GError **error) \
	{ \
		char **strv = NULL, **iter; \
		const char *item; \
		g_return_val_if_fail (error == NULL || *error == NULL, FALSE); \
		strv = nmc_strsplit_set (val, " \t,", 0); \
		for (iter = strv; iter && *iter; iter++) { \
			if (!(item = nmc_string_is_valid (g_strstrip (*iter), valid_strv, error))) { \
				g_strfreev (strv); \
				return FALSE; \
			} \
			set_func (s_macro (setting), item); \
		} \
		g_strfreev (strv); \
		return TRUE; \
	}

#define DEFINE_SETTER_OPTIONS(def_func, s_macro, s_type, add_func, valid_func1, valid_func2) \
	static gboolean \
	def_func (NMSetting *setting, const char *prop, const char *val, GError **error) \
	{ \
		char **strv = NULL, **iter; \
		const char **(*valid_func1_p) (s_type *) = valid_func1; \
		const char * (*valid_func2_p) (const char *, const char *, GError **) = valid_func2; \
		const char *opt_name, *opt_val; \
		\
		g_return_val_if_fail (error == NULL || *error == NULL, FALSE); \
		\
		strv = nmc_strsplit_set (val, ",", 0); \
		for (iter = strv; iter && *iter; iter++) { \
			char *left = g_strstrip (*iter); \
			char *right = strchr (left, '='); \
			if (!right) { \
				g_set_error (error, 1, 0, _("'%s' is not valid; use <option>=<value>"), *iter); \
				g_strfreev (strv); \
				return FALSE; \
			} \
			*right++ = '\0'; \
			\
			if (valid_func1_p) { \
				const char **valid_options = valid_func1_p (s_macro (setting)); \
				if (!(opt_name = nmc_string_is_valid (g_strstrip (left), valid_options, error))) { \
					g_strfreev (strv); \
					return FALSE; \
				} \
			} else \
				opt_name = g_strstrip (left);\
			\
			opt_val = g_strstrip (right); \
			if (valid_func2_p) { \
				if (!(opt_val = valid_func2_p ((const char *) left, (const char *) opt_val, error))) { \
					g_strfreev (strv); \
					return FALSE; \
				}\
			}\
			add_func (s_macro (setting), opt_name, opt_val); \
		} \
		g_strfreev (strv); \
		return TRUE; \
	}

#define DEFINE_REMOVER_INDEX(def_func, s_macro, num_func, rem_func) \
	static gboolean \
	def_func (NMSetting *setting, const char *prop, const char *option, guint32 idx, GError **error) \
	{ \
		guint32 num; \
		if (option) { \
			g_set_error (error, 1, 0, _("index '%s' is not valid"), option); \
			return FALSE; \
		} \
		num = num_func (s_macro (setting)); \
		if (num == 0) { \
			g_set_error_literal (error, 1, 0, _("no item to remove")); \
			return FALSE; \
		} \
		if (idx >= num) { \
			g_set_error (error, 1, 0, _("index '%d' is not in range <0-%d>"), idx, num - 1); \
			return FALSE; \
		} \
		rem_func (s_macro (setting), idx); \
		return TRUE; \
	}

#define DEFINE_REMOVER_INDEX_OR_VALUE(def_func, s_macro, num_func, rem_func_idx, rem_func_val) \
	static gboolean \
	def_func (NMSetting *setting, const char *prop, const char *value, guint32 idx, GError **error) \
	{ \
		guint32 num; \
		if (value) { \
			gboolean ret; \
			char *value_stripped = g_strstrip (g_strdup (value)); \
			ret = rem_func_val (s_macro (setting), value_stripped, error); \
			g_free (value_stripped); \
			return ret; \
		} \
		num = num_func (s_macro (setting)); \
		if (num == 0) { \
			g_set_error_literal (error, 1, 0, _("no item to remove")); \
			return FALSE; \
		} \
		if (idx >= num) { \
			g_set_error (error, 1, 0, _("index '%d' is not in range <0-%d>"), idx, num - 1); \
			return FALSE; \
		} \
		rem_func_idx (s_macro (setting), idx); \
		return TRUE; \
	}

#define DEFINE_REMOVER_OPTION(def_func, s_macro, rem_func) \
	static gboolean \
	def_func (NMSetting *setting, const char *prop, const char *option, guint32 idx, GError **error) \
	{ \
		gboolean success = FALSE; \
		if (option && *option) { \
			success = rem_func (s_macro (setting), option); \
			if (!success) \
				g_set_error (error, 1, 0, _("invalid option '%s'"), option); \
		} else \
			g_set_error_literal (error, 1, 0, _("missing option")); \
		return success; \
	}

#define DEFINE_ALLOWED_VAL_FUNC(def_func, valid_values) \
	static const char ** \
	def_func (NMSetting *setting, const char *prop) \
	{ \
		return valid_values; \
	}

/* --- generic property setter functions --- */
static gboolean
nmc_property_set_string (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	g_object_set (setting, prop, val, NULL);
	return TRUE;
}

static gboolean
nmc_property_set_uint (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	unsigned long val_int;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_uint (val, TRUE, 0, G_MAXUINT, &val_int)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid number (or out of range)"), val);
		return FALSE;
	}

	/* Validate the number according to the property spec */
	if (!validate_uint (setting, prop, (guint) val_int, error))
		return FALSE;

	g_object_set (setting, prop, (guint) val_int, NULL);
	return TRUE;
}

static gboolean
nmc_property_set_int (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	long int val_int;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_int (val, TRUE, G_MININT, G_MAXINT, &val_int)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid number (or out of range)"), val);
		return FALSE;
	}

	/* Validate the number according to the property spec */
	if (!validate_int (setting, prop, (gint) val_int, error))
		return FALSE;

	g_object_set (setting, prop, (gint) val_int, NULL);
	return TRUE;
}

static gboolean
nmc_property_set_int64 (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	long val_int;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_int (val, FALSE, 0, 0, &val_int)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid number (or out of range)"), val);
		return FALSE;
	}

	/* Validate the number according to the property spec */
	if (!validate_int64 (setting, prop, (gint64) val_int, error))
		return FALSE;

	g_object_set (setting, prop, (gint64) val_int, NULL);
	return TRUE;
}

static gboolean
nmc_property_set_bool (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	gboolean val_bool;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_bool (val, &val_bool, error))
		return FALSE;

	g_object_set (setting, prop, val_bool, NULL);
	return TRUE;
}

static gboolean
nmc_property_set_ssid (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	GBytes *ssid;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (strlen (val) > 32) {
		g_set_error (error, 1, 0, _("'%s' is not valid"), val);
		return FALSE;
	}

	ssid = g_bytes_new (val, strlen (val));
	g_object_set (setting, prop, ssid, NULL);
	g_bytes_unref (ssid);
	return TRUE;
}

static gboolean
nmc_property_set_mac (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nm_utils_hwaddr_valid (val, ETH_ALEN)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid Ethernet MAC"), val);
		return FALSE;
	}

	g_object_set (setting, prop, val, NULL);
	return TRUE;
}

static gboolean
nmc_property_set_mtu (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	const char *mtu = val;

	if (strcmp (mtu, "auto") == 0)
		mtu = "0";

	return nmc_property_set_uint (setting, prop, mtu, error);
}

static gboolean
nmc_property_set_ifname (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nm_utils_iface_valid_name (val)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid interface name"), val);
		return FALSE;
	}
	g_object_set (setting, prop, val, NULL);
	return TRUE;
}

#define ALL_SECRET_FLAGS \
	(NM_SETTING_SECRET_FLAG_NONE | \
	 NM_SETTING_SECRET_FLAG_AGENT_OWNED | \
	 NM_SETTING_SECRET_FLAG_NOT_SAVED | \
	 NM_SETTING_SECRET_FLAG_NOT_REQUIRED)

static gboolean
nmc_property_set_secret_flags (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL, **iter;
	unsigned long flags = 0, val_int;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (val, " \t,", 0);
	for (iter = strv; iter && *iter; iter++) {
		if (!nmc_string_to_uint (*iter, TRUE, 0, ALL_SECRET_FLAGS, &val_int)) {
			g_set_error (error, 1, 0, _("'%s' is not a valid flag number; use <0-%d>"),
			             *iter, ALL_SECRET_FLAGS);
			g_strfreev (strv);
			return FALSE;
		}
		flags += val_int;
	}
	g_strfreev (strv);

	/* Validate the flags number */
	if (flags > ALL_SECRET_FLAGS) {
		flags = ALL_SECRET_FLAGS;
		g_print (_("Warning: '%s' sum is higher than all flags => all flags set\n"), val);
	}

	g_object_set (setting, prop, (guint) flags, NULL);
	return TRUE;
}

static gboolean
nmc_util_is_domain (const char *domain)
{
	//FIXME: implement
	return TRUE;
}

static gboolean
nmc_property_set_byte_array (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL, **iter;
	char *val_strip;
	const char *delimiters = " \t,";
	long int val_int;
	GBytes *bytes;
	GByteArray *array = NULL;
	gboolean success = TRUE;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	val_strip = g_strstrip (g_strdup (val));

	/* First try hex string in the format of AAbbCCDd */
	bytes = nm_utils_hexstr2bin (val_strip);
	if (bytes) {
		array = g_bytes_unref_to_array (bytes);
		goto done;
	}

	/* Otherwise, consider the following format: AA b 0xCc D */
	strv = nmc_strsplit_set (val_strip, delimiters, 0);
	array = g_byte_array_sized_new (g_strv_length (strv));
	for (iter = strv; iter && *iter; iter++) {
		if (!nmc_string_to_int_base (g_strstrip (*iter), 16, TRUE, 0, 255, &val_int)) {
			g_set_error (error, 1, 0, _("'%s' is not a valid hex character"), *iter);
			success = FALSE;
			goto done;
		}
		g_byte_array_append (array, (const guint8 *) &val_int, 1);
	}

done:
	if (success)
		g_object_set (setting, prop, array, NULL);

	g_strfreev (strv);
	if (array)
		g_byte_array_free (array, TRUE);
	return success;
}

#define DEFINE_SETTER_MAC_BLACKLIST(def_func, s_macro, add_func) \
	static gboolean \
	def_func (NMSetting *setting, const char *prop, const char *val, GError **error) \
	{ \
		guint8 buf[32]; \
		char **list = NULL, **iter; \
		GSList *macaddr_blacklist = NULL; \
		\
		g_return_val_if_fail (error == NULL || *error == NULL, FALSE); \
		\
		list = nmc_strsplit_set (val, " \t,", 0); \
		for (iter = list; iter && *iter; iter++) { \
			if (!nm_utils_hwaddr_aton (*iter, buf, ETH_ALEN)) { \
				g_set_error (error, 1, 0, _("'%s' is not a valid MAC"), *iter); \
				g_strfreev (list); \
				g_slist_free (macaddr_blacklist); \
				return FALSE; \
			} \
		} \
		\
		for (iter = list; iter && *iter; iter++) \
			add_func (s_macro (setting), *iter); \
		\
		g_strfreev (list); \
		return TRUE; \
	}

/* --- NM_SETTING_CONNECTION_SETTING_NAME property setter functions --- */
#if 0
/*
 * Setting/removing UUID has been forbidden.
 * Should it be enabled later, this function can be used.
 */
static gboolean
nmc_property_con_set_uuid (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nm_utils_is_uuid (val)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid UUID"), val);
		return FALSE;
	}
	g_object_set (setting, prop, val, NULL);
	return TRUE;
}
#endif

/* 'permissions' */
/* define from libnm-core/nm-setting-connection.c */
#define PERM_USER_PREFIX  "user:"

static gboolean
permissions_valid (const char *perm)
{
	if (!perm || perm[0] == '\0')
		return FALSE;

	if (strncmp (perm, PERM_USER_PREFIX, strlen (PERM_USER_PREFIX)) == 0) {
		if (   strlen (perm) <= strlen (PERM_USER_PREFIX)
		    || strchr (perm + strlen (PERM_USER_PREFIX), ':'))
			return  FALSE;
	} else {
		if (strchr (perm, ':'))
			return  FALSE;
	}

	return TRUE;
}

static gboolean
nmc_property_connection_set_permissions (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL;
	guint i = 0;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (val, " \t,", 0);
	if (!verify_string_list (strv, prop, permissions_valid, error)) {
		g_strfreev (strv);
		return FALSE;
	}

	for (i = 0; strv && strv[i]; i++) {
		const char *user;

		if (strncmp (strv[i], PERM_USER_PREFIX, strlen (PERM_USER_PREFIX)) == 0)
			user = strv[i]+strlen (PERM_USER_PREFIX);
		else
			user = strv[i];

		nm_setting_connection_add_permission (NM_SETTING_CONNECTION (setting), "user", user, NULL);
	}

	return TRUE;
}

static gboolean
_validate_and_remove_connection_permission (NMSettingConnection *setting,
                                            const char *perm,
                                            GError **error)
{
	gboolean ret;

	ret = nm_setting_connection_remove_permission_by_value (setting, "user", perm, NULL);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain permission '%s'"), perm);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_connection_remove_permissions,
                               NM_SETTING_CONNECTION,
                               nm_setting_connection_get_num_permissions,
                               nm_setting_connection_remove_permission,
                               _validate_and_remove_connection_permission)

static const char *
nmc_property_connection_describe_permissions (NMSetting *setting, const char *prop)
{
	return _("Enter a list of user permissions. This is a list of user names formatted as:\n"
	         "  [user:]<user name 1>, [user:]<user name 2>,...\n"
	         "The items can be separated by commas or spaces.\n\n"
	         "Example: alice bob charlie\n");
}

/* 'master' */
static gboolean
nmc_property_con_set_master (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!val)
		;
	else if (!*val)
		val = NULL;
	else if (   !nm_utils_iface_valid_name (val)
	         && !nm_utils_is_uuid (val)) {
		g_set_error (error, 1, 0,
		             _("'%s' is not valid master; use ifname or connection UUID"),
		             val);
		return FALSE;
	}
	g_object_set (setting, prop, val, NULL);
	return TRUE;
}

/* 'slave-type' */
static const char *con_valid_slave_types[] = {
	NM_SETTING_BOND_SETTING_NAME,
	NM_SETTING_BRIDGE_SETTING_NAME,
	NM_SETTING_TEAM_SETTING_NAME,
	NULL
};

static gboolean
nmc_property_con_set_slave_type (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, con_valid_slave_types, error);
}


DEFINE_ALLOWED_VAL_FUNC (nmc_property_con_allowed_slave_type, con_valid_slave_types)

/* 'secondaries' */
static gboolean
nmc_property_connection_set_secondaries (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	NMConnection *con;
	char **strv = NULL, **iter;
	guint i = 0;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (val, " \t,", 0);
	for (iter = strv; iter && *iter; iter++) {
		if (**iter == '\0')
			continue;

		if (nm_utils_is_uuid (*iter)) {
			con = nmc_find_connection (nm_cli.connections,
			                           "uuid", *iter, NULL);
			if (!con)
				g_print (_("Warning: %s is not an UUID of any existing connection profile\n"), *iter);
			else {
				/* Currenly NM only supports VPN connections as secondaries */
				if (!nm_connection_is_type (con, NM_SETTING_VPN_SETTING_NAME)) {
					g_set_error (error, 1, 0, _("'%s' is not a VPN connection profile"), *iter);
					g_strfreev (strv);
					return FALSE;
				}
			}
		} else {
			con = nmc_find_connection (nm_cli.connections,
			                           "id", *iter, NULL);
			if (!con) {
				g_set_error (error, 1, 0, _("'%s' is not a name of any exiting profile"), *iter);
				g_strfreev (strv);
				return FALSE;
			}

			/* Currenly NM only supports VPN connections as secondaries */
			if (!nm_connection_is_type (con, NM_SETTING_VPN_SETTING_NAME)) {
				g_set_error (error, 1, 0, _("'%s' is not a VPN connection profile"), *iter);
				g_strfreev (strv);
				return FALSE;
			}

			/* translate id to uuid */
			g_free (*iter);
			*iter = g_strdup (nm_connection_get_uuid (con));
		}
	}

	while (strv && strv[i])
		nm_setting_connection_add_secondary (NM_SETTING_CONNECTION (setting), strv[i++]);
	g_strfreev (strv);

	return TRUE;
}

static gboolean
_validate_and_remove_connection_secondary (NMSettingConnection *setting,
                                           const char *secondary_uuid,
                                           GError **error)
{
	gboolean ret;

	if (!nm_utils_is_uuid (secondary_uuid)) {
		g_set_error (error, 1, 0,
		             _("the value '%s' is not a valid UUID"), secondary_uuid);
		return FALSE;
	}

	ret = nm_setting_connection_remove_secondary_by_value (setting, secondary_uuid);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain UUID '%s'"), secondary_uuid);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_connection_remove_secondaries,
                               NM_SETTING_CONNECTION,
                               nm_setting_connection_get_num_secondaries,
                               nm_setting_connection_remove_secondary,
                               _validate_and_remove_connection_secondary)

static const char *
nmc_property_connection_describe_secondaries (NMSetting *setting, const char *prop)
{
	return _("Enter secondary connections that should be activated when this connection is\n"
	         "activated. Connections can be specified either by UUID or ID (name). nmcli\n"
	         "transparently translates names to UUIDs. Note that NetworkManager only supports\n"
	         "VPNs as secondary connections at the moment.\n"
	         "The items can be separated by commas or spaces.\n\n"
	         "Example: private-openvpn, fe6ba5d8-c2fc-4aae-b2e3-97efddd8d9a7\n");
}

/* 'metered' */
static char *
nmc_property_connection_get_metered (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingConnection *s_conn = NM_SETTING_CONNECTION (setting);

	if (get_type == NMC_PROPERTY_GET_PARSABLE) {
		switch (nm_setting_connection_get_metered (s_conn)) {
		case NM_METERED_YES:
			return g_strdup ("yes");
		case NM_METERED_NO:
			return g_strdup ("no");
		case NM_METERED_UNKNOWN:
		default:
			return g_strdup ("unknown");
		}
	}
	switch (nm_setting_connection_get_metered (s_conn)) {
	case NM_METERED_YES:
		return g_strdup (_("yes"));
	case NM_METERED_NO:
		return g_strdup (_("no"));
	case NM_METERED_UNKNOWN:
	default:
		return g_strdup (_("unknown"));
	}
}

static gboolean
nmc_property_connection_set_metered (NMSetting *setting, const char *prop,
                                     const char *val, GError **error)
{
	NMMetered metered;
	NMCTriStateValue ts_val;

	if (!nmc_string_to_tristate (val, &ts_val, error))
		return FALSE;

	switch (ts_val) {
	case NMC_TRI_STATE_YES:
		metered = NM_METERED_YES;
		break;
	case NMC_TRI_STATE_NO:
		metered = NM_METERED_NO;
		break;
	case NMC_TRI_STATE_UNKNOWN:
		metered = NM_METERED_UNKNOWN;
		break;
	default:
		g_assert_not_reached();
	}

	g_object_set (setting, prop, metered, NULL);
	return TRUE;
}

/* --- NM_SETTING_802_1X_SETTING_NAME property setter functions --- */
#define DEFINE_SETTER_STR_LIST(def_func, set_func) \
	static gboolean \
	def_func (NMSetting *setting, const char *prop, const char *val, GError **error) \
	{ \
		char **strv = NULL; \
		guint i = 0; \
		\
		g_return_val_if_fail (error == NULL || *error == NULL, FALSE); \
		\
		strv = nmc_strsplit_set (val, " \t,", 0); \
		while (strv && strv[i]) \
			set_func (NM_SETTING_802_1X (setting), strv[i++]); \
		g_strfreev (strv); \
		return TRUE; \
	}

#define DEFINE_SETTER_CERT(def_func, set_func) \
	static gboolean \
	def_func (NMSetting *setting, const char *prop, const char *val, GError **error) \
	{ \
		char *val_strip = g_strstrip (g_strdup (val)); \
		char *p = val_strip; \
		gboolean success; \
		\
		if (strncmp (val_strip, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH, STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH)) == 0) \
			p += STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH); \
		\
		success = set_func (NM_SETTING_802_1X (setting), \
		                    p, \
		                    NM_SETTING_802_1X_CK_SCHEME_PATH, \
		                    NULL, \
		                    error); \
		g_free (val_strip); \
		return success; \
	}

#define DEFINE_SETTER_PRIV_KEY(def_func, pwd_func, set_func) \
	static gboolean \
	def_func (NMSetting *setting, const char *prop, const char *val, GError **error) \
	{ \
		char **strv = NULL; \
		char *val_strip = g_strstrip (g_strdup (val)); \
		char *p = val_strip; \
		const char *path, *password; \
		gboolean success; \
		\
		if (strncmp (val_strip, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH, STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH)) == 0) \
			p += STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH); \
		\
		strv = nmc_strsplit_set (p, " \t,", 2); \
		path = strv[0]; \
		if (g_strv_length (strv) == 2) \
			password = strv[1]; \
		else \
			password = pwd_func (NM_SETTING_802_1X (setting)); \
		if (password) { \
			char *tmp_pwd = g_strdup (password); \
			success = set_func (NM_SETTING_802_1X (setting), \
			                    path, \
			                    tmp_pwd, \
			                    NM_SETTING_802_1X_CK_SCHEME_PATH, \
			                    NULL, \
			                    error); \
			g_free (tmp_pwd); \
		} else { \
			success = FALSE; \
			g_set_error_literal  (error, 1, 0, _("private key password not provided")); \
		} \
		g_free (val_strip); \
		g_strfreev (strv); \
		return success; \
	}

/* 'eap' */
static const char *valid_eap[] = { "leap", "md5", "tls", "peap", "ttls", "sim", "fast", "pwd", NULL };

DEFINE_SETTER_STR_LIST_MULTI (check_and_add_802_1X_eap,
                              NM_SETTING_802_1X,
                              nm_setting_802_1x_add_eap_method)
static gboolean
nmc_property_802_1X_set_eap (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_add_802_1X_eap (setting, prop, val, valid_eap, error);
}

static gboolean
_validate_and_remove_eap_method (NMSetting8021x *setting,
                                 const char *eap,
                                 GError **error)
{
	gboolean ret;

	ret = nm_setting_802_1x_remove_eap_method_by_value(setting, eap);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain EAP method '%s'"), eap);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_802_1X_remove_eap,
                               NM_SETTING_802_1X,
                               nm_setting_802_1x_get_num_eap_methods,
                               nm_setting_802_1x_remove_eap_method,
                               _validate_and_remove_eap_method)

DEFINE_ALLOWED_VAL_FUNC (nmc_property_802_1X_allowed_eap, valid_eap)

/* 'ca-cert' */
DEFINE_SETTER_CERT (nmc_property_802_1X_set_ca_cert, nm_setting_802_1x_set_ca_cert)

static const char *
nmc_property_802_1X_describe_ca_cert (NMSetting *setting, const char *prop)
{
	return _("Enter file path to CA certificate (optionally prefixed with file://).\n"
	         "  [file://]<file path>\n"
	         "Note that nmcli does not support specifying certificates as raw blob data.\n"
	         "Example: /home/cimrman/cacert.crt\n");
}

/* 'altsubject-matches' */
DEFINE_SETTER_STR_LIST (nmc_property_802_1X_set_altsubject_matches, nm_setting_802_1x_add_altsubject_match)

static gboolean
_validate_and_remove_altsubject_match (NMSetting8021x *setting,
                                       const char *altsubject_match,
                                       GError **error)
{
	gboolean ret;

	ret = nm_setting_802_1x_remove_altsubject_match_by_value (setting, altsubject_match);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain alternative subject match '%s'"),
		             altsubject_match);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_802_1X_remove_altsubject_matches,
                               NM_SETTING_802_1X,
                               nm_setting_802_1x_get_num_altsubject_matches,
                               nm_setting_802_1x_remove_altsubject_match,
                               _validate_and_remove_altsubject_match)

/* 'client-cert' */
DEFINE_SETTER_CERT (nmc_property_802_1X_set_client_cert, nm_setting_802_1x_set_client_cert)

static const char *
nmc_property_802_1X_describe_client_cert (NMSetting *setting, const char *prop)
{
	return _("Enter file path to client certificate (optionally prefixed with file://).\n"
	         "  [file://]<file path>\n"
	         "Note that nmcli does not support specifying certificates as raw blob data.\n"
	         "Example: /home/cimrman/jara.crt\n");
}

/* 'phase2-ca-cert' */
DEFINE_SETTER_CERT (nmc_property_802_1X_set_phase2_ca_cert, nm_setting_802_1x_set_phase2_ca_cert)

static const char *
nmc_property_802_1X_describe_phase2_ca_cert (NMSetting *setting, const char *prop)
{
	return _("Enter file path to CA certificate for inner authentication (optionally prefixed\n"
	         "with file://).\n"
	         "  [file://]<file path>\n"
	         "Note that nmcli does not support specifying certificates as raw blob data.\n"
	         "Example: /home/cimrman/ca-zweite-phase.crt\n");
}

/* 'phase2-altsubject-matches' */
DEFINE_SETTER_STR_LIST (nmc_property_802_1X_set_phase2_altsubject_matches, nm_setting_802_1x_add_phase2_altsubject_match)

static gboolean
_validate_and_remove_phase2_altsubject_match (NMSetting8021x *setting,
                                              const char *phase2_altsubject_match,
                                              GError **error)
{
	gboolean ret;

	ret = nm_setting_802_1x_remove_phase2_altsubject_match_by_value (setting, phase2_altsubject_match);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain \"phase2\" alternative subject match '%s'"),
		             phase2_altsubject_match);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_802_1X_remove_phase2_altsubject_matches,
                               NM_SETTING_802_1X,
                               nm_setting_802_1x_get_num_phase2_altsubject_matches,
                               nm_setting_802_1x_remove_phase2_altsubject_match,
                               _validate_and_remove_phase2_altsubject_match)

/* 'phase2-client-cert' */
DEFINE_SETTER_CERT (nmc_property_802_1X_set_phase2_client_cert, nm_setting_802_1x_set_phase2_client_cert)

static const char *
nmc_property_802_1X_describe_phase2_client_cert (NMSetting *setting, const char *prop)
{
	return _("Enter file path to client certificate for inner authentication (optionally prefixed\n"
	         "with file://).\n"
	         "  [file://]<file path>\n"
	         "Note that nmcli does not support specifying certificates as raw blob data.\n"
	         "Example: /home/cimrman/jara-zweite-phase.crt\n");
}

/* 'private-key' */
DEFINE_SETTER_PRIV_KEY (nmc_property_802_1X_set_private_key,
                        nm_setting_802_1x_get_private_key_password,
                        nm_setting_802_1x_set_private_key)

/* 'phase2-private-key' */
DEFINE_SETTER_PRIV_KEY (nmc_property_802_1X_set_phase2_private_key,
                        nm_setting_802_1x_get_phase2_private_key_password,
                        nm_setting_802_1x_set_phase2_private_key)

static const char *
nmc_property_802_1X_describe_private_key (NMSetting *setting, const char *prop)
{
	return _("Enter path to a private key and the key password (if not set yet):\n"
	         "  [file://]<file path> [<password>]\n"
	         "Note that nmcli does not support specifying private key as raw blob data.\n"
	         "Example: /home/cimrman/jara-priv-key Dardanely\n");
}

/* 'phase1-peapver' */
static const char *_802_1X_valid_phase1_peapvers[] = { "0", "1", NULL };

static gboolean
nmc_property_802_1X_set_phase1_peapver (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, _802_1X_valid_phase1_peapvers, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_802_1X_allowed_phase1_peapver, _802_1X_valid_phase1_peapvers)

/* 'phase1-peaplabel' */
static const char *_802_1X_valid_phase1_peaplabels[] = { "0", "1", NULL };

static gboolean
nmc_property_802_1X_set_phase1_peaplabel (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, _802_1X_valid_phase1_peaplabels, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_802_1X_allowed_phase1_peaplabel, _802_1X_valid_phase1_peaplabels)

/* 'phase1-fast-provisioning' */
static const char *_802_1X_valid_phase1_fast_provisionings[] = { "0", "1", "2", "3", NULL };

static gboolean
nmc_property_802_1X_set_phase1_fast_provisioning (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, _802_1X_valid_phase1_fast_provisionings, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_802_1X_allowed_phase1_fast_provisioning, _802_1X_valid_phase1_fast_provisionings)

/* 'phase2-auth' */
static const char *_802_1X_valid_phase2_auths[] =
	{ "pap", "chap", "mschap", "mschapv2", "gtc", "otp", "md5", "tls", NULL };

static gboolean
nmc_property_802_1X_set_phase2_auth (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, _802_1X_valid_phase2_auths, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_802_1X_allowed_phase2_auth, _802_1X_valid_phase2_auths)

/* 'phase2-autheap' */
static const char *_802_1X_valid_phase2_autheaps[] = { "md5", "mschapv2", "otp", "gtc", "tls", NULL };
static gboolean
nmc_property_802_1X_set_phase2_autheap (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, _802_1X_valid_phase2_autheaps, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_802_1X_allowed_phase2_autheap, _802_1X_valid_phase2_autheaps)

/* 'password-raw' */
static gboolean
nmc_property_802_1X_set_password_raw (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return nmc_property_set_byte_array (setting, prop, val, error);
}

static const char *
nmc_property_802_1X_describe_password_raw (NMSetting *setting, const char *prop)
{
	return _("Enter bytes as a list of hexadecimal values.\n"
	         "Two formats are accepted:\n"
	         "(a) a string of hexadecimal digits, where each two digits represent one byte\n"
	         "(b) space-separated list of bytes written as hexadecimal digits "
	         "(with optional 0x/0X prefix, and optional leading 0).\n\n"
	         "Examples: ab0455a6ea3a74C2\n"
	         "          ab 4 55 0xa6 ea 3a 74 C2\n");
}

/* --- NM_SETTING_ADSL_SETTING_NAME property setter functions --- */
/* 'protocol' */
static const char *adsl_valid_protocols[] = {
	NM_SETTING_ADSL_PROTOCOL_PPPOA,
	NM_SETTING_ADSL_PROTOCOL_PPPOE,
	NM_SETTING_ADSL_PROTOCOL_IPOATM,
	NULL
};

static gboolean
nmc_property_adsl_set_protocol (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, adsl_valid_protocols, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_adsl_allowed_protocol, adsl_valid_protocols)

/* 'encapsulation' */
static const char *adsl_valid_encapsulations[] = {
	NM_SETTING_ADSL_ENCAPSULATION_VCMUX,
	NM_SETTING_ADSL_ENCAPSULATION_LLC,
	NULL
};

static gboolean
nmc_property_adsl_set_encapsulation (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, adsl_valid_encapsulations, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_adsl_allowed_encapsulation, adsl_valid_encapsulations)

/* --- NM_SETTING_BLUETOOTH_SETTING_NAME property setter functions --- */
/* 'type' */
static gboolean
nmc_property_bluetooth_set_type (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	const char *types[] = {
	    NM_SETTING_BLUETOOTH_TYPE_DUN,
	    NM_SETTING_BLUETOOTH_TYPE_PANU,
	    NULL };

	return check_and_set_string (setting, prop, val, types, error);
}

/* --- NM_SETTING_BOND_SETTING_NAME property setter functions --- */
/* 'options' */
/*  example: miimon=100,mode=balance-rr, updelay=5 */
static gboolean
_validate_and_remove_bond_option (NMSettingBond *setting, const char *option)
{
	const char *opt;
	const char **valid_options;

	valid_options = nm_setting_bond_get_valid_options (setting);
	opt = nmc_string_is_valid (option, valid_options, NULL);

	if (opt)
		return nm_setting_bond_remove_option (setting, opt);
	else
		return FALSE;
}

/* Validate bonding 'options' values */
static const char *
_validate_bond_option_value (const char *option, const char *value, GError **error)
{
	if (!g_strcmp0 (option, NM_SETTING_BOND_OPTION_MODE))
		return nmc_bond_validate_mode (value, error);

	return value;
}

DEFINE_SETTER_OPTIONS (nmc_property_bond_set_options,
                       NM_SETTING_BOND,
                       NMSettingBond,
                       nm_setting_bond_add_option,
                       nm_setting_bond_get_valid_options,
                       _validate_bond_option_value)
DEFINE_REMOVER_OPTION (nmc_property_bond_remove_option_options,
                       NM_SETTING_BOND,
                       _validate_and_remove_bond_option)

static const char *
nmc_property_bond_describe_options (NMSetting *setting, const char *prop)
{
	static char *desc = NULL;
	const char **valid_options;
	char *options_str;

	if (G_UNLIKELY (desc == NULL)) {
		valid_options = nm_setting_bond_get_valid_options (NM_SETTING_BOND (setting));
		options_str = g_strjoinv (", ", (char **) valid_options);

		desc = g_strdup_printf (_("Enter a list of bonding options formatted as:\n"
		                          "  option = <value>, option = <value>,... \n"
		                          "Valid options are: %s\n"
		                          "'mode' can be provided as a name or a number:\n"
		                          "balance-rr    = 0\n"
		                          "active-backup = 1\n"
		                          "balance-xor   = 2\n"
		                          "broadcast     = 3\n"
		                          "802.3ad       = 4\n"
		                          "balance-tlb   = 5\n"
		                          "balance-alb   = 6\n\n"
		                          "Example: mode=2,miimon=120\n"), options_str);
		g_free (options_str);
	}
	return desc;
}

static const char **
nmc_property_bond_allowed_options (NMSetting *setting, const char *prop)
{
	return nm_setting_bond_get_valid_options (NM_SETTING_BOND (setting));
}

/* --- NM_SETTING_INFINIBAND_SETTING_NAME property setter functions --- */
/* 'mac-address' */
static gboolean
nmc_property_ib_set_mac (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nm_utils_hwaddr_valid (val, INFINIBAND_ALEN)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid InfiniBand MAC"), val);
		return FALSE;
	}

	g_object_set (setting, prop, val, NULL);
	return TRUE;
}

/* 'transport-mode' */
static const char *ib_valid_transport_modes[] = { "datagram", "connected", NULL };

static gboolean
nmc_property_ib_set_transport_mode (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, ib_valid_transport_modes, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_ib_allowed_transport_mode, ib_valid_transport_modes)

/* 'p-key' */
static gboolean
nmc_property_ib_set_p_key (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	gboolean p_key_valid = FALSE;
	long p_key_int;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!strncasecmp (val, "0x", 2))
		p_key_valid = nmc_string_to_int_base (val + 2, 16, TRUE, 0, G_MAXUINT16, &p_key_int);
	else
		p_key_valid = nmc_string_to_int (val, TRUE, -1, G_MAXUINT16, &p_key_int);

	if (!p_key_valid) {
		if (strcmp (val, "default") == 0)
			p_key_int = -1;
		else {
			g_set_error (error, 1, 0, _("'%s' is not a valid IBoIP P_Key"), val);
			return FALSE;
		}
	}
	g_object_set (setting, prop, (gint) p_key_int, NULL);
	return TRUE;
}

/* --- IP4 / IP6 shared functions --- */
static NMIPAddress *
_parse_ip_address (int family, const char *address, GError **error)
{
	char *value = g_strdup (address);
	NMIPAddress *ipaddr;

	ipaddr = nmc_parse_and_build_address (family, g_strstrip (value), error);
	g_free (value);
	return ipaddr;
}

static NMIPRoute *
_parse_ip_route (int family, const char *route, GError **error)
{
	char *value = g_strdup (route);
	char **routev;
	guint len;
	NMIPRoute *iproute = NULL;

	routev = nmc_strsplit_set (g_strstrip (value), " \t", 0);
	len = g_strv_length (routev);
	if (len < 1 || len > 3) {
		g_set_error (error, 1, 0, _("'%s' is not valid (the format is: ip[/prefix] [next-hop] [metric])"),
		             route);
		goto finish;
	}
	iproute = nmc_parse_and_build_route (family, routev[0], routev[1], len >= 2 ? routev[2] : NULL, error);

finish:
	g_free (value);
	g_strfreev (routev);
	return iproute;
}

/* --- NM_SETTING_IP4_CONFIG_SETTING_NAME property setter functions --- */
/* 'method' */
static const char *ipv4_valid_methods[] = {
	NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL,
	NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	NM_SETTING_IP4_CONFIG_METHOD_SHARED,
	NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
	NULL
};

static gboolean
nmc_property_ipv4_set_method (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	/* Silently accept "static" and convert to "manual" */
	if (val && strlen (val) > 1 && matches (val, "static") == 0)
		val = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;

	return check_and_set_string (setting, prop, val, ipv4_valid_methods, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_ipv4_allowed_method, ipv4_valid_methods)

/* 'dns' */
static gboolean
nmc_property_ipv4_set_dns (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL, **iter, *addr;
	guint32 ip4_addr;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (val, " \t,", 0);
	for (iter = strv; iter && *iter; iter++) {
		addr = g_strstrip (*iter);
		if (inet_pton (AF_INET, addr, &ip4_addr) < 1) {
			g_set_error (error, 1, 0, _("invalid IPv4 address '%s'"), addr);
			g_strfreev (strv);
			return FALSE;
		}
		nm_setting_ip_config_add_dns (NM_SETTING_IP_CONFIG (setting), addr);
	}
	g_strfreev (strv);
	return TRUE;
}

static gboolean
_validate_and_remove_ipv4_dns (NMSettingIPConfig *setting,
                               const char *dns,
                               GError **error)
{
	guint32 ip4_addr;
	gboolean ret;

	if (inet_pton (AF_INET, dns, &ip4_addr) < 1) {
		g_set_error (error, 1, 0, _("invalid IPv4 address '%s'"), dns);
		return FALSE;
	}

	ret = nm_setting_ip_config_remove_dns_by_value (setting, dns);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain DNS server '%s'"), dns);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_ipv4_remove_dns,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_dns,
                               nm_setting_ip_config_remove_dns,
                               _validate_and_remove_ipv4_dns)

static const char *
nmc_property_ipv4_describe_dns (NMSetting *setting, const char *prop)
{
	return _("Enter a list of IPv4 addresses of DNS servers.\n\n"
	         "Example: 8.8.8.8, 8.8.4.4\n");
}

/* 'dns-search' */
static gboolean
nmc_property_ipv4_set_dns_search (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL;
	guint i = 0;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (val, " \t,", 0);
	if (!verify_string_list (strv, prop, nmc_util_is_domain, error)) {
		g_strfreev (strv);
		return FALSE;
	}

	while (strv && strv[i])
		nm_setting_ip_config_add_dns_search (NM_SETTING_IP_CONFIG (setting), strv[i++]);
	g_strfreev (strv);

	return TRUE;
}

static gboolean
_validate_and_remove_ipv4_dns_search (NMSettingIPConfig *setting,
                                      const char *dns_search,
                                      GError **error)
{
	gboolean ret;

	ret = nm_setting_ip_config_remove_dns_search_by_value (setting, dns_search);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain DNS search domain '%s'"),
		             dns_search);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_ipv4_remove_dns_search,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_dns_searches,
                               nm_setting_ip_config_remove_dns_search,
                               _validate_and_remove_ipv4_dns_search)

/* 'dns-options' */
static gboolean
nmc_property_ipv4_set_dns_options (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL;
	guint i = 0;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	nm_setting_ip_config_clear_dns_options (NM_SETTING_IP_CONFIG (setting), TRUE);
	strv = nmc_strsplit_set (val, " \t,", 0);
	while (strv && strv[i])
		nm_setting_ip_config_add_dns_option (NM_SETTING_IP_CONFIG (setting), strv[i++]);
	g_strfreev (strv);

	return TRUE;
}

static gboolean
_validate_and_remove_ipv4_dns_option (NMSettingIPConfig *setting,
                                      const char *dns_option,
                                      GError **error)
{
	gboolean ret;

	ret = nm_setting_ip_config_remove_dns_option_by_value (setting, dns_option);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain DNS option '%s'"),
		             dns_option);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_ipv4_remove_dns_option,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_dns_options,
                               nm_setting_ip_config_remove_dns_option,
                               _validate_and_remove_ipv4_dns_option)

/* 'addresses' */
static NMIPAddress *
_parse_ipv4_address (const char *address, GError **error)
{
	return _parse_ip_address (AF_INET, address, error);
}

static gboolean
nmc_property_ipv4_set_addresses (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL, **iter;
	NMIPAddress *ip4addr;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (val, ",", 0);
	for (iter = strv; iter && *iter; iter++) {
		ip4addr = _parse_ipv4_address (*iter, error);
		if (!ip4addr) {
			g_strfreev (strv);
			return FALSE;
		}
		nm_setting_ip_config_add_address (NM_SETTING_IP_CONFIG (setting), ip4addr);
		nm_ip_address_unref (ip4addr);
	}
	g_strfreev (strv);
	return TRUE;
}

static gboolean
_validate_and_remove_ipv4_address (NMSettingIPConfig *setting,
                                   const char *address,
                                   GError **error)
{
	NMIPAddress *ip4addr;
	gboolean ret;

	ip4addr = _parse_ipv4_address (address, error);
	if (!ip4addr)
		return FALSE;

	ret = nm_setting_ip_config_remove_address_by_value (setting, ip4addr);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain IP address '%s'"), address);
	nm_ip_address_unref (ip4addr);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_ipv4_remove_addresses,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_addresses,
                               nm_setting_ip_config_remove_address,
                               _validate_and_remove_ipv4_address)

static const char *
nmc_property_ipv4_describe_addresses (NMSetting *setting, const char *prop)
{
	return _("Enter a list of IPv4 addresses formatted as:\n"
	         "  ip[/prefix], ip[/prefix],...\n"
	         "Missing prefix is regarded as prefix of 32.\n\n"
	         "Example: 192.168.1.5/24, 10.0.0.11/24\n");
}

/* 'gateway' */
static gboolean
nmc_property_ipv4_set_gateway (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	NMIPAddress *ip4addr;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (strchr (val, '/')) {
		g_set_error (error, 1, 0,
	                     _("invalid gateway address '%s'"), val);
		return FALSE;
	}
	ip4addr = _parse_ipv4_address (val, error);
	if (!ip4addr)
		return FALSE;

	g_object_set (setting, prop, val, NULL);
	nm_ip_address_unref (ip4addr);
	return TRUE;
}

/* 'routes' */
static NMIPRoute *
_parse_ipv4_route (const char *route, GError **error)
{
	return _parse_ip_route (AF_INET, route, error);
}

static gboolean
nmc_property_ipv4_set_routes (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL, **iter;
	NMIPRoute *ip4route;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (val, ",", 0);
	for (iter = strv; iter && *iter; iter++) {
		ip4route = _parse_ipv4_route (*iter, error);
		if (!ip4route) {
			g_strfreev (strv);
			return FALSE;
		}
		nm_setting_ip_config_add_route (NM_SETTING_IP_CONFIG (setting), ip4route);
		nm_ip_route_unref (ip4route);
	}
	g_strfreev (strv);
	return TRUE;
}

static gboolean
_validate_and_remove_ipv4_route (NMSettingIPConfig *setting,
                                 const char *route,
                                 GError **error)
{
	NMIPRoute *ip4route;
	gboolean ret;

	ip4route = _parse_ipv4_route (route, error);
	if (!ip4route)
		return FALSE;

	ret = nm_setting_ip_config_remove_route_by_value (setting, ip4route);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain route '%s'"), route);
	nm_ip_route_unref (ip4route);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_ipv4_remove_routes,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_routes,
                               nm_setting_ip_config_remove_route,
                               _validate_and_remove_ipv4_route)

static const char *
nmc_property_ipv4_describe_routes (NMSetting *setting, const char *prop)
{
	return _("Enter a list of IPv4 routes formatted as:\n"
	         "  ip[/prefix] [next-hop] [metric],...\n\n"
	         "Missing prefix is regarded as a prefix of 32.\n"
	         "Missing next-hop is regarded as 0.0.0.0.\n"
	         "Missing metric means default (NM/kernel will set a default value).\n\n"
	         "Examples: 192.168.2.0/24 192.168.2.1 3, 10.1.0.0/16 10.0.0.254\n"
	         "          10.1.2.0/24\n");
}

/* --- NM_SETTING_IP6_CONFIG_SETTING_NAME property setter functions --- */
/* 'method' */
static const char *ipv6_valid_methods[] = {
	NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	NM_SETTING_IP6_CONFIG_METHOD_DHCP,
	NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
	NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	NM_SETTING_IP6_CONFIG_METHOD_SHARED,
	NULL
};

static gboolean
nmc_property_ipv6_set_method (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	/* Silently accept "static" and convert to "manual" */
	if (val && strlen (val) > 1 && matches (val, "static") == 0)
		val = NM_SETTING_IP6_CONFIG_METHOD_MANUAL;

	return check_and_set_string (setting, prop, val, ipv6_valid_methods, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_ipv6_allowed_method, ipv6_valid_methods)

/* 'dns' */
static gboolean
nmc_property_ipv6_set_dns (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL, **iter, *addr;
	struct in6_addr ip6_addr;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (val, " \t,", 0);
	for (iter = strv; iter && *iter; iter++) {
		addr = g_strstrip (*iter);
		if (inet_pton (AF_INET6, addr, &ip6_addr) < 1) {
			g_set_error (error, 1, 0, _("invalid IPv6 address '%s'"), addr);
			g_strfreev (strv);
			return FALSE;
		}
		nm_setting_ip_config_add_dns (NM_SETTING_IP_CONFIG (setting), addr);
	}
	g_strfreev (strv);
	return TRUE;
}

static gboolean
_validate_and_remove_ipv6_dns (NMSettingIPConfig *setting,
                               const char *dns,
                               GError **error)
{
	struct in6_addr ip6_addr;
	gboolean ret;

	if (inet_pton (AF_INET6, dns, &ip6_addr) < 1) {
		g_set_error (error, 1, 0, _("invalid IPv6 address '%s'"), dns);
		return FALSE;
	}

	ret = nm_setting_ip_config_remove_dns_by_value (setting, dns);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain DNS server '%s'"), dns);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_ipv6_remove_dns,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_dns,
                               nm_setting_ip_config_remove_dns,
                               _validate_and_remove_ipv6_dns)

static const char *
nmc_property_ipv6_describe_dns (NMSetting *setting, const char *prop)
{
	return _("Enter a list of IPv6 addresses of DNS servers.  If the IPv6 "
	         "configuration method is 'auto' these DNS servers are appended "
	         "to those (if any) returned by automatic configuration.  DNS "
	         "servers cannot be used with the 'shared' or 'link-local' IPv6 "
	         "configuration methods, as there is no upstream network. In "
	         "all other IPv6 configuration methods, these DNS "
	         "servers are used as the only DNS servers for this connection.\n\n"
	         "Example: 2607:f0d0:1002:51::4, 2607:f0d0:1002:51::1\n");
}

/* 'dns-search' */
static gboolean
nmc_property_ipv6_set_dns_search (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL;
	guint i = 0;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (val, " \t,", 0);
	if (!verify_string_list (strv, prop, nmc_util_is_domain, error)) {
		g_strfreev (strv);
		return FALSE;
	}

	while (strv && strv[i])
		nm_setting_ip_config_add_dns_search (NM_SETTING_IP_CONFIG (setting), strv[i++]);
	g_strfreev (strv);

	return TRUE;
}

static gboolean
_validate_and_remove_ipv6_dns_search (NMSettingIPConfig *setting,
                                      const char *dns_search,
                                      GError **error)
{
	gboolean ret;

	ret = nm_setting_ip_config_remove_dns_search_by_value (setting, dns_search);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain DNS search domain '%s'"),
		             dns_search);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_ipv6_remove_dns_search,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_dns_searches,
                               nm_setting_ip_config_remove_dns_search,
                               _validate_and_remove_ipv6_dns_search)

/* 'dns-options' */
static gboolean
nmc_property_ipv6_set_dns_options (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL;
	guint i = 0;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	nm_setting_ip_config_clear_dns_options (NM_SETTING_IP_CONFIG (setting), TRUE);
	strv = nmc_strsplit_set (val, " \t,", 0);
	while (strv && strv[i])
		nm_setting_ip_config_add_dns_option (NM_SETTING_IP_CONFIG (setting), strv[i++]);
	g_strfreev (strv);

	return TRUE;
}

static gboolean
_validate_and_remove_ipv6_dns_option (NMSettingIPConfig *setting,
                                      const char *dns_option,
                                      GError **error)
{
	gboolean ret;

	ret = nm_setting_ip_config_remove_dns_option_by_value (setting, dns_option);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain DNS option '%s'"),
		             dns_option);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_ipv6_remove_dns_option,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_dns_options,
                               nm_setting_ip_config_remove_dns_option,
                               _validate_and_remove_ipv6_dns_option)

/* 'addresses' */
static NMIPAddress *
_parse_ipv6_address (const char *address, GError **error)
{
	return _parse_ip_address (AF_INET6, address, error);
}

static gboolean
nmc_property_ipv6_set_addresses (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL, **iter;
	NMIPAddress *ip6addr;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (val, ",", 0);
	for (iter = strv; iter && *iter; iter++) {
		ip6addr = _parse_ipv6_address (*iter, error);
		if (!ip6addr) {
			g_strfreev (strv);
			return FALSE;
		}
		nm_setting_ip_config_add_address (NM_SETTING_IP_CONFIG (setting), ip6addr);
		nm_ip_address_unref (ip6addr);
	}
	g_strfreev (strv);
	return TRUE;
}

static gboolean
_validate_and_remove_ipv6_address (NMSettingIPConfig *setting,
                                   const char *address,
                                   GError **error)
{
	NMIPAddress *ip6addr;
	gboolean ret;

	ip6addr = _parse_ipv6_address (address, error);
	if (!ip6addr)
		return FALSE;

	ret = nm_setting_ip_config_remove_address_by_value (setting, ip6addr);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain IP address '%s'"), address);
	nm_ip_address_unref (ip6addr);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_ipv6_remove_addresses,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_addresses,
                               nm_setting_ip_config_remove_address,
                               _validate_and_remove_ipv6_address)

static const char *
nmc_property_ipv6_describe_addresses (NMSetting *setting, const char *prop)
{
	return _("Enter a list of IPv6 addresses formatted as:\n"
	         "  ip[/prefix], ip[/prefix],...\n"
	         "Missing prefix is regarded as prefix of 128.\n\n"
	         "Example: 2607:f0d0:1002:51::4/64, 1050:0:0:0:5:600:300c:326b\n");
}

/* 'gateway' */
static gboolean
nmc_property_ipv6_set_gateway (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	NMIPAddress *ip6addr;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (strchr (val, '/')) {
		g_set_error (error, 1, 0,
	                     _("invalid gateway address '%s'"), val);
		return FALSE;
	}
	ip6addr = _parse_ipv6_address (val, error);
	if (!ip6addr)
		return FALSE;

	g_object_set (setting, prop, val, NULL);
	nm_ip_address_unref (ip6addr);
	return TRUE;
}

/* 'routes' */
static NMIPRoute *
_parse_ipv6_route (const char *route, GError **error)
{
	return _parse_ip_route (AF_INET6, route, error);
}

static gboolean
nmc_property_ipv6_set_routes (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL, **iter;
	NMIPRoute *ip6route;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	strv = nmc_strsplit_set (val, ",", 0);
	for (iter = strv; iter && *iter; iter++) {
		ip6route = _parse_ipv6_route (*iter, error);
		if (!ip6route) {
			g_strfreev (strv);
			return FALSE;
		}
		nm_setting_ip_config_add_route (NM_SETTING_IP_CONFIG (setting), ip6route);
		nm_ip_route_unref (ip6route);
	}
	g_strfreev (strv);
	return TRUE;
}

static gboolean
_validate_and_remove_ipv6_route (NMSettingIPConfig *setting,
                                 const char *route,
                                 GError **error)
{
	NMIPRoute *ip6route;
	gboolean ret;

	ip6route = _parse_ipv6_route (route, error);
	if (!ip6route)
		return FALSE;

	ret = nm_setting_ip_config_remove_route_by_value (setting, ip6route);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain route '%s'"), route);
	nm_ip_route_unref (ip6route);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_ipv6_remove_routes,
                               NM_SETTING_IP_CONFIG,
                               nm_setting_ip_config_get_num_routes,
                               nm_setting_ip_config_remove_route,
                               _validate_and_remove_ipv6_route)

static const char *
nmc_property_ipv6_describe_routes (NMSetting *setting, const char *prop)
{
	return _("Enter a list of IPv6 routes formatted as:\n"
	         "  ip[/prefix] [next-hop] [metric],...\n\n"
	         "Missing prefix is regarded as a prefix of 128.\n"
	         "Missing next-hop is regarded as \"::\".\n"
	         "Missing metric means default (NM/kernel will set a default value).\n\n"
	         "Examples: 2001:db8:beef:2::/64 2001:db8:beef::2, 2001:db8:beef:3::/64 2001:db8:beef::3 2\n"
	         "          abbe::/64 55\n");
}

static gboolean
nmc_property_ipv6_set_ip6_privacy (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	unsigned long val_int;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_uint (val, FALSE, 0, 0, &val_int)) {
		g_set_error (error, 1, 0, _("'%s' is not a number"), val);
		return FALSE;
	}

	if (   val_int != NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED
	    && val_int != NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR
	    && val_int != NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR) {
		g_set_error (error, 1, 0, _("'%s' is not valid; use 0, 1, or 2"), val);
		return FALSE;
	}

	g_object_set (setting, prop, val_int, NULL);
	return TRUE;
}

/* --- NM_SETTING_OLPC_MESH_SETTING_NAME property setter functions --- */
static gboolean
nmc_property_olpc_set_channel (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	unsigned long chan_int;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_uint (val, TRUE, 1, 13, &chan_int)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid channel; use <1-13>"), val);
		return FALSE;
	}
	g_object_set (setting, prop, chan_int, NULL);
	return TRUE;
}


/* --- NM_SETTING_SERIAL_SETTING_NAME property setter functions --- */
static char *
nmc_property_serial_get_parity (NMSetting *setting, NmcPropertyGetType get_type)
{
	NMSettingSerial *s_serial = NM_SETTING_SERIAL (setting);

	switch (nm_setting_serial_get_parity (s_serial)) {
	case NM_SETTING_SERIAL_PARITY_EVEN:
		return g_strdup ("even");
	case NM_SETTING_SERIAL_PARITY_ODD:
		return g_strdup ("odd");
	default:
	case NM_SETTING_SERIAL_PARITY_NONE:
		return g_strdup ("none");
	}
}

static gboolean
nmc_property_serial_set_parity (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	NMSettingSerialParity parity;

	if (val[0] == 'E' || val[0] == 'e')
		parity = NM_SETTING_SERIAL_PARITY_EVEN;
	else if (val[0] == 'O' || val[0] == 'o')
		parity = NM_SETTING_SERIAL_PARITY_ODD;
	else if (val[0] == 'N' || val[0] == 'n')
		parity = NM_SETTING_SERIAL_PARITY_NONE;
	else {
		g_set_error (error, 1, 0, _("'%s' is not valid; use [e, o, n]"), val);
		return FALSE;
	}

	g_object_set (setting, prop, parity, NULL);
	return TRUE;
}

/* --- NM_SETTING_TEAM_SETTING_NAME property functions --- */
/* --- NM_SETTING_TEAM_PORT_SETTING_NAME property functions --- */
static gboolean
nmc_property_team_set_config (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char *json = NULL;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_team_check_config (val, &json, error)) {
		return FALSE;
	}
	g_object_set (setting, prop, json, NULL);
	g_free (json);
	return TRUE;
}

static const char *
nmc_property_team_describe_config (NMSetting *setting, const char *prop)
{
	return _("nmcli can accepts both direct JSON configuration data and a file name containing "
	         "the configuration. In the latter case the file is read and the contents is put "
	         "into this property.\n\n"
	         "Examples: set team.config "
	         "{ \"device\": \"team0\", \"runner\": {\"name\": \"roundrobin\"}, \"ports\": {\"eth1\": {}, \"eth2\": {}} }\n"
	         "          set team.config /etc/my-team.conf\n");
}

/* --- NM_SETTING_VLAN_SETTING_NAME property setter functions --- */
static gboolean
nmc_property_vlan_set_prio_map (NMSetting *setting,
                                const char *prop,
                                const char *val,
                                NMVlanPriorityMap map_type,
                                GError **error)
{
	char **prio_map, **p;

	prio_map = nmc_vlan_parse_priority_maps (val, map_type, error);
	if (!prio_map)
		return FALSE;

	for (p = prio_map; p && *p; p++)
		nm_setting_vlan_add_priority_str (NM_SETTING_VLAN (setting), map_type, *p);

	g_strfreev (prio_map);
	return TRUE;
}

static gboolean
nmc_property_vlan_remove_prio_map (NMSetting *setting,
                                   const char *prop,
                                   guint32 idx,
                                   NMVlanPriorityMap map_type,
                                   GError **error)
{
	guint32 num;

	num = nm_setting_vlan_get_num_priorities (NM_SETTING_VLAN (setting), map_type);
	if (num == 0) {
		g_set_error_literal (error, 1, 0, _("no priority to remove"));
		return FALSE;
	}
	if (idx >= num) {
		g_set_error (error, 1, 0, _("index '%d' is not in the range of <0-%d>"),
		             idx, num - 1);
		return FALSE;
	}

	nm_setting_vlan_remove_priority (NM_SETTING_VLAN (setting), map_type, idx);
	return TRUE;
}

static gboolean
nmc_property_vlan_set_ingress_priority_map (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return nmc_property_vlan_set_prio_map (setting, prop, val, NM_VLAN_INGRESS_MAP, error);
}

static gboolean
nmc_property_vlan_set_egress_priority_map (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return nmc_property_vlan_set_prio_map (setting, prop, val, NM_VLAN_EGRESS_MAP, error);
}

static gboolean
nmc_property_vlan_remove_priority_map (NMSetting *setting,
                                       const char *prop,
                                       const char *value,
                                       guint32 idx,
                                       NMVlanPriorityMap map,
                                       GError **error)
{
	/* If value != NULL, remove by value */
	if (value) {
		gboolean ret;
		char **prio_map;
		char *val = g_strdup (value);

		prio_map = nmc_vlan_parse_priority_maps (val, map, error);
		if (!prio_map)
			return FALSE;
		if (prio_map[1])
			g_print (_("Warning: only one mapping at a time is supported; taking the first one (%s)\n"),
			         prio_map[0]);
		ret = nm_setting_vlan_remove_priority_str_by_value (NM_SETTING_VLAN (setting),
		                                                    map,
		                                                    prio_map[0]);

		if (!ret)
			g_set_error (error, 1, 0, _("the property doesn't contain mapping '%s'"), prio_map[0]);
		g_free (val);
		g_strfreev (prio_map);
		return ret;
	}

	/* Else remove by index */
	return nmc_property_vlan_remove_prio_map (setting, prop, idx, map, error);
}

static gboolean
nmc_property_vlan_remove_ingress_priority_map (NMSetting *setting,
                                               const char *prop,
                                               const char *value,
                                               guint32 idx,
                                               GError **error)
{
	return nmc_property_vlan_remove_priority_map (setting,
                                                      prop,
                                                      value,
                                                      idx,
                                                      NM_VLAN_INGRESS_MAP,
                                                      error);
}

static gboolean
nmc_property_vlan_remove_egress_priority_map (NMSetting *setting,
                                              const char *prop,
                                              const char *value,
                                              guint32 idx,
                                              GError **error)
{
	return nmc_property_vlan_remove_priority_map (setting,
                                                      prop,
                                                      value,
                                                      idx,
                                                      NM_VLAN_EGRESS_MAP,
                                                      error);
}

/* --- NM_SETTING_VPN_SETTING_NAME property setter functions --- */
/* 'data' */
DEFINE_SETTER_OPTIONS (nmc_property_vpn_set_data,
                       NM_SETTING_VPN,
                       NMSettingVpn,
                       nm_setting_vpn_add_data_item,
                       NULL,
                       NULL)
DEFINE_REMOVER_OPTION (nmc_property_vpn_remove_option_data,
                       NM_SETTING_VPN,
                       nm_setting_vpn_remove_data_item)

/* 'secrets' */
DEFINE_SETTER_OPTIONS (nmc_property_vpn_set_secrets,
                       NM_SETTING_VPN,
                       NMSettingVpn,
                       nm_setting_vpn_add_secret,
                       NULL,
                       NULL)
DEFINE_REMOVER_OPTION (nmc_property_vpn_remove_option_secret,
                       NM_SETTING_VPN,
                       nm_setting_vpn_remove_secret)

/* --- NM_SETTING_WIMAX_SETTING_NAME property setter functions --- */
/* No specific functions */

/* --- NM_SETTING_WIRED_SETTING_NAME property setter functions --- */
#if 0
/*
 * Do not allow setting 'port' and 'duplex' for now. They are not implemented in
 * NM core, nor in ifcfg-rh plugin. Enable this when it gets done.
 */
/* 'port' */
static const char *wired_valid_ports[] = { "tp", "aui", "bnc", "mii", NULL };

static gboolean
nmc_property_wired_set_port (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, wired_valid_ports, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_wired_allowed_port, wired_valid_ports)

/* 'duplex' */
static const char *wired_valid_duplexes[] = { "half", "full", NULL };

static gboolean
nmc_property_wired_set_duplex (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, wired_valid_duplexes, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_wired_allowed_duplex, wired_valid_duplexes)
#endif

/* 'mac-address-blacklist' */
DEFINE_SETTER_MAC_BLACKLIST (nmc_property_wired_set_mac_address_blacklist,
                             NM_SETTING_WIRED,
                             nm_setting_wired_add_mac_blacklist_item)

static gboolean
_validate_and_remove_wired_mac_blacklist_item (NMSettingWired *setting,
                                              const char *mac,
                                              GError **error)
{
	gboolean ret;
	guint8 buf[32];

	if (!nm_utils_hwaddr_aton (mac, buf, ETH_ALEN)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid MAC address"), mac);
                return FALSE;
	}

	ret = nm_setting_wired_remove_mac_blacklist_item_by_value (setting, mac);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain MAC address '%s'"), mac);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_wired_remove_mac_address_blacklist,
                               NM_SETTING_WIRED,
                               nm_setting_wired_get_num_mac_blacklist_items,
                               nm_setting_wired_remove_mac_blacklist_item,
                               _validate_and_remove_wired_mac_blacklist_item)

/* 's390-subchannels' */
static gboolean
nmc_property_wired_set_s390_subchannels (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL;
	int len;

	strv = nmc_strsplit_set (val, " ,\t", 0);
	len = g_strv_length (strv);
	if (len != 2 && len != 3) {
		g_set_error (error, 1, 0, _("'%s' is not valid; 2 or 3 strings should be provided"),
		             val);
		g_strfreev (strv);
		return FALSE;
	}

	g_object_set (setting, prop, strv, NULL);
	g_strfreev (strv);
	return TRUE;
}

static const char *
nmc_property_wired_describe_s390_subchannels (NMSetting *setting, const char *prop)
{
	return _("Enter a list of subchannels (comma or space separated).\n\n"
	         "Example: 0.0.0e20 0.0.0e21 0.0.0e22\n");
}

/* 's390-nettype' */
static const char *wired_valid_s390_nettypes[] = { "qeth", "lcs", "ctc", NULL };

static gboolean
nmc_property_wired_set_s390_nettype (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, wired_valid_s390_nettypes, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_wired_allowed_s390_nettype, wired_valid_s390_nettypes)

/* 's390-options' */
DEFINE_SETTER_OPTIONS (nmc_property_wired_set_s390_options,
                       NM_SETTING_WIRED,
                       NMSettingWired,
                       nm_setting_wired_add_s390_option,
                       nm_setting_wired_get_valid_s390_options,
                       NULL)
DEFINE_REMOVER_OPTION (nmc_property_wired_remove_option_s390_options,
                       NM_SETTING_WIRED,
                       nm_setting_wired_remove_s390_option)

static const char **
nmc_property_wired_allowed_s390_options (NMSetting *setting, const char *prop)
{
	return nm_setting_wired_get_valid_s390_options (NM_SETTING_WIRED (setting));
}

static const char *
nmc_property_wired_describe_s390_options (NMSetting *setting, const char *prop)
{
	static char *desc = NULL;
	const char **valid_options;
	char *options_str;

	if (G_UNLIKELY (desc == NULL)) {
		valid_options = nm_setting_wired_get_valid_s390_options (NM_SETTING_WIRED (setting));
		options_str = g_strjoinv (", ", (char **) valid_options);

		desc = g_strdup_printf (_("Enter a list of S/390 options formatted as:\n"
		                          "  option = <value>, option = <value>,...\n"
		                          "Valid options are: %s\n"),
		                        options_str);
		g_free (options_str);
	}
	return desc;
}

/* --- NM_SETTING_WIRELESS_SETTING_NAME property setter functions --- */
/* 'mode' */
static const char *wifi_valid_modes[] = {
	NM_SETTING_WIRELESS_MODE_INFRA,
	NM_SETTING_WIRELESS_MODE_ADHOC,
	NM_SETTING_WIRELESS_MODE_AP,
	NULL
};

static gboolean
nmc_property_wifi_set_mode (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, wifi_valid_modes, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_wifi_allowed_mode, wifi_valid_modes)

/* 'band' */
static const char *wifi_valid_bands[] = { "a", "bg", NULL };

static gboolean
nmc_property_wifi_set_band (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, wifi_valid_bands, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_wifi_allowed_band, wifi_valid_bands)

/* 'channel' */
static gboolean
nmc_property_wifi_set_channel (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	unsigned long chan_int;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_uint (val, FALSE, 0, 0, &chan_int)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid channel"), val);
		return FALSE;
	}

	if (   !nm_utils_wifi_is_channel_valid (chan_int, "a")
	    && !nm_utils_wifi_is_channel_valid (chan_int, "bg")) {
		g_set_error (error, 1, 0, _("'%ld' is not a valid channel"), chan_int);
		return FALSE;
	}

	g_object_set (setting, prop, chan_int, NULL);
	return TRUE;
}

/* 'mac-address-blacklist' */
DEFINE_SETTER_MAC_BLACKLIST (nmc_property_wireless_set_mac_address_blacklist,
                             NM_SETTING_WIRELESS,
                             nm_setting_wireless_add_mac_blacklist_item)

static gboolean
_validate_and_remove_wifi_mac_blacklist_item (NMSettingWireless *setting,
                                              const char *mac,
                                              GError **error)
{
	gboolean ret;
	guint8 buf[32];

	if (!nm_utils_hwaddr_aton (mac, buf, ETH_ALEN)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid MAC address"), mac);
                return FALSE;
	}

	ret = nm_setting_wireless_remove_mac_blacklist_item_by_value (setting, mac);
	if (!ret)
		g_set_error (error, 1, 0, _("the property doesn't contain MAC address '%s'"), mac);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_wireless_remove_mac_address_blacklist,
                               NM_SETTING_WIRELESS,
                               nm_setting_wireless_get_num_mac_blacklist_items,
                               nm_setting_wireless_remove_mac_blacklist_item,
                               _validate_and_remove_wifi_mac_blacklist_item)

/* 'powersave' */
static gboolean
nmc_property_wireless_set_powersave (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	unsigned long powersave_int;
	gboolean val_bool = FALSE;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_uint (val, TRUE, 0, G_MAXUINT32, &powersave_int)) {
		if (!nmc_string_to_bool (val, &val_bool, NULL)) {
			g_set_error (error, 1, 0, _("'%s' is not a valid powersave value"), val);
			return FALSE;
		}
		powersave_int = val_bool ? 1 : 0;
	}

	g_object_set (setting, prop, (guint32) powersave_int, NULL);
	return TRUE;
}

/* --- NM_SETTING_WIRELESS_SECURITY_SETTING_NAME property setter functions --- */
/* 'key-mgmt' */
static const char *wifi_sec_valid_key_mgmts[] = { "none", "ieee8021x", "wpa-none", "wpa-psk", "wpa-eap", NULL };

static gboolean
nmc_property_wifi_sec_set_key_mgmt (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, wifi_sec_valid_key_mgmts, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_wifi_sec_allowed_key_mgmt, wifi_sec_valid_key_mgmts)

/* 'auth-alg' */
static const char *wifi_sec_valid_auth_algs[] = { "open", "shared", "leap", NULL };

static gboolean
nmc_property_wifi_sec_set_auth_alg (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, wifi_sec_valid_auth_algs, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_wifi_sec_allowed_auth_alg, wifi_sec_valid_auth_algs)

/* 'proto' */
static const char *wifi_sec_valid_protos[] = { "wpa", "rsn", NULL };

DEFINE_SETTER_STR_LIST_MULTI (check_and_add_wifi_sec_proto,
                              NM_SETTING_WIRELESS_SECURITY,
                              nm_setting_wireless_security_add_proto)

static gboolean
nmc_property_wifi_sec_set_proto (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_add_wifi_sec_proto (setting, prop, val, wifi_sec_valid_protos, error);
}

static gboolean
_validate_and_remove_wifi_sec_proto (NMSettingWirelessSecurity *setting,
                                     const char *proto,
                                     GError **error)
{
	gboolean ret;
	const char *valid;

	valid = nmc_string_is_valid (proto, wifi_sec_valid_protos, error);
	if (!valid)
		return FALSE;

	ret = nm_setting_wireless_security_remove_proto_by_value (setting, proto);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain protocol '%s'"), proto);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_wifi_sec_remove_proto,
                               NM_SETTING_WIRELESS_SECURITY,
                               nm_setting_wireless_security_get_num_protos,
                               nm_setting_wireless_security_remove_proto,
                               _validate_and_remove_wifi_sec_proto)

DEFINE_ALLOWED_VAL_FUNC (nmc_property_wifi_sec_allowed_proto, wifi_sec_valid_protos)

/* 'pairwise' */
static const char *wifi_sec_valid_pairwises[] = { "tkip", "ccmp", NULL };

DEFINE_SETTER_STR_LIST_MULTI (check_and_add_wifi_sec_pairwise,
                              NM_SETTING_WIRELESS_SECURITY,
                              nm_setting_wireless_security_add_pairwise)

static gboolean
nmc_property_wifi_sec_set_pairwise (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_add_wifi_sec_pairwise (setting, prop, val, wifi_sec_valid_pairwises, error);
}

static gboolean
_validate_and_remove_wifi_sec_pairwise (NMSettingWirelessSecurity *setting,
                                        const char *pairwise,
                                        GError **error)
{
	gboolean ret;
	const char *valid;

	valid = nmc_string_is_valid (pairwise, wifi_sec_valid_pairwises, error);
	if (!valid)
		return FALSE;

	ret = nm_setting_wireless_security_remove_pairwise_by_value (setting, pairwise);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain protocol '%s'"), pairwise);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_wifi_sec_remove_pairwise,
                               NM_SETTING_WIRELESS_SECURITY,
                               nm_setting_wireless_security_get_num_pairwise,
                               nm_setting_wireless_security_remove_pairwise,
                               _validate_and_remove_wifi_sec_pairwise)

DEFINE_ALLOWED_VAL_FUNC (nmc_property_wifi_sec_allowed_pairwise, wifi_sec_valid_pairwises)

/* 'group' */
static const char *wifi_sec_valid_groups[] = { "wep40", "wep104", "tkip", "ccmp", NULL };

DEFINE_SETTER_STR_LIST_MULTI (check_and_add_wifi_sec_group,
                              NM_SETTING_WIRELESS_SECURITY,
                              nm_setting_wireless_security_add_group)

static gboolean
nmc_property_wifi_sec_set_group (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_add_wifi_sec_group (setting, prop, val, wifi_sec_valid_groups, error);
}

static gboolean
_validate_and_remove_wifi_sec_group (NMSettingWirelessSecurity *setting,
                                     const char *group,
                                     GError **error)
{
	gboolean ret;
	const char *valid;

	valid = nmc_string_is_valid (group, wifi_sec_valid_groups, error);
	if (!valid)
		return FALSE;

	ret = nm_setting_wireless_security_remove_group_by_value (setting, group);
	if (!ret)
		g_set_error (error, 1, 0,
		             _("the property doesn't contain protocol '%s'"), group);
	return ret;
}
DEFINE_REMOVER_INDEX_OR_VALUE (nmc_property_wifi_sec_remove_group,
                               NM_SETTING_WIRELESS_SECURITY,
                               nm_setting_wireless_security_get_num_groups,
                               nm_setting_wireless_security_remove_group,
                               _validate_and_remove_wifi_sec_group)
DEFINE_ALLOWED_VAL_FUNC (nmc_property_wifi_sec_allowed_group, wifi_sec_valid_groups)

/* 'wep-key' */
static gboolean
nmc_property_wifi_set_wep_key (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	NMWepKeyType guessed_type = NM_WEP_KEY_TYPE_UNKNOWN;
	NMWepKeyType type;
	guint32 prev_idx, idx;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Get currently set type */
	type = nm_setting_wireless_security_get_wep_key_type (NM_SETTING_WIRELESS_SECURITY (setting));

	/* Guess key type */
	if (nm_utils_wep_key_valid (val, NM_WEP_KEY_TYPE_KEY))
		guessed_type = NM_WEP_KEY_TYPE_KEY;
	else if (nm_utils_wep_key_valid (val, NM_WEP_KEY_TYPE_PASSPHRASE))
		guessed_type = NM_WEP_KEY_TYPE_PASSPHRASE;

	if (guessed_type == NM_WEP_KEY_TYPE_UNKNOWN) {
		g_set_error (error, 1, 0, _("'%s' is not valid"), val);
		return FALSE;
	}

	if (type != NM_WEP_KEY_TYPE_UNKNOWN && type != guessed_type) {
		if (nm_utils_wep_key_valid (val, type))
			guessed_type = type;
		else {
			g_set_error (error, 1, 0,
			             _("'%s' not compatible with %s '%s', please change the key or set the right %s first."),
			             val, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, wep_key_type_to_string (type),
			             NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE);
			return FALSE;
		}
	}
	prev_idx = nm_setting_wireless_security_get_wep_tx_keyidx (NM_SETTING_WIRELESS_SECURITY (setting));
	idx = prop[strlen (prop) - 1] - '0';
	g_print (_("WEP key is guessed to be of '%s'\n"), wep_key_type_to_string (guessed_type));
	if (idx != prev_idx)
		g_print (_("WEP key index set to '%d'\n"), idx);

	g_object_set (setting, prop, val, NULL);
	g_object_set (setting, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, guessed_type, NULL);
	if (idx != prev_idx)
		g_object_set (setting, NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, idx, NULL);
	return TRUE;
}

/* 'wep-key-type' */
static gboolean
nmc_property_wifi_set_wep_key_type (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	unsigned long  type_int;
	const char *valid_wep_types[] = { "unknown", "key", "passphrase", NULL };
	const char *type_str = NULL;
	const char *key0, *key1,* key2, *key3;
	NMWepKeyType type = NM_WEP_KEY_TYPE_UNKNOWN;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_uint (val, TRUE, 0, 2, &type_int)) {
		if (!(type_str = nmc_string_is_valid (val, valid_wep_types, NULL))) {
			g_set_error (error, 1, 0, _("'%s' not among [0 (unknown), 1 (key), 2 (passphrase)]"), val);
			return FALSE;
		}
		if (type_str == valid_wep_types[1])
			type = NM_WEP_KEY_TYPE_KEY;
		else if (type_str == valid_wep_types[2])
			type = NM_WEP_KEY_TYPE_PASSPHRASE;
	} else
		type = (NMWepKeyType) type_int;

	/* Check type compatibility with set keys */
	key0 = nm_setting_wireless_security_get_wep_key (NM_SETTING_WIRELESS_SECURITY (setting), 0);
	key1 = nm_setting_wireless_security_get_wep_key (NM_SETTING_WIRELESS_SECURITY (setting), 1);
	key2 = nm_setting_wireless_security_get_wep_key (NM_SETTING_WIRELESS_SECURITY (setting), 2);
	key3 = nm_setting_wireless_security_get_wep_key (NM_SETTING_WIRELESS_SECURITY (setting), 3);
	if (key0 && !nm_utils_wep_key_valid (key0, type))
		g_print (_("Warning: '%s' is not compatible with '%s' type, please change or delete the key.\n"),
		         NM_SETTING_WIRELESS_SECURITY_WEP_KEY0, wep_key_type_to_string (type));
	if (key1 && !nm_utils_wep_key_valid (key1, type))
		g_print (_("Warning: '%s' is not compatible with '%s' type, please change or delete the key.\n"),
		         NM_SETTING_WIRELESS_SECURITY_WEP_KEY1, wep_key_type_to_string (type));
	if (key2 && !nm_utils_wep_key_valid (key2, type))
		g_print (_("Warning: '%s' is not compatible with '%s' type, please change or delete the key.\n"),
		         NM_SETTING_WIRELESS_SECURITY_WEP_KEY2, wep_key_type_to_string (type));
	if (key3 && !nm_utils_wep_key_valid (key3, type))
		g_print (_("Warning: '%s' is not compatible with '%s' type, please change or delete the key.\n"),
		         NM_SETTING_WIRELESS_SECURITY_WEP_KEY3, wep_key_type_to_string (type));

	g_object_set (setting, prop, type, NULL);
	return TRUE;
}

static const char *
nmc_property_wifi_describe_wep_key_type (NMSetting *setting, const char *prop)
{
	static char *desc = NULL;

	if (G_UNLIKELY (desc == NULL)) {
		desc = g_strdup_printf (_("Enter the type of WEP keys. The accepted values are: "
		                          "0 or unknown, 1 or key, and 2 or passphrase.\n"));
	}
	return desc;
}

/* 'psk' */
static gboolean
nmc_property_wifi_set_psk (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nm_utils_wpa_psk_valid (val)) {
		g_set_error (error, 1, 0, _("'%s' is not a valid PSK"), val);
		return FALSE;
	}
	g_object_set (setting, prop, val, NULL);
	return TRUE;
}

#define DCB_ALL_FLAGS (NM_SETTING_DCB_FLAG_ENABLE | NM_SETTING_DCB_FLAG_ADVERTISE | NM_SETTING_DCB_FLAG_WILLING)

/* DCB stuff */
static gboolean
nmc_property_dcb_set_flags (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	char **strv = NULL, **iter;
	NMSettingDcbFlags flags = NM_SETTING_DCB_FLAG_NONE;
	long int t;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Check for overall hex numeric value */
	if (nmc_string_to_int_base (val, 0, TRUE, 0, DCB_ALL_FLAGS, &t))
		flags = (guint) t;
	else {
		/* Check for individual flag numbers */
		strv = nmc_strsplit_set (val, " \t,", 0);
		for (iter = strv; iter && *iter; iter++) {
			if (!nmc_string_to_int_base (*iter, 0, TRUE, 0, DCB_ALL_FLAGS, &t))
				t = -1;

			if (   g_ascii_strcasecmp (*iter, "enable") == 0
			    || g_ascii_strcasecmp (*iter, "enabled") == 0
			    || t == NM_SETTING_DCB_FLAG_ENABLE)
				flags |= NM_SETTING_DCB_FLAG_ENABLE;
			else if (   g_ascii_strcasecmp (*iter, "advertise") == 0
				 || t == NM_SETTING_DCB_FLAG_ADVERTISE)
				flags |= NM_SETTING_DCB_FLAG_ADVERTISE;
			else if (   g_ascii_strcasecmp (*iter, "willing") == 0
				 || t == NM_SETTING_DCB_FLAG_WILLING)
				flags |= NM_SETTING_DCB_FLAG_WILLING;
			else if (   g_ascii_strcasecmp (*iter, "disable") == 0
				 || g_ascii_strcasecmp (*iter, "disabled") == 0
				 || t == 0) {
				/* pass */
			} else {
				g_set_error (error, 1, 0, _("'%s' is not a valid DCB flag"), *iter);
				return FALSE;
			}
		}
		g_strfreev (strv);
	}

	/* Validate the number according to the property spec */
	if (!validate_uint (setting, prop, (guint) flags, error))
		return FALSE;

	g_object_set (setting, prop, (guint) flags, NULL);
	return TRUE;
}

static gboolean
nmc_property_dcb_set_priority (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	long int priority = 0;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!nmc_string_to_int (val, FALSE, -1, 7, &priority)) {
		g_set_error (error, 1, 0, _("'%s' is not a DCB app priority"), val);
		return FALSE;
	}

	/* Validate the number according to the property spec */
	if (!validate_int (setting, prop, (gint) priority, error))
		return FALSE;

	g_object_set (setting, prop, (gint) priority, NULL);
	return TRUE;
}

static gboolean
dcb_parse_uint_array (const char *val,
                      guint max,
                      guint other,
                      guint *out_array,
                      GError **error)
{
	char **items, **iter;
	guint i = 0;

	g_return_val_if_fail (out_array != NULL, FALSE);

	items = g_strsplit_set (val, ",", -1);
	if (g_strv_length (items) != 8) {
		g_set_error_literal (error, 1, 0, _("must contain 8 comma-separated numbers"));
		goto error;
	}

	for (iter = items; iter && *iter; iter++) {
		long int num = 0;
		gboolean success;

		*iter = g_strstrip (*iter);
		success = nmc_string_to_int_base (*iter, 10, TRUE, 0, other ? other : max, &num);

		/* If number is greater than 'max' it must equal 'other' */
		if (success && other && (num > max) && (num != other))
			success = FALSE;

		if (!success) {
			if (other) {
				g_set_error (error, 1, 0, _("'%s' not a number between 0 and %u (inclusive) or %u"),
					     *iter, max, other);
			} else {
				g_set_error (error, 1, 0, _("'%s' not a number between 0 and %u (inclusive)"),
					     *iter, max);
			}
			goto error;
		}
		out_array[i++] = (guint) num;
	}

	return TRUE;

error:
	g_strfreev (items);
	return FALSE;
}

static void
dcb_check_feature_enabled (NMSettingDcb *s_dcb, const char *flags_prop)
{
	NMSettingDcbFlags flags = NM_SETTING_DCB_FLAG_NONE;

	g_object_get (s_dcb, flags_prop, &flags, NULL);
	if (!(flags & NM_SETTING_DCB_FLAG_ENABLE))
		g_print (_("Warning: changes will have no effect until '%s' includes 1 (enabled)\n\n"), flags_prop);
}

static gboolean
nmc_property_dcb_set_pfc (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	guint i = 0;
	guint nums[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!dcb_parse_uint_array (val, 1, 0, nums, error))
		return FALSE;

	for (i = 0; i < 8; i++)
		nm_setting_dcb_set_priority_flow_control (NM_SETTING_DCB (setting), i, !!nums[i]);

	dcb_check_feature_enabled (NM_SETTING_DCB (setting), NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS);
	return TRUE;
}

static gboolean
nmc_property_dcb_set_pg_group_id (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	guint i = 0;
	guint nums[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!dcb_parse_uint_array (val, 7, 15, nums, error))
		return FALSE;

	for (i = 0; i < 8; i++)
		nm_setting_dcb_set_priority_group_id (NM_SETTING_DCB (setting), i, nums[i]);

	dcb_check_feature_enabled (NM_SETTING_DCB (setting), NM_SETTING_DCB_PRIORITY_GROUP_FLAGS);
	return TRUE;
}

static gboolean
nmc_property_dcb_set_pg_group_bandwidth (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	guint i = 0, sum = 0;
	guint nums[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!dcb_parse_uint_array (val, 100, 0, nums, error))
		return FALSE;

	for (i = 0; i < 8; i++)
		sum += nums[i];
	if (sum != 100) {
		g_set_error_literal (error, 1, 0, _("bandwidth percentages must total 100%%"));
		return FALSE;
	}

	for (i = 0; i < 8; i++)
		nm_setting_dcb_set_priority_group_bandwidth (NM_SETTING_DCB (setting), i, nums[i]);

	dcb_check_feature_enabled (NM_SETTING_DCB (setting), NM_SETTING_DCB_PRIORITY_GROUP_FLAGS);
	return TRUE;
}

static gboolean
nmc_property_dcb_set_pg_bandwidth (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	guint i = 0;
	guint nums[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!dcb_parse_uint_array (val, 100, 0, nums, error))
		return FALSE;

	for (i = 0; i < 8; i++)
		nm_setting_dcb_set_priority_bandwidth (NM_SETTING_DCB (setting), i, nums[i]);

	dcb_check_feature_enabled (NM_SETTING_DCB (setting), NM_SETTING_DCB_PRIORITY_GROUP_FLAGS);
	return TRUE;
}

static gboolean
nmc_property_dcb_set_pg_strict (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	guint i = 0;
	guint nums[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!dcb_parse_uint_array (val, 1, 0, nums, error))
		return FALSE;

	for (i = 0; i < 8; i++)
		nm_setting_dcb_set_priority_strict_bandwidth (NM_SETTING_DCB (setting), i, !!nums[i]);

	dcb_check_feature_enabled (NM_SETTING_DCB (setting), NM_SETTING_DCB_PRIORITY_GROUP_FLAGS);
	return TRUE;
}

static gboolean
nmc_property_dcb_set_pg_traffic_class (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	guint i = 0;
	guint nums[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!dcb_parse_uint_array (val, 7, 0, nums, error))
		return FALSE;

	for (i = 0; i < 8; i++)
		nm_setting_dcb_set_priority_traffic_class (NM_SETTING_DCB (setting), i, nums[i]);

	dcb_check_feature_enabled (NM_SETTING_DCB (setting), NM_SETTING_DCB_PRIORITY_GROUP_FLAGS);
	return TRUE;
}

/* 'app-fcoe-mode' */
static const char *_dcb_valid_fcoe_modes[] = { NM_SETTING_DCB_FCOE_MODE_FABRIC,
                                               NM_SETTING_DCB_FCOE_MODE_VN2VN,
                                               NULL };

static gboolean
nmc_property_dcb_set_app_fcoe_mode (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	return check_and_set_string (setting, prop, val, _dcb_valid_fcoe_modes, error);
}

DEFINE_ALLOWED_VAL_FUNC (nmc_property_dcb_allowed_app_fcoe_modes, _dcb_valid_fcoe_modes)

/*----------------------------------------------------------------------------*/

static inline void
_nmc_add_prop_funcs (const char *key,
                     const NmcPropertyFuncs *item_init)
{
	NmcPropertyFuncs *item;

	item = g_malloc (sizeof (NmcPropertyFuncs));
	*item = *item_init;
	g_hash_table_insert (nmc_properties, (gpointer) key, item);
}

#define nmc_add_prop_funcs(key, ...) \
	G_STMT_START { \
		struct { \
			NmcPropertyFuncsFields; \
			/* The _dummy field is here so that the last argument can be always
			 * NULL. That means every call to nmc_add_prop_funcs() below ends
			 * with a separate line "NULL);". */ \
			gpointer _dummy; \
		} _item_init = { \
			__VA_ARGS__ \
		};\
		\
		nm_assert (_item_init._dummy == NULL); \
		_nmc_add_prop_funcs ("" key, (NmcPropertyFuncs *) &_item_init); \
	} G_STMT_END

/* concatenate setting name and property name */
#define GLUE(A,B) "" NM_SETTING_##A##_SETTING_NAME "" NM_SETTING_##A##_##B ""
#define GLUE_IP(A,B) "" NM_SETTING_IP##A##_CONFIG_SETTING_NAME "" NM_SETTING_IP_CONFIG_##B ""

void
nmc_properties_init (void)
{
	if (G_LIKELY (nmc_properties))
		return;

	/* create properties hash table */
	nmc_properties = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);

	/* Add editable properties for NM_SETTING_802_1X_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (802_1X, EAP),
	                    nmc_property_802_1X_get_eap,
	                    nmc_property_802_1X_set_eap,
	                    nmc_property_802_1X_remove_eap,
	                    NULL,
	                    nmc_property_802_1X_allowed_eap,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, IDENTITY),
	                    nmc_property_802_1X_get_identity,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, ANONYMOUS_IDENTITY),
	                    nmc_property_802_1X_get_anonymous_identity,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PAC_FILE),
	                    nmc_property_802_1X_get_pac_file,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, CA_CERT),
	                    nmc_property_802_1X_get_ca_cert,
	                    nmc_property_802_1X_set_ca_cert,
	                    NULL,
	                    nmc_property_802_1X_describe_ca_cert,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, CA_PATH),
	                    nmc_property_802_1X_get_ca_path,
                            nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, SUBJECT_MATCH),
	                    nmc_property_802_1X_get_subject_match,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, ALTSUBJECT_MATCHES),
	                    nmc_property_802_1X_get_altsubject_matches,
	                    nmc_property_802_1X_set_altsubject_matches,
	                    nmc_property_802_1X_remove_altsubject_matches,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, CLIENT_CERT),
	                    nmc_property_802_1X_get_client_cert,
	                    nmc_property_802_1X_set_client_cert,
	                    NULL,
	                    nmc_property_802_1X_describe_client_cert,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PHASE1_PEAPVER),
	                    nmc_property_802_1X_get_phase1_peapver,
	                    nmc_property_802_1X_set_phase1_peapver,
	                    NULL,
	                    NULL,
	                    nmc_property_802_1X_allowed_phase1_peapver,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PHASE1_PEAPLABEL),
	                    nmc_property_802_1X_get_phase1_peaplabel,
	                    nmc_property_802_1X_set_phase1_peaplabel,
	                    NULL,
	                    NULL,
	                    nmc_property_802_1X_allowed_phase1_peaplabel,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PHASE1_FAST_PROVISIONING),
	                    nmc_property_802_1X_get_phase1_fast_provisioning,
	                    nmc_property_802_1X_set_phase1_fast_provisioning,
	                    NULL,
	                    NULL,
	                    nmc_property_802_1X_allowed_phase1_fast_provisioning,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PHASE2_AUTH),
	                    nmc_property_802_1X_get_phase2_auth,
	                    nmc_property_802_1X_set_phase2_auth,
	                    NULL,
	                    NULL,
	                    nmc_property_802_1X_allowed_phase2_auth,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PHASE2_AUTHEAP),
	                    nmc_property_802_1X_get_phase2_autheap,
	                    nmc_property_802_1X_set_phase2_autheap,
	                    NULL,
	                    NULL,
	                    nmc_property_802_1X_allowed_phase2_autheap,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PHASE2_CA_CERT),
	                    nmc_property_802_1X_get_phase2_ca_cert,
	                    nmc_property_802_1X_set_phase2_ca_cert,
	                    NULL,
	                    nmc_property_802_1X_describe_phase2_ca_cert,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PHASE2_CA_PATH),
	                    nmc_property_802_1X_get_phase2_ca_path,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PHASE2_SUBJECT_MATCH),
	                    nmc_property_802_1X_get_phase2_subject_match,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PHASE2_ALTSUBJECT_MATCHES),
	                    nmc_property_802_1X_get_phase2_altsubject_matches,
	                    nmc_property_802_1X_set_phase2_altsubject_matches,
	                    nmc_property_802_1X_remove_phase2_altsubject_matches,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PHASE2_CLIENT_CERT),
	                    nmc_property_802_1X_get_phase2_client_cert,
	                    nmc_property_802_1X_set_phase2_client_cert,
	                    NULL,
	                    nmc_property_802_1X_describe_phase2_client_cert,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PASSWORD),
	                    nmc_property_802_1X_get_password,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PASSWORD_FLAGS),
	                    nmc_property_802_1X_get_password_flags,
	                    nmc_property_set_secret_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PASSWORD_RAW),
	                    nmc_property_802_1X_get_password_raw,
	                    nmc_property_802_1X_set_password_raw,
	                    NULL,
	                    nmc_property_802_1X_describe_password_raw,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PASSWORD_RAW_FLAGS),
	                    nmc_property_802_1X_get_password_raw_flags,
	                    nmc_property_set_secret_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PRIVATE_KEY),
	                    nmc_property_802_1X_get_private_key,
	                    nmc_property_802_1X_set_private_key,
	                    NULL,
	                    nmc_property_802_1X_describe_private_key,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PRIVATE_KEY_PASSWORD),
	                    nmc_property_802_1X_get_private_key_password,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PRIVATE_KEY_PASSWORD_FLAGS),
	                    nmc_property_802_1X_get_private_key_password_flags,
	                    nmc_property_set_secret_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PHASE2_PRIVATE_KEY),
	                    nmc_property_802_1X_get_phase2_private_key,
	                    nmc_property_802_1X_set_phase2_private_key,
	                    NULL,
	                    nmc_property_802_1X_describe_private_key,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PHASE2_PRIVATE_KEY_PASSWORD),
	                    nmc_property_802_1X_get_phase2_private_key_password,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PHASE2_PRIVATE_KEY_PASSWORD_FLAGS),
	                    nmc_property_802_1X_get_phase2_private_key_password_flags,
	                    nmc_property_set_secret_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PIN),
	                    nmc_property_802_1X_get_pin,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, PIN_FLAGS),
	                    nmc_property_802_1X_get_pin_flags,
	                    nmc_property_set_secret_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (802_1X, SYSTEM_CA_CERTS),
	                    nmc_property_802_1X_get_system_ca_certs,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_ADSL_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (ADSL, USERNAME),
	                    nmc_property_adsl_get_username,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (ADSL, PASSWORD),
	                    nmc_property_adsl_get_password,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (ADSL, PASSWORD_FLAGS),
	                    nmc_property_adsl_get_password_flags,
	                    nmc_property_set_secret_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (ADSL, PROTOCOL),
	                    nmc_property_adsl_get_protocol,
	                    nmc_property_adsl_set_protocol,
	                    NULL,
	                    NULL,
	                    nmc_property_adsl_allowed_protocol,
	                    NULL);
	nmc_add_prop_funcs (GLUE (ADSL, ENCAPSULATION),
	                    nmc_property_adsl_get_encapsulation,
	                    nmc_property_adsl_set_encapsulation,
	                    NULL,
	                    NULL,
	                    nmc_property_adsl_allowed_encapsulation,
	                    NULL);
	nmc_add_prop_funcs (GLUE (ADSL, VPI),
	                    nmc_property_adsl_get_vpi,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (ADSL, VCI),
	                    nmc_property_adsl_get_vci,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_BLUETOOTH_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (BLUETOOTH, BDADDR),
	                    nmc_property_bluetooth_get_bdaddr,
	                    nmc_property_set_mac,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (BLUETOOTH, TYPE),
	                    nmc_property_bluetooth_get_type,
	                    nmc_property_bluetooth_set_type,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_BOND_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (BOND, OPTIONS),
	                    nmc_property_bond_get_options,
	                    nmc_property_bond_set_options,
	                    nmc_property_bond_remove_option_options,
	                    nmc_property_bond_describe_options,
	                    nmc_property_bond_allowed_options,
	                    NULL);

	/* Add editable properties for NM_SETTING_BRIDGE_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (BRIDGE, MAC_ADDRESS),
	                    nmc_property_bridge_get_mac_address,
	                    nmc_property_set_mac,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (BRIDGE, STP),
	                    nmc_property_bridge_get_stp,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (BRIDGE, PRIORITY),
	                    nmc_property_bridge_get_priority,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (BRIDGE, FORWARD_DELAY),
	                    nmc_property_bridge_get_forward_delay,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (BRIDGE, HELLO_TIME),
	                    nmc_property_bridge_get_hello_time,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (BRIDGE, MAX_AGE),
	                    nmc_property_bridge_get_max_age,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (BRIDGE, AGEING_TIME),
	                    nmc_property_bridge_get_ageing_time,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	nmc_add_prop_funcs (GLUE (BRIDGE, MULTICAST_SNOOPING),
	                    nmc_property_bridge_get_multicast_snooping,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_BRIDGE_PORT_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (BRIDGE_PORT, PRIORITY),
	                    nmc_property_bridge_port_get_priority,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (BRIDGE_PORT, PATH_COST),
	                    nmc_property_bridge_port_get_path_cost,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (BRIDGE_PORT, HAIRPIN_MODE),
	                    nmc_property_bridge_port_get_hairpin_mode,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_CDMA_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (CDMA, NUMBER),
	                    nmc_property_cdma_get_number,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CDMA, USERNAME),
	                    nmc_property_cdma_get_username,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CDMA, PASSWORD),
	                    nmc_property_cdma_get_password,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CDMA, PASSWORD_FLAGS),
	                    nmc_property_cdma_get_password_flags,
	                    nmc_property_set_secret_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_CONNECTION_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (CONNECTION, ID),
	                    nmc_property_connection_get_id,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CONNECTION, UUID),
	                    nmc_property_connection_get_uuid,
	                    NULL, /* forbid setting/removing UUID */
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CONNECTION, INTERFACE_NAME),
	                    nmc_property_connection_get_interface_name,
	                    nmc_property_set_ifname,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CONNECTION, TYPE),
	                    nmc_property_connection_get_type,
	                    NULL, /* read-only */
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CONNECTION, AUTOCONNECT),
	                    nmc_property_connection_get_autoconnect,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CONNECTION, AUTOCONNECT_PRIORITY),
	                    nmc_property_connection_get_autoconnect_priority,
	                    nmc_property_set_int,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CONNECTION, TIMESTAMP),
	                    nmc_property_connection_get_timestamp,
	                    NULL, /* read-only */
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CONNECTION, READ_ONLY),
	                    nmc_property_connection_get_read_only,
	                    NULL, /* 'read-only' is read-only :-) */
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CONNECTION, PERMISSIONS),
	                    nmc_property_connection_get_permissions,
	                    nmc_property_connection_set_permissions,
	                    nmc_property_connection_remove_permissions,
	                    nmc_property_connection_describe_permissions,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CONNECTION, ZONE),
	                    nmc_property_connection_get_zone,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CONNECTION, MASTER),
	                    nmc_property_connection_get_master,
	                    nmc_property_con_set_master,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CONNECTION, SLAVE_TYPE),
	                    nmc_property_connection_get_slave_type,
	                    nmc_property_con_set_slave_type,
	                    NULL,
	                    NULL,
	                    nmc_property_con_allowed_slave_type,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CONNECTION, SECONDARIES),
	                    nmc_property_connection_get_secondaries,
	                    nmc_property_connection_set_secondaries,
	                    nmc_property_connection_remove_secondaries,
	                    nmc_property_connection_describe_secondaries,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CONNECTION, GATEWAY_PING_TIMEOUT),
	                    nmc_property_connection_get_gateway_ping_timeout,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (CONNECTION, METERED),
	                    nmc_property_connection_get_metered,
	                    nmc_property_connection_set_metered,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_DCB_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (DCB, APP_FCOE_FLAGS),
	                    nmc_property_dcb_get_app_fcoe_flags,
	                    nmc_property_dcb_set_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (DCB, APP_FCOE_MODE),
	                    nmc_property_dcb_get_app_fcoe_mode,
	                    nmc_property_dcb_set_app_fcoe_mode,
	                    NULL,
	                    NULL,
	                    nmc_property_dcb_allowed_app_fcoe_modes,
	                    NULL);
	nmc_add_prop_funcs (GLUE (DCB, APP_FCOE_PRIORITY),
	                    nmc_property_dcb_get_app_fcoe_priority,
	                    nmc_property_dcb_set_priority,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (DCB, APP_ISCSI_FLAGS),
	                    nmc_property_dcb_get_app_iscsi_flags,
	                    nmc_property_dcb_set_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (DCB, APP_ISCSI_PRIORITY),
	                    nmc_property_dcb_get_app_iscsi_priority,
	                    nmc_property_dcb_set_priority,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (DCB, APP_FIP_FLAGS),
	                    nmc_property_dcb_get_app_fip_flags,
	                    nmc_property_dcb_set_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (DCB, APP_FIP_PRIORITY),
	                    nmc_property_dcb_get_app_fip_priority,
	                    nmc_property_dcb_set_priority,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (DCB, PRIORITY_FLOW_CONTROL_FLAGS),
	                    nmc_property_dcb_get_pfc_flags,
	                    nmc_property_dcb_set_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (DCB, PRIORITY_FLOW_CONTROL),
	                    nmc_property_dcb_get_pfc,
	                    nmc_property_dcb_set_pfc,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (DCB, PRIORITY_GROUP_FLAGS),
	                    nmc_property_dcb_get_pg_flags,
	                    nmc_property_dcb_set_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (DCB, PRIORITY_GROUP_ID),
	                    nmc_property_dcb_get_pg_group_id,
	                    nmc_property_dcb_set_pg_group_id,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (DCB, PRIORITY_GROUP_BANDWIDTH),
	                    nmc_property_dcb_get_pg_group_bandwidth,
	                    nmc_property_dcb_set_pg_group_bandwidth,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (DCB, PRIORITY_BANDWIDTH),
	                    nmc_property_dcb_get_pg_bandwidth,
	                    nmc_property_dcb_set_pg_bandwidth,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (DCB, PRIORITY_STRICT_BANDWIDTH),
	                    nmc_property_dcb_get_pg_strict,
	                    nmc_property_dcb_set_pg_strict,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (DCB, PRIORITY_TRAFFIC_CLASS),
	                    nmc_property_dcb_get_pg_traffic_class,
	                    nmc_property_dcb_set_pg_traffic_class,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_GSM_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (GSM, NUMBER),
	                    nmc_property_gsm_get_number,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (GSM, USERNAME),
	                    nmc_property_gsm_get_username,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (GSM, PASSWORD),
	                    nmc_property_gsm_get_password,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (GSM, PASSWORD_FLAGS),
	                    nmc_property_gsm_get_password_flags,
	                    nmc_property_set_secret_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (GSM, APN),
	                    nmc_property_gsm_get_apn,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (GSM, NETWORK_ID),
	                    nmc_property_gsm_get_network_id,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (GSM, PIN),
	                    nmc_property_gsm_get_pin,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (GSM, PIN_FLAGS),
	                    nmc_property_gsm_get_pin_flags,
	                    nmc_property_set_secret_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (GSM, HOME_ONLY),
	                    nmc_property_gsm_get_home_only,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_INFINIBAND_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (INFINIBAND, MAC_ADDRESS),
	                    nmc_property_ib_get_mac_address,
	                    nmc_property_ib_set_mac,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (INFINIBAND, MTU),
	                    nmc_property_ib_get_mtu,
	                    nmc_property_set_mtu,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (INFINIBAND, TRANSPORT_MODE),
	                    nmc_property_ib_get_transport_mode,
	                    nmc_property_ib_set_transport_mode,
	                    NULL,
	                    NULL,
	                    nmc_property_ib_allowed_transport_mode,
	                    NULL);
	nmc_add_prop_funcs (GLUE (INFINIBAND, P_KEY),
	                    nmc_property_ib_get_p_key,
	                    nmc_property_ib_set_p_key,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (INFINIBAND, PARENT),
	                    nmc_property_ib_get_parent,
	                    nmc_property_set_ifname,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_IP4_CONFIG_SETTING_NAME */
	nmc_add_prop_funcs (GLUE_IP (4, METHOD),
	                    nmc_property_ipv4_get_method,
	                    nmc_property_ipv4_set_method,
	                    NULL,
	                    NULL,
	                    nmc_property_ipv4_allowed_method,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (4, DNS),
	                    nmc_property_ipv4_get_dns,
	                    nmc_property_ipv4_set_dns,
	                    nmc_property_ipv4_remove_dns,
	                    nmc_property_ipv4_describe_dns,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (4, DNS_SEARCH),
	                    nmc_property_ipv4_get_dns_search,
	                    nmc_property_ipv4_set_dns_search,
	                    nmc_property_ipv4_remove_dns_search,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (4, DNS_OPTIONS),
	                    nmc_property_ipv4_get_dns_options,
	                    nmc_property_ipv4_set_dns_options,
	                    nmc_property_ipv4_remove_dns_option,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (4, ADDRESSES),
	                    nmc_property_ip_get_addresses,
	                    nmc_property_ipv4_set_addresses,
	                    nmc_property_ipv4_remove_addresses,
	                    nmc_property_ipv4_describe_addresses,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (4, GATEWAY),
	                    nmc_property_ipv4_get_gateway,
	                    nmc_property_ipv4_set_gateway,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (4, ROUTES),
	                    nmc_property_ipv4_get_routes,
	                    nmc_property_ipv4_set_routes,
	                    nmc_property_ipv4_remove_routes,
	                    nmc_property_ipv4_describe_routes,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (4, ROUTE_METRIC),
	                    nmc_property_ipv4_get_route_metric,
	                    nmc_property_set_int64,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (4, IGNORE_AUTO_ROUTES),
	                    nmc_property_ipv4_get_ignore_auto_routes,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (4, IGNORE_AUTO_DNS),
	                    nmc_property_ipv4_get_ignore_auto_dns,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (IP4_CONFIG, DHCP_CLIENT_ID),
	                    nmc_property_ipv4_get_dhcp_client_id,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (4, DHCP_SEND_HOSTNAME),
	                    nmc_property_ipv4_get_dhcp_send_hostname,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (4, DHCP_HOSTNAME),
	                    nmc_property_ipv4_get_dhcp_hostname,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (4, NEVER_DEFAULT),
	                    nmc_property_ipv4_get_never_default,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (4, MAY_FAIL),
	                    nmc_property_ipv4_get_may_fail,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_IP6_CONFIG_SETTING_NAME */
	nmc_add_prop_funcs (GLUE_IP (6, METHOD),
	                    nmc_property_ipv6_get_method,
	                    nmc_property_ipv6_set_method,
	                    NULL,
	                    NULL,
	                    nmc_property_ipv6_allowed_method,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (6, DNS),
	                    nmc_property_ipv6_get_dns,
	                    nmc_property_ipv6_set_dns,
	                    nmc_property_ipv6_remove_dns,
	                    nmc_property_ipv6_describe_dns,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (6, DNS_SEARCH),
	                    nmc_property_ipv6_get_dns_search,
	                    nmc_property_ipv6_set_dns_search,
	                    nmc_property_ipv6_remove_dns_search,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (6, DNS_OPTIONS),
	                    nmc_property_ipv6_get_dns_options,
	                    nmc_property_ipv6_set_dns_options,
	                    nmc_property_ipv6_remove_dns_option,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (6, ADDRESSES),
	                    nmc_property_ip_get_addresses,
	                    nmc_property_ipv6_set_addresses,
	                    nmc_property_ipv6_remove_addresses,
	                    nmc_property_ipv6_describe_addresses,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (6, GATEWAY),
	                    nmc_property_ipv6_get_gateway,
	                    nmc_property_ipv6_set_gateway,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (6, ROUTES),
	                    nmc_property_ipv6_get_routes,
	                    nmc_property_ipv6_set_routes,
	                    nmc_property_ipv6_remove_routes,
	                    nmc_property_ipv6_describe_routes,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (6, ROUTE_METRIC),
	                    nmc_property_ipv6_get_route_metric,
	                    nmc_property_set_int64,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (6, IGNORE_AUTO_ROUTES),
	                    nmc_property_ipv6_get_ignore_auto_routes,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (6, IGNORE_AUTO_DNS),
	                    nmc_property_ipv6_get_ignore_auto_dns,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (6, NEVER_DEFAULT),
	                    nmc_property_ipv6_get_never_default,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (6, MAY_FAIL),
	                    nmc_property_ipv6_get_may_fail,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (IP6_CONFIG, IP6_PRIVACY),
	                    nmc_property_ipv6_get_ip6_privacy,
	                    nmc_property_ipv6_set_ip6_privacy,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (6, DHCP_SEND_HOSTNAME),
	                    nmc_property_ipv6_get_dhcp_send_hostname,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE_IP (6, DHCP_HOSTNAME),
	                    nmc_property_ipv6_get_dhcp_hostname,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_OLPC_MESH_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (OLPC_MESH, SSID),
	                    nmc_property_olpc_get_ssid,
	                    nmc_property_set_ssid,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (OLPC_MESH, CHANNEL),
	                    nmc_property_olpc_get_channel,
	                    nmc_property_olpc_set_channel,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (OLPC_MESH, DHCP_ANYCAST_ADDRESS),
	                    nmc_property_olpc_get_anycast_address,
	                    nmc_property_set_mac,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_PPP_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (PPP, NOAUTH),
	                    nmc_property_ppp_get_noauth,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, REFUSE_EAP),
	                    nmc_property_ppp_get_refuse_eap,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, REFUSE_PAP),
	                    nmc_property_ppp_get_refuse_pap,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, REFUSE_CHAP),
	                    nmc_property_ppp_get_refuse_chap,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, REFUSE_MSCHAP),
	                    nmc_property_ppp_get_refuse_mschap,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, REFUSE_MSCHAPV2),
	                    nmc_property_ppp_get_refuse_mschapv2,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, NOBSDCOMP),
	                    nmc_property_ppp_get_nobsdcomp,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, NODEFLATE),
	                    nmc_property_ppp_get_nodeflate,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, NO_VJ_COMP),
	                    nmc_property_ppp_get_no_vj_comp,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, REQUIRE_MPPE),
	                    nmc_property_ppp_get_require_mppe,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, REQUIRE_MPPE_128),
	                    nmc_property_ppp_get_require_mppe_128,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, MPPE_STATEFUL),
	                    nmc_property_ppp_get_mppe_stateful,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, CRTSCTS),
	                    nmc_property_ppp_get_crtscts,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, BAUD),
	                    nmc_property_ppp_get_baud,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, MRU),
	                    nmc_property_ppp_get_mru,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, MTU),
	                    nmc_property_ppp_get_mtu,
	                    nmc_property_set_mtu,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, LCP_ECHO_FAILURE),
	                    nmc_property_ppp_get_lcp_echo_failure,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPP, LCP_ECHO_INTERVAL),
	                    nmc_property_ppp_get_lcp_echo_interval,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_PPPOE_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (PPPOE, SERVICE),
	                    nmc_property_pppoe_get_service,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPPOE, USERNAME),
	                    nmc_property_pppoe_get_username,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPPOE, PASSWORD),
	                    nmc_property_pppoe_get_password,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (PPPOE, PASSWORD_FLAGS),
	                    nmc_property_pppoe_get_password_flags,
	                    nmc_property_set_secret_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_SERIAL_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (SERIAL, BAUD),
	                    nmc_property_serial_get_baud,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (SERIAL, BITS),
	                    nmc_property_serial_get_bits,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (SERIAL, PARITY),
	                    nmc_property_serial_get_parity,
	                    nmc_property_serial_set_parity,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (SERIAL, STOPBITS),
	                    nmc_property_serial_get_stopbits,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (SERIAL, SEND_DELAY),
	                    nmc_property_serial_get_send_delay,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_TEAM_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (TEAM, CONFIG),
	                    nmc_property_team_get_config,
	                    nmc_property_team_set_config,
	                    NULL,
	                    nmc_property_team_describe_config,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_TEAM_PORT_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (TEAM_PORT, CONFIG),
	                    nmc_property_team_port_get_config,
	                    nmc_property_team_set_config,
	                    NULL,
	                    nmc_property_team_describe_config,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_VLAN_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (VLAN, PARENT),
	                    nmc_property_vlan_get_parent,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (VLAN, ID),
	                    nmc_property_vlan_get_id,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (VLAN, FLAGS),
	                    nmc_property_vlan_get_flags,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (VLAN, INGRESS_PRIORITY_MAP),
	                    nmc_property_vlan_get_ingress_priority_map,
	                    nmc_property_vlan_set_ingress_priority_map,
	                    nmc_property_vlan_remove_ingress_priority_map,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (VLAN, EGRESS_PRIORITY_MAP),
	                    nmc_property_vlan_get_egress_priority_map,
	                    nmc_property_vlan_set_egress_priority_map,
	                    nmc_property_vlan_remove_egress_priority_map,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_VPN_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (VPN, SERVICE_TYPE),
	                    nmc_property_vpn_get_service_type,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (VPN, USER_NAME),
	                    nmc_property_vpn_get_user_name,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (VPN, DATA),
	                    nmc_property_vpn_get_data,
	                    nmc_property_vpn_set_data,
	                    nmc_property_vpn_remove_option_data,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (VPN, SECRETS),
	                    nmc_property_vpn_get_secrets,
	                    nmc_property_vpn_set_secrets,
	                    nmc_property_vpn_remove_option_secret,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (VPN, PERSISTENT),
	                    nmc_property_vpn_get_persistent,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_WIMAX_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (WIMAX, NETWORK_NAME),
	                    nmc_property_wimax_get_network_name,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIMAX, MAC_ADDRESS),
	                    nmc_property_wimax_get_mac_address,
	                    nmc_property_set_mac,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_WIRED_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (WIRED, PORT),
	                    nmc_property_wired_get_port,
	                    NULL, /*nmc_property_wired_set_port,*/
	                    NULL,
	                    NULL,
	                    NULL, /*nmc_property_wired_allowed_port,*/
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRED, SPEED),
	                    nmc_property_wired_get_speed,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRED, DUPLEX),
	                    nmc_property_wired_get_duplex,
	                    NULL, /*nmc_property_wired_set_duplex,*/
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL); /*nmc_property_wired_allowed_duplex);*/
	nmc_add_prop_funcs (GLUE (WIRED, AUTO_NEGOTIATE),
	                    nmc_property_wired_get_auto_negotiate,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRED, MAC_ADDRESS),
	                    nmc_property_wired_get_mac_address,
	                    nmc_property_set_mac,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRED, CLONED_MAC_ADDRESS),
	                    nmc_property_wired_get_cloned_mac_address,
	                    nmc_property_set_mac,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRED, MAC_ADDRESS_BLACKLIST),
	                    nmc_property_wired_get_mac_address_blacklist,
	                    nmc_property_wired_set_mac_address_blacklist,
	                    nmc_property_wired_remove_mac_address_blacklist,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRED, MTU),
	                    nmc_property_wired_get_mtu,
	                    nmc_property_set_mtu,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRED, S390_SUBCHANNELS),
	                    nmc_property_wired_get_s390_subchannels,
	                    nmc_property_wired_set_s390_subchannels,
	                    NULL,
	                    nmc_property_wired_describe_s390_subchannels,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRED, S390_NETTYPE),
	                    nmc_property_wired_get_s390_nettype,
	                    nmc_property_wired_set_s390_nettype,
	                    NULL,
	                    NULL,
	                    nmc_property_wired_allowed_s390_nettype,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRED, S390_OPTIONS),
	                    nmc_property_wired_get_s390_options,
	                    nmc_property_wired_set_s390_options,
	                    nmc_property_wired_remove_option_s390_options,
	                    nmc_property_wired_describe_s390_options,
	                    nmc_property_wired_allowed_s390_options,
	                    NULL);

	/* Add editable properties for NM_SETTING_WIRELESS_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (WIRELESS, SSID),
	                    nmc_property_wireless_get_ssid,
	                    nmc_property_set_ssid,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS, MODE),
	                    nmc_property_wireless_get_mode,
	                    nmc_property_wifi_set_mode,
	                    NULL,
	                    NULL,
	                    nmc_property_wifi_allowed_mode,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS, BAND),
	                    nmc_property_wireless_get_band,
	                    nmc_property_wifi_set_band,
	                    NULL,
	                    NULL,
	                    nmc_property_wifi_allowed_band,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS, CHANNEL),
	                    nmc_property_wireless_get_channel,
	                    nmc_property_wifi_set_channel,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS, BSSID),
	                    nmc_property_wireless_get_bssid,
	                    nmc_property_set_mac,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	/*
	 * Do not allow setting 'rate' and 'tx-power'. They are not implemented in
	 * NM core, nor in ifcfg-rh plugin (thus not preserved over re-reading).
	 */
	nmc_add_prop_funcs (GLUE (WIRELESS, RATE),
	                    nmc_property_wireless_get_rate,
	                    NULL, /* editing rate disabled */
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS, TX_POWER),
	                    nmc_property_wireless_get_tx_power,
	                    NULL, /* editing tx-power disabled */
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS, MAC_ADDRESS),
	                    nmc_property_wireless_get_mac_address,
	                    nmc_property_set_mac,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS, CLONED_MAC_ADDRESS),
	                    nmc_property_wireless_get_cloned_mac_address,
	                    nmc_property_set_mac,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS, MAC_ADDRESS_BLACKLIST),
	                    nmc_property_wireless_get_mac_address_blacklist,
	                    nmc_property_wireless_set_mac_address_blacklist,
	                    nmc_property_wireless_remove_mac_address_blacklist,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS, SEEN_BSSIDS),
	                    nmc_property_wireless_get_seen_bssids,
	                    NULL, /* read-only */
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS, MTU),
	                    nmc_property_wireless_get_mtu,
	                    nmc_property_set_mtu,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS, HIDDEN),
	                    nmc_property_wireless_get_hidden,
	                    nmc_property_set_bool,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS, POWERSAVE),
	                    nmc_property_wireless_get_powersave,
	                    nmc_property_wireless_set_powersave,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);

	/* Add editable properties for NM_SETTING_WIRELESS_SECURITY_SETTING_NAME */
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, KEY_MGMT),
	                    nmc_property_wifi_sec_get_key_mgmt,
	                    nmc_property_wifi_sec_set_key_mgmt,
	                    NULL,
	                    NULL,
	                    nmc_property_wifi_sec_allowed_key_mgmt,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, WEP_TX_KEYIDX),
	                    nmc_property_wifi_sec_get_wep_tx_keyidx,
	                    nmc_property_set_uint,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, AUTH_ALG),
	                    nmc_property_wifi_sec_get_auth_alg,
	                    nmc_property_wifi_sec_set_auth_alg,
	                    NULL,
	                    NULL,
	                    nmc_property_wifi_sec_allowed_auth_alg,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, PROTO),
	                    nmc_property_wifi_sec_get_proto,
	                    nmc_property_wifi_sec_set_proto,
	                    nmc_property_wifi_sec_remove_proto,
	                    NULL,
	                    nmc_property_wifi_sec_allowed_proto,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, PAIRWISE),
	                    nmc_property_wifi_sec_get_pairwise,
	                    nmc_property_wifi_sec_set_pairwise,
	                    nmc_property_wifi_sec_remove_pairwise,
	                    NULL,
	                    nmc_property_wifi_sec_allowed_pairwise,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, GROUP),
	                    nmc_property_wifi_sec_get_group,
	                    nmc_property_wifi_sec_set_group,
	                    nmc_property_wifi_sec_remove_group,
	                    NULL,
	                    nmc_property_wifi_sec_allowed_group,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, LEAP_USERNAME),
	                    nmc_property_wifi_sec_get_leap_username,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, WEP_KEY0),
	                    nmc_property_wifi_sec_get_wep_key0,
	                    nmc_property_wifi_set_wep_key,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, WEP_KEY1),
	                    nmc_property_wifi_sec_get_wep_key1,
	                    nmc_property_wifi_set_wep_key,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, WEP_KEY2),
	                    nmc_property_wifi_sec_get_wep_key2,
	                    nmc_property_wifi_set_wep_key,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, WEP_KEY3),
	                    nmc_property_wifi_sec_get_wep_key3,
	                    nmc_property_wifi_set_wep_key,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, WEP_KEY_FLAGS),
	                    nmc_property_wifi_sec_get_wep_key_flags,
	                    nmc_property_set_secret_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, WEP_KEY_TYPE),
	                    nmc_property_wifi_sec_get_wep_key_type,
	                    nmc_property_wifi_set_wep_key_type,
	                    NULL,
	                    nmc_property_wifi_describe_wep_key_type,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, PSK),
	                    nmc_property_wifi_sec_get_psk,
	                    nmc_property_wifi_set_psk,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, PSK_FLAGS),
	                    nmc_property_wifi_sec_get_psk_flags,
	                    nmc_property_set_secret_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, LEAP_PASSWORD),
	                    nmc_property_wifi_sec_get_leap_password,
	                    nmc_property_set_string,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
	nmc_add_prop_funcs (GLUE (WIRELESS_SECURITY, LEAP_PASSWORD_FLAGS),
	                    nmc_property_wifi_sec_get_leap_password_flags,
	                    nmc_property_set_secret_flags,
	                    NULL,
	                    NULL,
	                    NULL,
	                    NULL);
}

void
nmc_properties_cleanup ()
{
	if (nmc_properties)
		g_hash_table_destroy (nmc_properties);
}

static const NmcPropertyFuncs *
nmc_properties_find (const char *s_name, const char *p_name)
{
	char *key;
	gsize p_l, s_l;

	nmc_properties_init ();

	s_l = strlen (s_name);
	p_l = strlen (p_name);
	key = g_alloca (s_l + p_l + 1);
	memcpy (&key[  0], s_name, s_l);
	memcpy (&key[s_l], p_name, p_l + 1);
	return (NmcPropertyFuncs *) g_hash_table_lookup (nmc_properties, key);
}

static char *
get_property_val (NMSetting *setting, const char *prop, NmcPropertyGetType get_type, GError **error)
{
	const NmcPropertyFuncs *item;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	item = nmc_properties_find (nm_setting_get_name (setting), prop);
	if (item && item->get_func)
		return item->get_func (setting, get_type);

	g_set_error_literal (error, 1, 0, _("don't know how to get the property value"));
	return NULL;
}

/*
 * Generic function for getting property value.
 *
 * Gets property value as a string by calling specialized functions.
 *
 * Returns: current property value. The caller must free the returned string.
 */
char *
nmc_setting_get_property (NMSetting *setting, const char *prop, GError **error)
{
	return get_property_val (setting, prop, NMC_PROPERTY_GET_PRETTY, error);
}

/*
 * Similar to nmc_setting_get_property(), but returns the property in a string
 * format that can be parsed via nmc_setting_set_property().
 */
char *
nmc_setting_get_property_parsable (NMSetting *setting, const char *prop, GError **error)
{
	return get_property_val (setting, prop, NMC_PROPERTY_GET_PARSABLE, error);
}

/*
 * Generic function for setting property value.
 *
 * Sets property=val in setting by calling specialized functions.
 * If val is NULL then default property value is set.
 *
 * Returns: TRUE on success; FALSE on failure and sets error
 */
gboolean
nmc_setting_set_property (NMSetting *setting, const char *prop, const char *val, GError **error)
{
	const NmcPropertyFuncs *item;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	item = nmc_properties_find (nm_setting_get_name (setting), prop);
	if (item && item->set_func) {
		if (!val) {
			/* No value argument sets default value */
			nmc_property_set_default_value (setting, prop);
			return TRUE;
		}
		return item->set_func (setting, prop, val, error);
	}

	g_set_error_literal (error, 1, 0, _("the property can't be changed"));
	return FALSE;
}

void
nmc_property_set_default_value (NMSetting *setting, const char *prop)
{
	GValue value = G_VALUE_INIT;
	GParamSpec *param_spec;

	param_spec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (setting)), prop);
	if (param_spec) {
		g_value_init (&value, G_PARAM_SPEC_VALUE_TYPE (param_spec));
		g_param_value_set_default (param_spec, &value);
		g_object_set_property (G_OBJECT (setting), prop, &value);
	}
}

/*
 * Generic function for reseting (single value) properties.
 *
 * The function resets the property value to the default one. It respects
 * nmcli restrictions for changing properties. So if 'set_func' is NULL,
 * reseting the value is denied.
 *
 * Returns: TRUE on success; FALSE on failure and sets error
 */
gboolean
nmc_setting_reset_property (NMSetting *setting, const char *prop, GError **error)
{
	const NmcPropertyFuncs *item;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	item = nmc_properties_find (nm_setting_get_name (setting), prop);
	if (item && item->set_func) {
		nmc_property_set_default_value (setting, prop);
		return TRUE;
	}
	g_set_error_literal (error, 1, 0, _("the property can't be changed"));
	return FALSE;
}

/*
 * Generic function for removing items for collection-type properties.
 *
 * If 'option' is not NULL, it tries to remove it, otherwise 'idx' is used.
 * For single-value properties (not having specialized remove function) this
 * function does nothing and just returns TRUE.
 *
 * Returns: TRUE on success; FALSE on failure and sets error
 */
gboolean
nmc_setting_remove_property_option (NMSetting *setting,
                                    const char *prop,
                                    const char *option,
                                    guint32 idx,
                                    GError **error)
{
	const NmcPropertyFuncs *item;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	item = nmc_properties_find (nm_setting_get_name (setting), prop);
	if (item && item->remove_func)
		return item->remove_func (setting, prop, option, idx, error);

	return TRUE;
}

/*
 * Get valid property names for a setting.
 *
 * Returns: string array with the properties or NULL on failure.
 *          The returned value should be freed with g_strfreev()
 */
char **
nmc_setting_get_valid_properties (NMSetting *setting)
{
	char **valid_props = NULL;
	GParamSpec **props, **iter;
	guint num;
	int i;

	/* Iterate through properties */
	i = 0;
	props = g_object_class_list_properties (G_OBJECT_GET_CLASS (G_OBJECT (setting)), &num);
	valid_props = g_malloc0 (sizeof (char*) * (num + 1));
	for (iter = props; iter && *iter; iter++) {
		const char *key_name = g_param_spec_get_name (*iter);

		/* Add all properties except for "name" that is non-editable */
		if (g_strcmp0 (key_name, "name") != 0)
			valid_props[i++] = g_strdup (key_name);
	}
	valid_props[i] = NULL;
	g_free (props);

	return valid_props;
}

/*
 * Return allowed values for 'prop' as a string.
 */
const char **
nmc_setting_get_property_allowed_values (NMSetting *setting, const char *prop)
{

	const NmcPropertyFuncs *item;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);

	item = nmc_properties_find (nm_setting_get_name (setting), prop);
	if (item && item->values_func)
		return item->values_func (setting, prop);

	return NULL;
}

#if defined (BUILD_SETTING_DOCS) || defined (HAVE_SETTING_DOCS)
#include "settings-docs.c"
#else
#define nmc_setting_get_property_doc(setting, prop) _("(not available)")
#endif

/*
 * Create a description string for a property.
 *
 * It returns a description got from property documentation, concatenated with
 * nmcli specific description (if it exists).
 *
 * Returns: property description or NULL on failure. The caller must free the string.
 */
char *
nmc_setting_get_property_desc (NMSetting *setting, const char *prop)
{
	const NmcPropertyFuncs *item;
	const char *setting_desc = NULL;
	const char *setting_desc_title = "";
	const char *nmcli_desc = NULL;
	const char *nmcli_desc_title = "";
	const char *nmcli_nl = "";

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);

	setting_desc = nmc_setting_get_property_doc (setting, prop);
	if (setting_desc)
		setting_desc_title = _("[NM property description]");

	item = nmc_properties_find (nm_setting_get_name (setting), prop);
	if (item && item->describe_func) {
		nmcli_desc = item->describe_func (setting, prop);
		nmcli_desc_title = _("[nmcli specific description]");
		nmcli_nl = "\n";
	}

	return g_strdup_printf ("%s\n%s\n%s%s%s%s",
	                        setting_desc_title,
	                        setting_desc ? setting_desc : "",
	                        nmcli_nl, nmcli_desc_title, nmcli_nl,
	                        nmcli_desc ? nmcli_desc : "");
}

/*
 * Gets setting:prop property value and returns it in 'value'.
 * Caller is responsible for freeing the GValue resources using g_value_unset()
 */
gboolean
nmc_property_get_gvalue (NMSetting *setting, const char *prop, GValue *value)
{
	GParamSpec *param_spec;

	param_spec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (setting)), prop);
	if (param_spec) {
		memset (value, 0, sizeof (GValue));
		g_value_init (value, G_PARAM_SPEC_VALUE_TYPE (param_spec));
		g_object_get_property (G_OBJECT (setting), prop, value);
		return TRUE;
	}
	return FALSE;
}

/*
 * Sets setting:prop property value from 'value'.
 */
gboolean
nmc_property_set_gvalue (NMSetting *setting, const char *prop, GValue *value)
{
	GParamSpec *param_spec;

	param_spec = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (setting)), prop);
	if (param_spec && G_VALUE_TYPE (value) == G_PARAM_SPEC_VALUE_TYPE (param_spec)) {
		g_object_set_property (G_OBJECT (setting), prop, value);
		return TRUE;
	}
	return FALSE;
}

/*----------------------------------------------------------------------------*/

#define GET_SECRET(show, setting, func) \
	(show ? func (setting, NMC_PROPERTY_GET_PRETTY) : g_strdup (_("<hidden>")))

static gboolean
setting_connection_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingConnection *s_con = NM_SETTING_CONNECTION (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (s_con), FALSE);

	tmpl = nmc_fields_setting_connection;
	tmpl_len = sizeof (nmc_fields_setting_connection);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_CONNECTION_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_connection_get_id (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_connection_get_uuid (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_connection_get_interface_name (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, nmc_property_connection_get_type (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_connection_get_autoconnect (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 6, nmc_property_connection_get_autoconnect_priority (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 7, nmc_property_connection_get_timestamp (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 8, nmc_property_connection_get_read_only (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 9, nmc_property_connection_get_permissions (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 10, nmc_property_connection_get_zone (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 11, nmc_property_connection_get_master (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 12, nmc_property_connection_get_slave_type (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 13, nmc_property_connection_get_secondaries (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 14, nmc_property_connection_get_gateway_ping_timeout (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 15, nmc_property_connection_get_metered (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_wired_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingWired *s_wired = NM_SETTING_WIRED (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_WIRED (s_wired), FALSE);

	tmpl = nmc_fields_setting_wired;
	tmpl_len = sizeof (nmc_fields_setting_wired);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_WIRED_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_wired_get_port (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_wired_get_speed (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_wired_get_duplex (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, nmc_property_wired_get_auto_negotiate (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_wired_get_mac_address (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 6, nmc_property_wired_get_cloned_mac_address (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 7, nmc_property_wired_get_mac_address_blacklist (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 8, nmc_property_wired_get_mtu (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 9, nmc_property_wired_get_s390_subchannels (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 10, nmc_property_wired_get_s390_nettype (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 11, nmc_property_wired_get_s390_options (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_802_1X_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSetting8021x *s_8021x = NM_SETTING_802_1X (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (s_8021x), FALSE);

	tmpl = nmc_fields_setting_8021X;
	tmpl_len = sizeof (nmc_fields_setting_8021X);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_802_1X_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_802_1X_get_eap (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_802_1X_get_identity (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_802_1X_get_anonymous_identity (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, nmc_property_802_1X_get_pac_file (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_802_1X_get_ca_cert (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 6, nmc_property_802_1X_get_ca_path (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 7, nmc_property_802_1X_get_subject_match (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 8, nmc_property_802_1X_get_altsubject_matches (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 9, nmc_property_802_1X_get_client_cert (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 10, nmc_property_802_1X_get_phase1_peapver (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 11, nmc_property_802_1X_get_phase1_peaplabel (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 12, nmc_property_802_1X_get_phase1_fast_provisioning (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 13, nmc_property_802_1X_get_phase2_auth (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 14, nmc_property_802_1X_get_phase2_autheap (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 15, nmc_property_802_1X_get_phase2_ca_cert (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 16, nmc_property_802_1X_get_phase2_ca_path (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 17, nmc_property_802_1X_get_phase2_subject_match (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 18, nmc_property_802_1X_get_phase2_altsubject_matches (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 19, nmc_property_802_1X_get_phase2_client_cert (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 20, GET_SECRET (secrets, setting, nmc_property_802_1X_get_password));
	set_val_str (arr, 21, nmc_property_802_1X_get_password_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 22, GET_SECRET (secrets, setting, nmc_property_802_1X_get_password_raw));
	set_val_str (arr, 23, nmc_property_802_1X_get_password_raw_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 24, nmc_property_802_1X_get_private_key (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 25, GET_SECRET (secrets, setting, nmc_property_802_1X_get_private_key_password));
	set_val_str (arr, 26, nmc_property_802_1X_get_private_key_password_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 27, nmc_property_802_1X_get_phase2_private_key (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 28, GET_SECRET (secrets, setting, nmc_property_802_1X_get_phase2_private_key_password));
	set_val_str (arr, 29, nmc_property_802_1X_get_phase2_private_key_password_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 30, GET_SECRET (secrets, setting, nmc_property_802_1X_get_pin));
	set_val_str (arr, 31, nmc_property_802_1X_get_pin_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 32, nmc_property_802_1X_get_system_ca_certs (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_wireless_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingWireless *s_wireless = NM_SETTING_WIRELESS (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (s_wireless), FALSE);

	tmpl = nmc_fields_setting_wireless;
	tmpl_len = sizeof (nmc_fields_setting_wireless);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_WIRELESS_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_wireless_get_ssid (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_wireless_get_mode (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_wireless_get_band (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, nmc_property_wireless_get_channel (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_wireless_get_bssid (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 6, nmc_property_wireless_get_rate (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 7, nmc_property_wireless_get_tx_power (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 8, nmc_property_wireless_get_mac_address (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 9, nmc_property_wireless_get_cloned_mac_address (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 10, nmc_property_wireless_get_mac_address_blacklist (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 11, nmc_property_wireless_get_mtu (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 12, nmc_property_wireless_get_seen_bssids (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 13, nmc_property_wireless_get_hidden (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 14, nmc_property_wireless_get_powersave (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_wireless_security_details (NMSetting *setting, NmCli *nmc, const char *one_prop, gboolean secrets)
{
	NMSettingWirelessSecurity *s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (s_wireless_sec), FALSE);

	tmpl = nmc_fields_setting_wireless_security;
	tmpl_len = sizeof (nmc_fields_setting_wireless_security);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_WIRELESS_SECURITY_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_wifi_sec_get_key_mgmt (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_wifi_sec_get_wep_tx_keyidx (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_wifi_sec_get_auth_alg (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, nmc_property_wifi_sec_get_proto (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_wifi_sec_get_pairwise (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 6, nmc_property_wifi_sec_get_group (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 7, nmc_property_wifi_sec_get_leap_username (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 8, GET_SECRET (secrets, setting, nmc_property_wifi_sec_get_wep_key0));
	set_val_str (arr, 9, GET_SECRET (secrets, setting, nmc_property_wifi_sec_get_wep_key1));
	set_val_str (arr, 10, GET_SECRET (secrets, setting, nmc_property_wifi_sec_get_wep_key2));
	set_val_str (arr, 11, GET_SECRET (secrets, setting, nmc_property_wifi_sec_get_wep_key3));
	set_val_str (arr, 12, nmc_property_wifi_sec_get_wep_key_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 13, nmc_property_wifi_sec_get_wep_key_type (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 14, GET_SECRET (secrets, setting, nmc_property_wifi_sec_get_psk));
	set_val_str (arr, 15, nmc_property_wifi_sec_get_psk_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 16, GET_SECRET (secrets, setting, nmc_property_wifi_sec_get_leap_password));
	set_val_str (arr, 17, nmc_property_wifi_sec_get_leap_password_flags (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_ip4_config_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingIPConfig *s_ip4 = NM_SETTING_IP_CONFIG (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (s_ip4), FALSE);

	tmpl = nmc_fields_setting_ip4_config;
	tmpl_len = sizeof (nmc_fields_setting_ip4_config);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_IP4_CONFIG_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_ipv4_get_method (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_ipv4_get_dns (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_ipv4_get_dns_search (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, nmc_property_ipv4_get_dns_options (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_ip_get_addresses (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 6, nmc_property_ipv4_get_gateway (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 7, nmc_property_ipv4_get_routes (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 8, nmc_property_ipv4_get_route_metric (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 9, nmc_property_ipv4_get_ignore_auto_routes (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 10, nmc_property_ipv4_get_ignore_auto_dns (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 11, nmc_property_ipv4_get_dhcp_client_id (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 12, nmc_property_ipv4_get_dhcp_send_hostname (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 13, nmc_property_ipv4_get_dhcp_hostname (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 14, nmc_property_ipv4_get_never_default (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 15, nmc_property_ipv4_get_may_fail (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_ip6_config_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingIPConfig *s_ip6 = NM_SETTING_IP_CONFIG (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (s_ip6), FALSE);

	tmpl = nmc_fields_setting_ip6_config;
	tmpl_len = sizeof (nmc_fields_setting_ip6_config);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_IP6_CONFIG_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_ipv6_get_method (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_ipv6_get_dns (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_ipv6_get_dns_search (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, nmc_property_ipv6_get_dns_options (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_ip_get_addresses (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 6, nmc_property_ipv6_get_gateway (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 7, nmc_property_ipv6_get_routes (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 8, nmc_property_ipv6_get_route_metric (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 9, nmc_property_ipv6_get_ignore_auto_routes (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 10, nmc_property_ipv6_get_ignore_auto_dns (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 11, nmc_property_ipv6_get_never_default (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 12, nmc_property_ipv6_get_may_fail (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 13, nmc_property_ipv6_get_ip6_privacy (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 14, nmc_property_ipv6_get_dhcp_send_hostname (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 15, nmc_property_ipv6_get_dhcp_hostname (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_serial_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingSerial *s_serial = NM_SETTING_SERIAL (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_SERIAL (s_serial), FALSE);

	tmpl = nmc_fields_setting_serial;
	tmpl_len = sizeof (nmc_fields_setting_serial);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_SERIAL_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_serial_get_baud (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_serial_get_bits (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_serial_get_parity (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, nmc_property_serial_get_stopbits (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_serial_get_send_delay (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_ppp_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingPpp *s_ppp = NM_SETTING_PPP (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_PPP (s_ppp), FALSE);

	tmpl = nmc_fields_setting_ppp;
	tmpl_len = sizeof (nmc_fields_setting_ppp);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_PPP_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_ppp_get_noauth (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_ppp_get_refuse_eap (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_ppp_get_refuse_pap (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, nmc_property_ppp_get_refuse_chap (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_ppp_get_refuse_mschap (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 6, nmc_property_ppp_get_refuse_mschapv2 (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 7, nmc_property_ppp_get_nobsdcomp (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 8, nmc_property_ppp_get_nodeflate (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 9, nmc_property_ppp_get_no_vj_comp (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 10, nmc_property_ppp_get_require_mppe (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 11, nmc_property_ppp_get_require_mppe_128 (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 12, nmc_property_ppp_get_mppe_stateful (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 13, nmc_property_ppp_get_crtscts (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 14, nmc_property_ppp_get_baud (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 15, nmc_property_ppp_get_mru (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 16, nmc_property_ppp_get_mtu (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 17, nmc_property_ppp_get_lcp_echo_failure (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 18, nmc_property_ppp_get_lcp_echo_interval (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_pppoe_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingPppoe *s_pppoe = NM_SETTING_PPPOE (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_PPPOE (s_pppoe), FALSE);

	tmpl = nmc_fields_setting_pppoe;
	tmpl_len = sizeof (nmc_fields_setting_pppoe);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_PPPOE_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_pppoe_get_service (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_pppoe_get_username (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, GET_SECRET (secrets, setting, nmc_property_pppoe_get_password));
	set_val_str (arr, 4, nmc_property_pppoe_get_password_flags (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_gsm_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingGsm *s_gsm = NM_SETTING_GSM (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_GSM (s_gsm), FALSE);

	tmpl = nmc_fields_setting_gsm;
	tmpl_len = sizeof (nmc_fields_setting_gsm);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_GSM_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_gsm_get_number (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_gsm_get_username (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, GET_SECRET (secrets, setting, nmc_property_gsm_get_password));
	set_val_str (arr, 4, nmc_property_gsm_get_password_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_gsm_get_apn (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 6, nmc_property_gsm_get_network_id (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 7, GET_SECRET (secrets, setting, nmc_property_gsm_get_pin));
	set_val_str (arr, 8, nmc_property_gsm_get_pin_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 9, nmc_property_gsm_get_home_only (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_cdma_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingCdma *s_cdma = NM_SETTING_CDMA (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_CDMA (s_cdma), FALSE);

	tmpl = nmc_fields_setting_cdma;
	tmpl_len = sizeof (nmc_fields_setting_cdma);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_CDMA_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_cdma_get_number (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_cdma_get_username (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, GET_SECRET (secrets, setting, nmc_property_cdma_get_password));
	set_val_str (arr, 4, nmc_property_cdma_get_password_flags (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_bluetooth_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingBluetooth *s_bluetooth = NM_SETTING_BLUETOOTH (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_BLUETOOTH (s_bluetooth), FALSE);

	tmpl = nmc_fields_setting_bluetooth;
	tmpl_len = sizeof (nmc_fields_setting_bluetooth);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_BLUETOOTH_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_bluetooth_get_bdaddr (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_bluetooth_get_type (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_olpc_mesh_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingOlpcMesh *s_olpc_mesh = NM_SETTING_OLPC_MESH (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_OLPC_MESH (s_olpc_mesh), FALSE);

	tmpl = nmc_fields_setting_olpc_mesh;
	tmpl_len = sizeof (nmc_fields_setting_olpc_mesh);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_OLPC_MESH_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_olpc_get_ssid (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_olpc_get_channel (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_olpc_get_anycast_address (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_vpn_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingVpn *s_vpn = NM_SETTING_VPN (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_VPN (s_vpn), FALSE);

	tmpl = nmc_fields_setting_vpn;
	tmpl_len = sizeof (nmc_fields_setting_vpn);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_VPN_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_vpn_get_service_type (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_vpn_get_user_name (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_vpn_get_data (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, GET_SECRET (secrets, setting, nmc_property_vpn_get_secrets));
	set_val_str (arr, 5, nmc_property_vpn_get_persistent (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_wimax_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingWimax *s_wimax = NM_SETTING_WIMAX (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_WIMAX (s_wimax), FALSE);

	tmpl = nmc_fields_setting_wimax;
	tmpl_len = sizeof (nmc_fields_setting_wimax);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_WIMAX_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_wimax_get_mac_address (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_wimax_get_network_name (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_infiniband_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingInfiniband *s_infiniband = NM_SETTING_INFINIBAND (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_INFINIBAND (s_infiniband), FALSE);

	tmpl = nmc_fields_setting_infiniband;
	tmpl_len = sizeof (nmc_fields_setting_infiniband);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_INFINIBAND_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_ib_get_mac_address (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_ib_get_mtu (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_ib_get_transport_mode (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, nmc_property_ib_get_p_key (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_ib_get_parent (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_bond_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingBond *s_bond = NM_SETTING_BOND (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_BOND (s_bond), FALSE);

	tmpl = nmc_fields_setting_bond;
	tmpl_len = sizeof (nmc_fields_setting_bond);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_BOND_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_bond_get_options (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_vlan_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingVlan *s_vlan = NM_SETTING_VLAN (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_VLAN (s_vlan), FALSE);

	tmpl = nmc_fields_setting_vlan;
	tmpl_len = sizeof (nmc_fields_setting_vlan);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_VLAN_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_vlan_get_parent (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_vlan_get_id (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_vlan_get_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, nmc_property_vlan_get_ingress_priority_map (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_vlan_get_egress_priority_map (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_adsl_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingAdsl *s_adsl = NM_SETTING_ADSL (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_ADSL (s_adsl), FALSE);

	tmpl = nmc_fields_setting_adsl;
	tmpl_len = sizeof (nmc_fields_setting_adsl);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_ADSL_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_adsl_get_username (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, GET_SECRET (secrets, setting, nmc_property_adsl_get_password));
	set_val_str (arr, 3, nmc_property_adsl_get_password_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, nmc_property_adsl_get_protocol (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_adsl_get_encapsulation (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 6, nmc_property_adsl_get_vpi (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 7, nmc_property_adsl_get_vci (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_bridge_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingBridge *s_bridge = NM_SETTING_BRIDGE (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (s_bridge), FALSE);

	tmpl = nmc_fields_setting_bridge;
	tmpl_len = sizeof (nmc_fields_setting_bridge);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_BRIDGE_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_bridge_get_mac_address (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_bridge_get_stp (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_bridge_get_priority (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, nmc_property_bridge_get_forward_delay (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_bridge_get_hello_time (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 6, nmc_property_bridge_get_max_age (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 7, nmc_property_bridge_get_ageing_time (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 8, nmc_property_bridge_get_multicast_snooping (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_bridge_port_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingBridgePort *s_bridge_port = NM_SETTING_BRIDGE_PORT (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_BRIDGE_PORT (s_bridge_port), FALSE);

	tmpl = nmc_fields_setting_bridge_port;
	tmpl_len = sizeof (nmc_fields_setting_bridge_port);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_BRIDGE_PORT_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_bridge_port_get_priority (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_bridge_port_get_path_cost (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_bridge_port_get_hairpin_mode (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_team_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingTeam *s_team = NM_SETTING_TEAM (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_TEAM (s_team), FALSE);

	tmpl = nmc_fields_setting_team;
	tmpl_len = sizeof (nmc_fields_setting_team);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_TEAM_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_team_get_config (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_team_port_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingTeamPort *s_team_port = NM_SETTING_TEAM_PORT (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (s_team_port), FALSE);

	tmpl = nmc_fields_setting_team_port;
	tmpl_len = sizeof (nmc_fields_setting_team_port);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_TEAM_PORT_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_team_port_get_config (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

static gboolean
setting_dcb_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	NMSettingDcb *s_dcb = NM_SETTING_DCB (setting);
	NmcOutputField *tmpl, *arr;
	size_t tmpl_len;

	g_return_val_if_fail (NM_IS_SETTING_DCB (s_dcb), FALSE);

	tmpl = nmc_fields_setting_dcb;
	tmpl_len = sizeof (nmc_fields_setting_dcb);
	nmc->print_fields.indices = parse_output_fields (one_prop ? one_prop : NMC_FIELDS_SETTING_DCB_ALL,
	                                                 tmpl, FALSE, NULL, NULL);
	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_FIELD_NAMES);
	g_ptr_array_add (nmc->output_data, arr);

	arr = nmc_dup_fields_array (tmpl, tmpl_len, NMC_OF_FLAG_SECTION_PREFIX);
	set_val_str (arr, 0, g_strdup (nm_setting_get_name (setting)));
	set_val_str (arr, 1, nmc_property_dcb_get_app_fcoe_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 2, nmc_property_dcb_get_app_fcoe_priority (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 3, nmc_property_dcb_get_app_fcoe_mode (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 4, nmc_property_dcb_get_app_iscsi_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 5, nmc_property_dcb_get_app_iscsi_priority (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 6, nmc_property_dcb_get_app_fip_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 7, nmc_property_dcb_get_app_fip_priority (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 8, nmc_property_dcb_get_pfc_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 9, nmc_property_dcb_get_pfc (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 10, nmc_property_dcb_get_pg_flags (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 11, nmc_property_dcb_get_pg_group_id (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 12, nmc_property_dcb_get_pg_group_bandwidth (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 13, nmc_property_dcb_get_pg_bandwidth (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 14, nmc_property_dcb_get_pg_strict (setting, NMC_PROPERTY_GET_PRETTY));
	set_val_str (arr, 15, nmc_property_dcb_get_pg_traffic_class (setting, NMC_PROPERTY_GET_PRETTY));
	g_ptr_array_add (nmc->output_data, arr);

	print_data (nmc);  /* Print all data */

	return TRUE;
}

typedef struct {
	const char *sname;
	gboolean (*func) (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets);
} SettingDetails;

static const SettingDetails detail_printers[] = {
	{ NM_SETTING_CONNECTION_SETTING_NAME,        setting_connection_details },
	{ NM_SETTING_WIRED_SETTING_NAME,             setting_wired_details },
	{ NM_SETTING_802_1X_SETTING_NAME,            setting_802_1X_details },
	{ NM_SETTING_WIRELESS_SETTING_NAME,          setting_wireless_details },
	{ NM_SETTING_WIRELESS_SECURITY_SETTING_NAME, setting_wireless_security_details },
	{ NM_SETTING_IP4_CONFIG_SETTING_NAME,        setting_ip4_config_details },
	{ NM_SETTING_IP6_CONFIG_SETTING_NAME,        setting_ip6_config_details },
	{ NM_SETTING_SERIAL_SETTING_NAME,            setting_serial_details },
	{ NM_SETTING_PPP_SETTING_NAME,               setting_ppp_details },
	{ NM_SETTING_PPPOE_SETTING_NAME,             setting_pppoe_details },
	{ NM_SETTING_GSM_SETTING_NAME,               setting_gsm_details },
	{ NM_SETTING_CDMA_SETTING_NAME,              setting_cdma_details },
	{ NM_SETTING_BLUETOOTH_SETTING_NAME,         setting_bluetooth_details },
	{ NM_SETTING_OLPC_MESH_SETTING_NAME,         setting_olpc_mesh_details },
	{ NM_SETTING_VPN_SETTING_NAME,               setting_vpn_details },
	{ NM_SETTING_WIMAX_SETTING_NAME,             setting_wimax_details },
	{ NM_SETTING_INFINIBAND_SETTING_NAME,        setting_infiniband_details },
	{ NM_SETTING_BOND_SETTING_NAME,              setting_bond_details },
	{ NM_SETTING_VLAN_SETTING_NAME,              setting_vlan_details },
	{ NM_SETTING_ADSL_SETTING_NAME,              setting_adsl_details },
	{ NM_SETTING_BRIDGE_SETTING_NAME,            setting_bridge_details },
	{ NM_SETTING_BRIDGE_PORT_SETTING_NAME,       setting_bridge_port_details },
	{ NM_SETTING_TEAM_SETTING_NAME,              setting_team_details },
	{ NM_SETTING_TEAM_PORT_SETTING_NAME,         setting_team_port_details },
	{ NM_SETTING_DCB_SETTING_NAME,               setting_dcb_details },
	{ NULL },
};

gboolean
setting_details (NMSetting *setting, NmCli *nmc,  const char *one_prop, gboolean secrets)
{
	const SettingDetails *iter = &detail_printers[0];

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);

	while (iter->sname) {
		if (nm_setting_lookup_type (iter->sname) == G_OBJECT_TYPE (setting))
			return iter->func (setting, nmc, one_prop, secrets);
		iter++;
	}

	g_assert_not_reached ();
	return FALSE;
}

