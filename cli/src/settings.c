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
 * (C) Copyright 2010 Red Hat, Inc.
 */

#include <glib.h>
#include <glib/gi18n.h>
#include <libnm-util/nm-utils.h>

#include "utils.h"
#include "settings.h"


/* Helper macro to define fields */
#define SETTING_FIELD(setting, width) { setting, N_(setting), width, NULL, 0 }

/* Available fields for NM_SETTING_CONNECTION_SETTING_NAME */
static NmcOutputField nmc_fields_setting_connection[] = {
	SETTING_FIELD ("name",  15),                            /* 0 */
	SETTING_FIELD (NM_SETTING_CONNECTION_ID, 25),           /* 1 */
	SETTING_FIELD (NM_SETTING_CONNECTION_UUID, 38),         /* 2 */
	SETTING_FIELD (NM_SETTING_CONNECTION_TYPE, 17),         /* 3 */
	SETTING_FIELD (NM_SETTING_CONNECTION_AUTOCONNECT, 13),  /* 4 */
	SETTING_FIELD (NM_SETTING_CONNECTION_TIMESTAMP, 10),    /* 5 */
	SETTING_FIELD (NM_SETTING_CONNECTION_READ_ONLY, 10),    /* 6 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_SETTING_CONNECTION_ALL     "name"","\
                                              NM_SETTING_CONNECTION_ID","\
                                              NM_SETTING_CONNECTION_UUID","\
                                              NM_SETTING_CONNECTION_TYPE","\
                                              NM_SETTING_CONNECTION_AUTOCONNECT","\
                                              NM_SETTING_CONNECTION_TIMESTAMP","\
                                              NM_SETTING_CONNECTION_READ_ONLY
#define NMC_FIELDS_SETTING_CONNECTION_COMMON  NMC_FIELDS_SETTING_CONNECTION_ALL

/* Available fields for NM_SETTING_WIRED_SETTING_NAME */
static NmcOutputField nmc_fields_setting_wired[] = {
	SETTING_FIELD ("name",  17),                             /* 0 */
	SETTING_FIELD (NM_SETTING_WIRED_PORT, 8),                /* 1 */
	SETTING_FIELD (NM_SETTING_WIRED_SPEED, 10),              /* 2 */
	SETTING_FIELD (NM_SETTING_WIRED_DUPLEX, 10),             /* 3 */
	SETTING_FIELD (NM_SETTING_WIRED_AUTO_NEGOTIATE, 15),     /* 4 */
	SETTING_FIELD (NM_SETTING_WIRED_MAC_ADDRESS, 19),        /* 5 */
	SETTING_FIELD (NM_SETTING_WIRED_CLONED_MAC_ADDRESS, 19), /* 6 */
	SETTING_FIELD (NM_SETTING_WIRED_MTU, 6),                 /* 7 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_SETTING_WIRED_ALL     "name"","\
                                         NM_SETTING_WIRED_PORT","\
                                         NM_SETTING_WIRED_SPEED","\
                                         NM_SETTING_WIRED_DUPLEX","\
                                         NM_SETTING_WIRED_AUTO_NEGOTIATE","\
                                         NM_SETTING_WIRED_MAC_ADDRESS","\
                                         NM_SETTING_WIRED_CLONED_MAC_ADDRESS","\
                                         NM_SETTING_WIRED_MTU
#define NMC_FIELDS_SETTING_WIRED_COMMON  NMC_FIELDS_SETTING_WIRED_ALL

/* Available fields for NM_SETTING_802_1X_SETTING_NAME */
static NmcOutputField nmc_fields_setting_8021X[] = {
	SETTING_FIELD ("name", 10),                                         /* 0 */
	SETTING_FIELD (NM_SETTING_802_1X_EAP, 10),                          /* 1 */
	SETTING_FIELD (NM_SETTING_802_1X_IDENTITY, 15),                     /* 2 */
	SETTING_FIELD (NM_SETTING_802_1X_ANONYMOUS_IDENTITY, 15),           /* 3 */
	SETTING_FIELD (NM_SETTING_802_1X_CA_CERT, 10),                      /* 4 */
	SETTING_FIELD (NM_SETTING_802_1X_CA_PATH, 10),                      /* 5 */
	SETTING_FIELD (NM_SETTING_802_1X_CLIENT_CERT, 10),                  /* 6 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE1_PEAPVER, 10),               /* 7 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE1_PEAPLABEL, 10),             /* 8 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING, 10),     /* 9 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_AUTH, 10),                  /* 10 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_AUTHEAP, 10),               /* 11 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_CA_CERT, 20),               /* 12 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_CA_PATH, 20),               /* 13 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_CLIENT_CERT, 20),           /* 14 */
	SETTING_FIELD (NM_SETTING_802_1X_PASSWORD, 10),                     /* 15 */
	SETTING_FIELD (NM_SETTING_802_1X_PRIVATE_KEY, 15),                  /* 16 */
	SETTING_FIELD (NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD, 20),         /* 17 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY, 20),           /* 18 */
	SETTING_FIELD (NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD, 20),  /* 19 */
	SETTING_FIELD (NM_SETTING_802_1X_PIN, 8),                           /* 20 */
	SETTING_FIELD (NM_SETTING_802_1X_PSK, 8),                           /* 21 */
	SETTING_FIELD (NM_SETTING_802_1X_SYSTEM_CA_CERTS, 17),              /* 22 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_SETTING_802_1X_ALL     "name"","\
                                          NM_SETTING_802_1X_EAP","\
                                          NM_SETTING_802_1X_IDENTITY","\
                                          NM_SETTING_802_1X_ANONYMOUS_IDENTITY","\
                                          NM_SETTING_802_1X_CA_CERT","\
                                          NM_SETTING_802_1X_CA_PATH","\
                                          NM_SETTING_802_1X_CLIENT_CERT","\
                                          NM_SETTING_802_1X_PHASE1_PEAPVER","\
                                          NM_SETTING_802_1X_PHASE1_PEAPLABEL","\
                                          NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING","\
                                          NM_SETTING_802_1X_PHASE2_AUTH","\
                                          NM_SETTING_802_1X_PHASE2_AUTHEAP","\
                                          NM_SETTING_802_1X_PHASE2_CA_CERT","\
                                          NM_SETTING_802_1X_PHASE2_CA_PATH","\
                                          NM_SETTING_802_1X_PHASE2_CLIENT_CERT","\
                                          NM_SETTING_802_1X_PASSWORD","\
                                          NM_SETTING_802_1X_PRIVATE_KEY","\
                                          NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD","\
                                          NM_SETTING_802_1X_PHASE2_PRIVATE_KEY","\
                                          NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD","\
                                          NM_SETTING_802_1X_PIN","\
                                          NM_SETTING_802_1X_PSK","\
                                          NM_SETTING_802_1X_SYSTEM_CA_CERTS
#define NMC_FIELDS_SETTING_802_1X_COMMON  NMC_FIELDS_SETTING_802_1X_ALL

/* Available fields for NM_SETTING_WIRELESS_SETTING_NAME */
static NmcOutputField nmc_fields_setting_wireless[] = {
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
	SETTING_FIELD (NM_SETTING_WIRELESS_MTU, 6),                        /* 10 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SEEN_BSSIDS, 35),               /* 11 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SEC, 10),                       /* 12 */
	{NULL, NULL, 0, NULL, 0}
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
                                            NM_SETTING_WIRELESS_MTU","\
                                            NM_SETTING_WIRELESS_SEEN_BSSIDS","\
                                            NM_SETTING_WIRELESS_SEC
#define NMC_FIELDS_SETTING_WIRELESS_COMMON  NMC_FIELDS_SETTING_WIRELESS_ALL

/* Available fields for NM_SETTING_WIRELESS_SECURITY_SETTING_NAME */
static NmcOutputField nmc_fields_setting_wireless_security[] = {
	SETTING_FIELD ("name", 25),                                      /* 0 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, 10),       /* 1 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, 15),  /* 2 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, 10),       /* 3 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_PROTO, 10),          /* 4 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_PAIRWISE, 10),       /* 5 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_GROUP, 10),          /* 6 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, 15),  /* 7 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_WEP_KEY0, 10),       /* 8 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_WEP_KEY1, 10),       /* 9 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_WEP_KEY2, 10),       /* 10 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_WEP_KEY3, 10),       /* 11 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_PSK, 6),             /* 12 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD, 15),  /* 13 */
	SETTING_FIELD (NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, 15),   /* 14 */
	{NULL, NULL, 0, NULL, 0}
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
                                                     NM_SETTING_WIRELESS_SECURITY_PSK","\
                                                     NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD","\
                                                     NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE
#define NMC_FIELDS_SETTING_WIRELESS_SECURITY_COMMON  NMC_FIELDS_SETTING_WIRELESS_SECURITY_ALL

/* Available fields for NM_SETTING_IP4_CONFIG_SETTING_NAME */
static NmcOutputField nmc_fields_setting_ip4_config[] = {
	SETTING_FIELD ("name", 8),                                         /* 0 */
	SETTING_FIELD (NM_SETTING_IP4_CONFIG_METHOD, 10),                  /* 1 */
	SETTING_FIELD (NM_SETTING_IP4_CONFIG_DNS, 20),                     /* 2 */
	SETTING_FIELD (NM_SETTING_IP4_CONFIG_DNS_SEARCH, 15),              /* 3 */
	SETTING_FIELD (NM_SETTING_IP4_CONFIG_ADDRESSES, 20),               /* 4 */
	SETTING_FIELD (NM_SETTING_IP4_CONFIG_ROUTES, 20),                  /* 5 */
	SETTING_FIELD (NM_SETTING_IP4_CONFIG_IGNORE_AUTO_ROUTES, 19),      /* 6 */
	SETTING_FIELD (NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS, 16),         /* 7 */
	SETTING_FIELD (NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID, 15),          /* 8 */
	SETTING_FIELD (NM_SETTING_IP4_CONFIG_DHCP_SEND_HOSTNAME, 19),      /* 9 */
	SETTING_FIELD (NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME, 14),           /* 10 */
	SETTING_FIELD (NM_SETTING_IP4_CONFIG_NEVER_DEFAULT, 15),           /* 11 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_SETTING_IP4_CONFIG_ALL     "name"","\
                                              NM_SETTING_IP4_CONFIG_METHOD","\
                                              NM_SETTING_IP4_CONFIG_DNS","\
                                              NM_SETTING_IP4_CONFIG_DNS_SEARCH","\
                                              NM_SETTING_IP4_CONFIG_ADDRESSES","\
                                              NM_SETTING_IP4_CONFIG_ROUTES","\
                                              NM_SETTING_IP4_CONFIG_IGNORE_AUTO_ROUTES","\
                                              NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS","\
                                              NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID","\
                                              NM_SETTING_IP4_CONFIG_DHCP_SEND_HOSTNAME","\
                                              NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME","\
                                              NM_SETTING_IP4_CONFIG_NEVER_DEFAULT
#define NMC_FIELDS_SETTING_IP4_CONFIG_COMMON  NMC_FIELDS_SETTING_IP4_CONFIG_ALL

/* Available fields for NM_SETTING_IP6_CONFIG_SETTING_NAME */
static NmcOutputField nmc_fields_setting_ip6_config[] = {
	SETTING_FIELD ("name", 8),                                         /* 0 */
	SETTING_FIELD (NM_SETTING_IP6_CONFIG_METHOD, 10),                  /* 1 */
	SETTING_FIELD (NM_SETTING_IP6_CONFIG_DNS, 20),                     /* 2 */
	SETTING_FIELD (NM_SETTING_IP6_CONFIG_DNS_SEARCH, 15),              /* 3 */
	SETTING_FIELD (NM_SETTING_IP6_CONFIG_ADDRESSES, 20),               /* 4 */
	SETTING_FIELD (NM_SETTING_IP6_CONFIG_ROUTES, 20),                  /* 5 */
	SETTING_FIELD (NM_SETTING_IP6_CONFIG_IGNORE_AUTO_ROUTES, 19),      /* 6 */
	SETTING_FIELD (NM_SETTING_IP6_CONFIG_IGNORE_AUTO_DNS, 16),         /* 7 */
	SETTING_FIELD (NM_SETTING_IP6_CONFIG_NEVER_DEFAULT, 15),           /* 8 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_SETTING_IP6_CONFIG_ALL     "name"","\
                                              NM_SETTING_IP6_CONFIG_METHOD","\
                                              NM_SETTING_IP6_CONFIG_DNS","\
                                              NM_SETTING_IP6_CONFIG_DNS_SEARCH","\
                                              NM_SETTING_IP6_CONFIG_ADDRESSES","\
                                              NM_SETTING_IP6_CONFIG_ROUTES","\
                                              NM_SETTING_IP6_CONFIG_IGNORE_AUTO_ROUTES","\
                                              NM_SETTING_IP6_CONFIG_IGNORE_AUTO_DNS","\
                                              NM_SETTING_IP6_CONFIG_NEVER_DEFAULT
#define NMC_FIELDS_SETTING_IP6_CONFIG_COMMON  NMC_FIELDS_SETTING_IP4_CONFIG_ALL

/* Available fields for NM_SETTING_SERIAL_SETTING_NAME */
static NmcOutputField nmc_fields_setting_serial[] = {
	SETTING_FIELD ("name", 10),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_SERIAL_BAUD, 10),                        /* 1 */
	SETTING_FIELD (NM_SETTING_SERIAL_BITS, 10),                        /* 2 */
	SETTING_FIELD (NM_SETTING_SERIAL_PARITY, 10),                      /* 3 */
	SETTING_FIELD (NM_SETTING_SERIAL_STOPBITS, 10),                    /* 4 */
	SETTING_FIELD (NM_SETTING_SERIAL_SEND_DELAY, 12),                  /* 5 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_SETTING_SERIAL_ALL     "name"","\
                                          NM_SETTING_SERIAL_BAUD","\
                                          NM_SETTING_SERIAL_BITS","\
                                          NM_SETTING_SERIAL_PARITY","\
                                          NM_SETTING_SERIAL_STOPBITS","\
                                          NM_SETTING_SERIAL_SEND_DELAY
#define NMC_FIELDS_SETTING_SERIAL_COMMON  NMC_FIELDS_SETTING_SERIAL_ALL

/* Available fields for NM_SETTING_PPP_SETTING_NAME */
static NmcOutputField nmc_fields_setting_ppp[] = {
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
	{NULL, NULL, 0, NULL, 0}
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
static NmcOutputField nmc_fields_setting_pppoe[] = {
	SETTING_FIELD ("name", 10),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_PPPOE_SERVICE, 12),                      /* 1 */
	SETTING_FIELD (NM_SETTING_PPPOE_USERNAME, 15),                     /* 2 */
	SETTING_FIELD (NM_SETTING_PPPOE_PASSWORD, 15),                     /* 3 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_SETTING_PPPOE_ALL     "name"","\
                                         NM_SETTING_PPPOE_SERVICE","\
                                         NM_SETTING_PPPOE_USERNAME","\
                                         NM_SETTING_PPPOE_PASSWORD
#define NMC_FIELDS_SETTING_PPPOE_COMMON  NMC_FIELDS_SETTING_PPP_ALL

/* Available fields for NM_SETTING_GSM_SETTING_NAME */
static NmcOutputField nmc_fields_setting_gsm[] = {
	SETTING_FIELD ("name", 10),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_GSM_NUMBER, 10),                         /* 1 */
	SETTING_FIELD (NM_SETTING_GSM_USERNAME, 15),                       /* 2 */
	SETTING_FIELD (NM_SETTING_GSM_PASSWORD, 15),                       /* 3 */
	SETTING_FIELD (NM_SETTING_GSM_APN, 25),                            /* 4 */
	SETTING_FIELD (NM_SETTING_GSM_NETWORK_ID, 12),                     /* 5 */
	SETTING_FIELD (NM_SETTING_GSM_NETWORK_TYPE, 15),                   /* 6 */
	SETTING_FIELD (NM_SETTING_GSM_ALLOWED_BANDS, 15),                  /* 7 */
	SETTING_FIELD (NM_SETTING_GSM_PIN, 10),                            /* 8 */
	SETTING_FIELD (NM_SETTING_GSM_HOME_ONLY, 10),                      /* 9 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_SETTING_GSM_ALL     "name"","\
                                       NM_SETTING_GSM_NUMBER","\
                                       NM_SETTING_GSM_USERNAME","\
                                       NM_SETTING_GSM_PASSWORD","\
                                       NM_SETTING_GSM_APN","\
                                       NM_SETTING_GSM_NETWORK_ID","\
                                       NM_SETTING_GSM_NETWORK_TYPE","\
                                       NM_SETTING_GSM_ALLOWED_BANDS","\
                                       NM_SETTING_GSM_PIN","\
                                       NM_SETTING_GSM_HOME_ONLY
#define NMC_FIELDS_SETTING_GSM_COMMON  NMC_FIELDS_SETTING_GSM_ALL

/* Available fields for NM_SETTING_CDMA_SETTING_NAME */
static NmcOutputField nmc_fields_setting_cdma[] = {
	SETTING_FIELD ("name", 10),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_CDMA_NUMBER, 15),                        /* 1 */
	SETTING_FIELD (NM_SETTING_CDMA_USERNAME, 15),                      /* 2 */
	SETTING_FIELD (NM_SETTING_CDMA_PASSWORD, 15),                      /* 3 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_SETTING_CDMA_ALL     "name"","\
                                        NM_SETTING_CDMA_NUMBER","\
                                        NM_SETTING_CDMA_USERNAME","\
                                        NM_SETTING_CDMA_PASSWORD
#define NMC_FIELDS_SETTING_CDMA_COMMON  NMC_FIELDS_SETTING_CDMA_ALL

/* Available fields for NM_SETTING_BLUETOOTH_SETTING_NAME */
static NmcOutputField nmc_fields_setting_bluetooth[] = {
	SETTING_FIELD ("name", 11),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_BLUETOOTH_BDADDR, 19),                   /* 1 */
	SETTING_FIELD (NM_SETTING_BLUETOOTH_TYPE, 10),                     /* 2 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_SETTING_BLUETOOTH_ALL     "name"","\
                                             NM_SETTING_BLUETOOTH_BDADDR","\
                                             NM_SETTING_BLUETOOTH_TYPE
#define NMC_FIELDS_SETTING_BLUETOOTH_COMMON  NMC_FIELDS_SETTING_BLUETOOTH_ALL

/* Available fields for NM_SETTING_OLPC_MESH_SETTING_NAME */
static NmcOutputField nmc_fields_setting_olpc_mesh[] = {
	SETTING_FIELD ("name", 18),                                        /* 0 */
	SETTING_FIELD (NM_SETTING_OLPC_MESH_SSID, 34),                     /* 1 */
	SETTING_FIELD (NM_SETTING_OLPC_MESH_CHANNEL, 12),                  /* 2 */
	SETTING_FIELD (NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS, 17),     /* 3 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_SETTING_OLPC_MESH_ALL     "name"","\
                                             NM_SETTING_OLPC_MESH_SSID","\
                                             NM_SETTING_OLPC_MESH_CHANNEL","\
                                             NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS
#define NMC_FIELDS_SETTING_OLPC_MESH_COMMON  NMC_FIELDS_SETTING_OLPC_MESH_ALL

/* Available fields for NM_SETTING_VPN_SETTING_NAME */
static NmcOutputField nmc_fields_setting_vpn[] = {
	SETTING_FIELD ("name", 6),                                         /* 0 */
	SETTING_FIELD (NM_SETTING_VPN_SERVICE_TYPE, 40),                   /* 1 */
	SETTING_FIELD (NM_SETTING_VPN_USER_NAME, 12),                      /* 2 */
	SETTING_FIELD (NM_SETTING_VPN_DATA, 30),                           /* 3 */
	SETTING_FIELD (NM_SETTING_VPN_SECRETS, 15),                        /* 4 */
	{NULL, NULL, 0, NULL, 0}
};
#define NMC_FIELDS_SETTING_VPN_ALL     "name"","\
                                       NM_SETTING_VPN_SERVICE_TYPE","\
                                       NM_SETTING_VPN_USER_NAME","\
                                       NM_SETTING_VPN_DATA","\
                                       NM_SETTING_VPN_SECRETS
#define NMC_FIELDS_SETTING_VPN_COMMON  NMC_FIELDS_SETTING_VPN_ALL


static char *
wep_key_type_to_string (NMWepKeyType type)
{
	switch (type) {
	case NM_WEP_KEY_TYPE_KEY:
		return g_strdup_printf (_("%d (hex-ascii-key)"), type);
	case NM_WEP_KEY_TYPE_PASSPHRASE:
		return g_strdup_printf (_("%d (104/128-bit passphrase)"), type);
	case NM_WEP_KEY_TYPE_UNKNOWN:
	default:
		return g_strdup_printf (_("%d (unknown)"), type);
	}
}

static char *
blob_cert_to_string (const GByteArray *array)
{
	GString *cert = NULL;
	int i;

	if (array->len > 0)
		cert = g_string_new (NULL);

	for (i = 0; i < array->len; i++) {
		g_string_append_printf (cert, "%02X", array->data[i]);
	}

	return cert ? g_string_free (cert, FALSE) : NULL;
}

static char *
allowed_bands_to_string (guint32 bands)
{
	GString *band_str;

	if (bands == NM_SETTING_GSM_BAND_UNKNOWN)
		return g_strdup (_("0 (unknown)"));

	band_str = g_string_new (NULL);
	g_string_printf (band_str, "%d (", bands);

	if (bands & NM_SETTING_GSM_BAND_ANY)
		g_string_append (band_str, _("any, "));
	if (bands & NM_SETTING_GSM_BAND_EGSM)
		g_string_append (band_str, _("900 MHz, "));
	if (bands & NM_SETTING_GSM_BAND_DCS)
		g_string_append (band_str, _("1800 MHz, "));
	if (bands & NM_SETTING_GSM_BAND_PCS)
		g_string_append (band_str, _("1900 MHz, "));
	if (bands & NM_SETTING_GSM_BAND_G850)
		g_string_append (band_str, _("850 MHz, "));
	if (bands & NM_SETTING_GSM_BAND_U2100)
		g_string_append (band_str, _("WCDMA 3GPP UMTS 2100 MHz, "));
	if (bands & NM_SETTING_GSM_BAND_U1800)
		g_string_append (band_str, _("WCDMA 3GPP UMTS 1800 MHz, "));
	if (bands & NM_SETTING_GSM_BAND_U17IV)
		g_string_append (band_str, _("WCDMA 3GPP UMTS 1700/2100 MHz, "));
	if (bands & NM_SETTING_GSM_BAND_U800)
		g_string_append (band_str, _("WCDMA 3GPP UMTS 800 MHz, "));
	if (bands & NM_SETTING_GSM_BAND_U850)
		g_string_append (band_str, _("WCDMA 3GPP UMTS 850 MHz, "));
	if (bands & NM_SETTING_GSM_BAND_U900)
		g_string_append (band_str, _("WCDMA 3GPP UMTS 900 MHz, "));
	if (bands & NM_SETTING_GSM_BAND_U17IX)
		g_string_append (band_str, _("WCDMA 3GPP UMTS 1700 MHz, "));

	if (band_str->str[band_str->len-1] == '(')
		g_string_assign (band_str, _("unknown"));
	else
		g_string_truncate (band_str, band_str->len-2);  /* chop off trailing ', ' */

	g_string_append_c (band_str, ')');

	return g_string_free (band_str, FALSE);
}


gboolean
setting_connection_details (NMSetting *setting, NmCli *nmc)
{
	NMSettingConnection *s_con;
	guint64 timestamp;
	char *timestamp_str;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), FALSE);
	s_con = (NMSettingConnection *) setting;

	nmc->allowed_fields = nmc_fields_setting_connection;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_CONNECTION_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	timestamp = nm_setting_connection_get_timestamp (s_con);
	timestamp_str = g_strdup_printf ("%" G_GUINT64_FORMAT, timestamp);

	nmc->allowed_fields[0].value = NM_SETTING_CONNECTION_SETTING_NAME;
	nmc->allowed_fields[1].value = nm_setting_connection_get_id (s_con);
	nmc->allowed_fields[2].value = nm_setting_connection_get_uuid (s_con);
	nmc->allowed_fields[3].value = nm_setting_connection_get_connection_type (s_con);
	nmc->allowed_fields[4].value = nm_setting_connection_get_autoconnect (s_con) ? _("yes") : _("no");
	nmc->allowed_fields[5].value = timestamp_str;
	nmc->allowed_fields[6].value = nm_setting_connection_get_read_only (s_con) ? ("yes") : _("no");

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_free (timestamp_str);

	return TRUE;
}

gboolean
setting_wired_details (NMSetting *setting, NmCli *nmc)
{
	NMSettingWired *s_wired;
	const GByteArray *mac;
	char *speed_str, *mtu_str, *device_mac_str = NULL, *cloned_mac_str = NULL;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), FALSE);
	s_wired = (NMSettingWired *) setting;

	nmc->allowed_fields = nmc_fields_setting_wired;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_WIRED_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	speed_str = g_strdup_printf ("%d", nm_setting_wired_get_speed (s_wired));
	mtu_str = g_strdup_printf ("%d", nm_setting_wired_get_mtu (s_wired));
	mac = nm_setting_wired_get_mac_address (s_wired);
	if (mac)
		device_mac_str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X", mac->data[0], mac->data[1], mac->data[2], mac->data[3], mac->data[4], mac->data[5]);
	mac = nm_setting_wired_get_cloned_mac_address (s_wired);
	if (mac)
		cloned_mac_str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X", mac->data[0], mac->data[1], mac->data[2], mac->data[3], mac->data[4], mac->data[5]);

	nmc->allowed_fields[0].value = NM_SETTING_WIRED_SETTING_NAME;
	nmc->allowed_fields[1].value = nm_setting_wired_get_port (s_wired);
	nmc->allowed_fields[2].value = speed_str;
	nmc->allowed_fields[3].value = nm_setting_wired_get_duplex (s_wired);
	nmc->allowed_fields[4].value = nm_setting_wired_get_auto_negotiate (s_wired) ? _("yes") : _("no");
	nmc->allowed_fields[5].value = device_mac_str;
	nmc->allowed_fields[6].value = cloned_mac_str;
	nmc->allowed_fields[7].value = strcmp (mtu_str, "0") ? mtu_str : _("auto");

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_free (speed_str);
	g_free (device_mac_str);
	g_free (cloned_mac_str);
	g_free (mtu_str);

	return TRUE;
}

gboolean
setting_802_1X_details (NMSetting *setting, NmCli *nmc)
{
	NMSetting8021x *s_8021X;
	NMSetting8021xCKScheme scheme;
	GString *eap_str;
	char *ca_cert_str = NULL, *client_cert_str = NULL, *phase2_ca_cert_str = NULL;
	char *phase2_client_cert_str = NULL, *private_key_str = NULL, *phase2_private_key_str = NULL;
	int i;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_802_1X (setting), FALSE);
	s_8021X = (NMSetting8021x *) setting;

	nmc->allowed_fields = nmc_fields_setting_8021X;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_802_1X_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	eap_str = g_string_new (NULL);
	for (i = 0; i < nm_setting_802_1x_get_num_eap_methods (s_8021X); i++) {
		if (i > 0)
			g_string_append_c (eap_str, ',');
		g_string_append (eap_str, nm_setting_802_1x_get_eap_method (s_8021X, i));
	}
	scheme = nm_setting_802_1x_get_ca_cert_scheme (s_8021X);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
		ca_cert_str = blob_cert_to_string (nm_setting_802_1x_get_ca_cert_blob (s_8021X));
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
		ca_cert_str = g_strdup (nm_setting_802_1x_get_ca_cert_path (s_8021X));

	scheme = nm_setting_802_1x_get_client_cert_scheme (s_8021X);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
		client_cert_str = blob_cert_to_string (nm_setting_802_1x_get_client_cert_blob (s_8021X));
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
		client_cert_str = g_strdup (nm_setting_802_1x_get_client_cert_path (s_8021X));

	scheme = nm_setting_802_1x_get_phase2_ca_cert_scheme (s_8021X);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
		phase2_ca_cert_str = blob_cert_to_string (nm_setting_802_1x_get_phase2_ca_cert_blob (s_8021X));
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
		phase2_ca_cert_str = g_strdup (nm_setting_802_1x_get_phase2_ca_cert_path (s_8021X));

	scheme = nm_setting_802_1x_get_phase2_client_cert_scheme (s_8021X);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
		phase2_client_cert_str = blob_cert_to_string (nm_setting_802_1x_get_phase2_client_cert_blob (s_8021X));
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
		phase2_client_cert_str = g_strdup (nm_setting_802_1x_get_phase2_client_cert_path (s_8021X));

	scheme = nm_setting_802_1x_get_private_key_scheme (s_8021X);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
		private_key_str = blob_cert_to_string (nm_setting_802_1x_get_private_key_blob (s_8021X));
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
		private_key_str = g_strdup (nm_setting_802_1x_get_private_key_path (s_8021X));

	scheme = nm_setting_802_1x_get_phase2_private_key_scheme (s_8021X);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB)
		phase2_private_key_str = blob_cert_to_string (nm_setting_802_1x_get_phase2_private_key_blob (s_8021X));
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH)
		phase2_private_key_str = g_strdup (nm_setting_802_1x_get_phase2_private_key_path (s_8021X));

	nmc->allowed_fields[0].value = NM_SETTING_802_1X_SETTING_NAME;
	nmc->allowed_fields[1].value = eap_str->str;
	nmc->allowed_fields[2].value = nm_setting_802_1x_get_identity (s_8021X);
	nmc->allowed_fields[3].value = nm_setting_802_1x_get_anonymous_identity (s_8021X);
	nmc->allowed_fields[4].value = ca_cert_str;
	nmc->allowed_fields[5].value = nm_setting_802_1x_get_ca_path (s_8021X);
	nmc->allowed_fields[6].value = client_cert_str;
	nmc->allowed_fields[7].value = nm_setting_802_1x_get_phase1_peapver (s_8021X);
	nmc->allowed_fields[8].value = nm_setting_802_1x_get_phase1_peaplabel (s_8021X);
	nmc->allowed_fields[9].value = nm_setting_802_1x_get_phase1_fast_provisioning (s_8021X);
	nmc->allowed_fields[10].value = nm_setting_802_1x_get_phase2_auth (s_8021X);
	nmc->allowed_fields[11].value = nm_setting_802_1x_get_phase2_autheap (s_8021X);
	nmc->allowed_fields[12].value = phase2_ca_cert_str;
	nmc->allowed_fields[13].value = nm_setting_802_1x_get_phase2_ca_path (s_8021X);
	nmc->allowed_fields[14].value = phase2_client_cert_str;
	nmc->allowed_fields[15].value = nm_setting_802_1x_get_password (s_8021X);
	nmc->allowed_fields[16].value = private_key_str;
	nmc->allowed_fields[17].value = nm_setting_802_1x_get_private_key_password (s_8021X);
	nmc->allowed_fields[18].value = phase2_private_key_str;
	nmc->allowed_fields[19].value = nm_setting_802_1x_get_phase2_private_key_password (s_8021X);
	nmc->allowed_fields[20].value = nm_setting_802_1x_get_pin (s_8021X);
	nmc->allowed_fields[21].value = nm_setting_802_1x_get_psk (s_8021X);
	nmc->allowed_fields[22].value = nm_setting_802_1x_get_system_ca_certs (s_8021X) ? _("yes") : _("no");

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_free (ca_cert_str);
	g_free (client_cert_str);
	g_free (phase2_ca_cert_str);
	g_free (phase2_client_cert_str);
	g_free (private_key_str);
	g_free (phase2_private_key_str);
	g_string_free (eap_str, TRUE);

	return TRUE;
}

gboolean
setting_wireless_details (NMSetting *setting, NmCli *nmc)
{
	NMSettingWireless *s_wireless;
	int i;
	const GByteArray *ssid, *bssid, *mac;
	char *ssid_str, *channel_str, *rate_str, *tx_power_str, *mtu_str;
	char *device_mac_str = NULL, *cloned_mac_str = NULL, *bssid_str = NULL;
	GString *seen_bssids;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS (setting), FALSE);
	s_wireless = (NMSettingWireless *) setting;

	nmc->allowed_fields = nmc_fields_setting_wireless;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_WIRELESS_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	ssid_str = ssid_to_printable ((const char *) ssid->data, ssid->len);
	channel_str = g_strdup_printf ("%d", nm_setting_wireless_get_channel (s_wireless));
	rate_str = g_strdup_printf ("%d", nm_setting_wireless_get_rate (s_wireless));
	bssid = nm_setting_wireless_get_bssid (s_wireless);
	if (bssid)
		bssid_str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X", bssid->data[0], bssid->data[1], bssid->data[2], bssid->data[3], bssid->data[4], bssid->data[5]);
	tx_power_str = g_strdup_printf ("%d", nm_setting_wireless_get_tx_power (s_wireless));
	mtu_str = g_strdup_printf ("%d", nm_setting_wireless_get_mtu (s_wireless));
	mac = nm_setting_wireless_get_mac_address (s_wireless);
	if (mac)
		device_mac_str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X", mac->data[0], mac->data[1], mac->data[2], mac->data[3], mac->data[4], mac->data[5]);
	mac = nm_setting_wireless_get_cloned_mac_address (s_wireless);
	if (mac)
		cloned_mac_str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X", mac->data[0], mac->data[1], mac->data[2], mac->data[3], mac->data[4], mac->data[5]);
	seen_bssids = g_string_new (NULL);
	for (i = 0; i < nm_setting_wireless_get_num_seen_bssids (s_wireless); i++) {
		if (i > 0)
			g_string_append_c (seen_bssids, ',');
		g_string_append (seen_bssids, nm_setting_wireless_get_seen_bssid (s_wireless, i));
	}

	nmc->allowed_fields[0].value = NM_SETTING_WIRELESS_SETTING_NAME;
	nmc->allowed_fields[1].value = ssid_str;
	nmc->allowed_fields[2].value = nm_setting_wireless_get_mode (s_wireless);
	nmc->allowed_fields[3].value = nm_setting_wireless_get_band (s_wireless);
	nmc->allowed_fields[4].value = channel_str;
	nmc->allowed_fields[5].value = bssid_str ? bssid_str : _("not set");
	nmc->allowed_fields[6].value = rate_str;
	nmc->allowed_fields[7].value = tx_power_str;
	nmc->allowed_fields[8].value = device_mac_str ? device_mac_str : _("not set");
	nmc->allowed_fields[9].value = cloned_mac_str ? cloned_mac_str : _("not set");
	nmc->allowed_fields[10].value = strcmp (mtu_str, "0") ?  mtu_str : _("auto");
	nmc->allowed_fields[11].value = seen_bssids->str;
	nmc->allowed_fields[12].value = nm_setting_wireless_get_security (s_wireless);

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_free (ssid_str);
	g_free (channel_str);
	g_free (bssid_str);
	g_free (rate_str);
	g_free (tx_power_str);
	g_free (device_mac_str);
	g_free (cloned_mac_str);
	g_free (mtu_str);
	g_string_free (seen_bssids, TRUE);

	return TRUE;
}

gboolean
setting_wireless_security_details (NMSetting *setting, NmCli *nmc)
{
	NMSettingWirelessSecurity *s_wireless_sec;
	int i;
	char *wep_tx_keyidx_str, *wep_key_type_str;
	GString *protos, *pairwises, *groups;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_WIRELESS_SECURITY (setting), FALSE);
	s_wireless_sec = (NMSettingWirelessSecurity *) setting;

	nmc->allowed_fields = nmc_fields_setting_wireless_security;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_WIRELESS_SECURITY_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	wep_tx_keyidx_str = g_strdup_printf ("%d", nm_setting_wireless_security_get_wep_tx_keyidx (s_wireless_sec));
	protos = g_string_new (NULL);
	for (i = 0; i < nm_setting_wireless_security_get_num_protos (s_wireless_sec); i++) {
		if (i > 0)
		g_string_append_c (protos, ',');
		g_string_append (protos, nm_setting_wireless_security_get_proto (s_wireless_sec, i));
	}
	pairwises = g_string_new (NULL);
	for (i = 0; i < nm_setting_wireless_security_get_num_pairwise (s_wireless_sec); i++) {
		if (i > 0)
		g_string_append_c (pairwises, ',');
		g_string_append (pairwises, nm_setting_wireless_security_get_pairwise (s_wireless_sec, i));
	}
	groups = g_string_new (NULL);
	for (i = 0; i < nm_setting_wireless_security_get_num_groups (s_wireless_sec); i++) {
		if (i > 0)
		g_string_append_c (groups, ',');
		g_string_append (groups, nm_setting_wireless_security_get_group (s_wireless_sec, i));
	}
	wep_key_type_str = wep_key_type_to_string (nm_setting_wireless_security_get_wep_key_type (s_wireless_sec));

	nmc->allowed_fields[0].value = NM_SETTING_WIRELESS_SECURITY_SETTING_NAME;
	nmc->allowed_fields[1].value = nm_setting_wireless_security_get_key_mgmt (s_wireless_sec);
	nmc->allowed_fields[2].value = wep_tx_keyidx_str;
	nmc->allowed_fields[3].value = nm_setting_wireless_security_get_auth_alg (s_wireless_sec);
	nmc->allowed_fields[4].value = protos->str;
	nmc->allowed_fields[5].value = pairwises->str;
	nmc->allowed_fields[6].value = groups->str;
	nmc->allowed_fields[7].value = nm_setting_wireless_security_get_leap_username (s_wireless_sec);
	nmc->allowed_fields[8].value = nm_setting_wireless_security_get_wep_key (s_wireless_sec, 0);
	nmc->allowed_fields[9].value = nm_setting_wireless_security_get_wep_key (s_wireless_sec, 1);
	nmc->allowed_fields[10].value = nm_setting_wireless_security_get_wep_key (s_wireless_sec, 2);
	nmc->allowed_fields[11].value = nm_setting_wireless_security_get_wep_key (s_wireless_sec, 3);
	nmc->allowed_fields[12].value = nm_setting_wireless_security_get_psk (s_wireless_sec);
	nmc->allowed_fields[13].value = nm_setting_wireless_security_get_leap_password (s_wireless_sec);
	nmc->allowed_fields[14].value = wep_key_type_str;

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_free (wep_tx_keyidx_str);
	g_free (wep_key_type_str);
	g_string_free (protos, TRUE);
	g_string_free (pairwises, TRUE);
	g_string_free (groups, TRUE);

	return TRUE;
}

gboolean
setting_ip4_config_details (NMSetting *setting, NmCli *nmc)
{
	NMSettingIP4Config *s_ip4;
	GString *dns_str, *dns_search_str, *addr_str, *route_str;
	int i, num;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_IP4_CONFIG (setting), FALSE);
	s_ip4 = (NMSettingIP4Config *) setting;

	nmc->allowed_fields = nmc_fields_setting_ip4_config;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_IP4_CONFIG_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	dns_str = g_string_new (NULL);
	num = nm_setting_ip4_config_get_num_dns (s_ip4);
	for (i = 0; i < num; i++) {
		char buf[INET_ADDRSTRLEN];
		guint32 ip;

		ip = nm_setting_ip4_config_get_dns (s_ip4, i);
		memset (buf, 0, sizeof (buf));
		inet_ntop (AF_INET, (const void *) &ip, buf, sizeof (buf));
		if (i > 0)
			g_string_append (dns_str, ", ");
		g_string_append (dns_str, buf);
	}

	dns_search_str = g_string_new (NULL);
	num = nm_setting_ip4_config_get_num_dns_searches (s_ip4);
	for (i = 0; i < num; i++) {
		const char *domain;

		domain = nm_setting_ip4_config_get_dns_search (s_ip4, i);
		if (i > 0)
			g_string_append (dns_search_str, ", ");
		g_string_append (dns_search_str, domain);
	}

	addr_str = g_string_new (NULL);
	num = nm_setting_ip4_config_get_num_addresses (s_ip4);
	for (i = 0; i < num; i++) {
		char buf[INET_ADDRSTRLEN];
		char *tmp;
		NMIP4Address *addr;
		guint32 ip;

		if (i > 0)
			g_string_append (addr_str, "; ");

		g_string_append (addr_str, "{ ");

		addr = nm_setting_ip4_config_get_address (s_ip4, i);

		memset (buf, 0, sizeof (buf));
		ip = nm_ip4_address_get_address (addr);
		inet_ntop (AF_INET, (const void *) &ip, buf, sizeof (buf));
		g_string_append_printf (addr_str, "ip = %s", buf);

		tmp = g_strdup_printf ("/%u", nm_ip4_address_get_prefix (addr));
		g_string_append (addr_str, tmp);
		g_free (tmp);

		memset (buf, 0, sizeof (buf));
		ip = nm_ip4_address_get_gateway (addr);
		inet_ntop (AF_INET, (const void *) &ip, buf, sizeof (buf));
		g_string_append_printf (addr_str, ", gw = %s", buf);

		g_string_append (addr_str, " }");
	}

	route_str = g_string_new (NULL);
	num = nm_setting_ip4_config_get_num_routes (s_ip4);
	for (i = 0; i < num; i++) {
		char buf[INET_ADDRSTRLEN];
		char *tmp;
		NMIP4Route *route;
		guint32 ip;

		if (i > 0)
			g_string_append (route_str, "; ");

		g_string_append (route_str, "{ ");

		route = nm_setting_ip4_config_get_route (s_ip4, i);

		memset (buf, 0, sizeof (buf));
		ip = nm_ip4_route_get_dest (route);
		inet_ntop (AF_INET, (const void *) &ip, buf, sizeof (buf));
		g_string_append_printf (route_str, "dst = %s", buf);

		tmp = g_strdup_printf ("/%u", nm_ip4_route_get_prefix (route));
		g_string_append (route_str, tmp);
		g_free (tmp);

		memset (buf, 0, sizeof (buf));
		ip = nm_ip4_route_get_next_hop (route);
		inet_ntop (AF_INET, (const void *) &ip, buf, sizeof (buf));
		g_string_append_printf (route_str, ", nh = %s", buf);

		tmp = g_strdup_printf (", mt = %u", nm_ip4_route_get_metric (route));
		g_string_append (route_str, tmp);
		g_free (tmp);

		g_string_append (route_str, " }");
	}

	nmc->allowed_fields[0].value = NM_SETTING_IP4_CONFIG_SETTING_NAME;
	nmc->allowed_fields[1].value = nm_setting_ip4_config_get_method (s_ip4);
	nmc->allowed_fields[2].value = dns_str->str;
	nmc->allowed_fields[3].value = dns_search_str->str;
	nmc->allowed_fields[4].value = addr_str->str;
	nmc->allowed_fields[5].value = route_str->str;
	nmc->allowed_fields[6].value = nm_setting_ip4_config_get_ignore_auto_routes (s_ip4) ? _("yes") : _("no");
	nmc->allowed_fields[7].value = nm_setting_ip4_config_get_ignore_auto_dns (s_ip4) ? _("yes") : _("no");
	nmc->allowed_fields[8].value = nm_setting_ip4_config_get_dhcp_client_id (s_ip4);
	nmc->allowed_fields[9].value = nm_setting_ip4_config_get_dhcp_send_hostname (s_ip4) ? _("yes") : _("no");
	nmc->allowed_fields[10].value = nm_setting_ip4_config_get_dhcp_hostname (s_ip4);
	nmc->allowed_fields[11].value = nm_setting_ip4_config_get_never_default (s_ip4) ? _("yes") : _("no");

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_string_free (dns_str, TRUE);
	g_string_free (dns_search_str, TRUE);
	g_string_free (addr_str, TRUE);
	g_string_free (route_str, TRUE);

	return TRUE;
}

gboolean
setting_ip6_config_details (NMSetting *setting, NmCli *nmc)
{
	NMSettingIP6Config *s_ip6;
	GString *dns_str, *dns_search_str, *addr_str, *route_str;
	int i, num;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_IP6_CONFIG (setting), FALSE);
	s_ip6 = (NMSettingIP6Config *) setting;

	nmc->allowed_fields = nmc_fields_setting_ip6_config;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_IP6_CONFIG_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	dns_str = g_string_new (NULL);
	num = nm_setting_ip6_config_get_num_dns (s_ip6);
	for (i = 0; i < num; i++) {
		char buf[INET6_ADDRSTRLEN];
		const struct in6_addr *ip;

		ip = nm_setting_ip6_config_get_dns (s_ip6, i);
		memset (buf, 0, sizeof (buf));
		inet_ntop (AF_INET6, (const void *) ip, buf, sizeof (buf));
		if (i > 0)
			g_string_append (dns_str, ", ");
		g_string_append (dns_str, buf);
	}

	dns_search_str = g_string_new (NULL);
	num = nm_setting_ip6_config_get_num_dns_searches (s_ip6);
	for (i = 0; i < num; i++) {
		const char *domain;

		domain = nm_setting_ip6_config_get_dns_search (s_ip6, i);
		if (i > 0)
			g_string_append (dns_search_str, ", ");
		g_string_append (dns_search_str, domain);
	}

	addr_str = g_string_new (NULL);
	num = nm_setting_ip6_config_get_num_addresses (s_ip6);
	for (i = 0; i < num; i++) {
		char buf[INET6_ADDRSTRLEN];
		char *tmp;
		NMIP6Address *addr;
		const struct in6_addr *ip;

		if (i > 0)
			g_string_append (addr_str, "; ");

		g_string_append (addr_str, "{ ");

		addr = nm_setting_ip6_config_get_address (s_ip6, i);

		memset (buf, 0, sizeof (buf));
		ip = nm_ip6_address_get_address (addr);
		inet_ntop (AF_INET6, (const void *) ip, buf, sizeof (buf));
		g_string_append_printf (addr_str, "ip = %s", buf);

		tmp = g_strdup_printf ("/%u", nm_ip6_address_get_prefix (addr));
		g_string_append (addr_str, tmp);
		g_free (tmp);

		g_string_append (addr_str, " }");
	}

	route_str = g_string_new (NULL);
	num = nm_setting_ip6_config_get_num_routes (s_ip6);
	for (i = 0; i < num; i++) {
		char buf[INET6_ADDRSTRLEN];
		char *tmp;
		NMIP6Route *route;
		const struct in6_addr *ip;

		if (i > 0)
			g_string_append (route_str, "; ");

		g_string_append (route_str, "{ ");

		route = nm_setting_ip6_config_get_route (s_ip6, i);

		memset (buf, 0, sizeof (buf));
		ip = nm_ip6_route_get_dest (route);
		inet_ntop (AF_INET6, (const void *) ip, buf, sizeof (buf));
		g_string_append_printf (route_str, "dst = %s", buf);

		tmp = g_strdup_printf ("/%u", nm_ip6_route_get_prefix (route));
		g_string_append (route_str, tmp);
		g_free (tmp);

		memset (buf, 0, sizeof (buf));
		ip = nm_ip6_route_get_next_hop (route);
		inet_ntop (AF_INET6, (const void *) ip, buf, sizeof (buf));
		g_string_append_printf (route_str, ", nh = %s", buf);

		tmp = g_strdup_printf (", mt = %u", nm_ip6_route_get_metric (route));
		g_string_append (route_str, tmp);
		g_free (tmp);

		g_string_append (route_str, " }");
	}

	nmc->allowed_fields[0].value = NM_SETTING_IP6_CONFIG_SETTING_NAME;
	nmc->allowed_fields[1].value = nm_setting_ip6_config_get_method (s_ip6);
	nmc->allowed_fields[2].value = dns_str->str;
	nmc->allowed_fields[3].value = dns_search_str->str;
	nmc->allowed_fields[4].value = addr_str->str;
	nmc->allowed_fields[5].value = route_str->str;
	nmc->allowed_fields[6].value = nm_setting_ip6_config_get_ignore_auto_routes (s_ip6) ? _("yes") : _("no");
	nmc->allowed_fields[7].value = nm_setting_ip6_config_get_ignore_auto_dns (s_ip6) ? _("yes") : _("no");
	nmc->allowed_fields[8].value = nm_setting_ip6_config_get_never_default (s_ip6) ? _("yes") : _("no");

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_string_free (dns_str, TRUE);
	g_string_free (dns_search_str, TRUE);
	g_string_free (addr_str, TRUE);
	g_string_free (route_str, TRUE);

	return TRUE;
}

gboolean
setting_serial_details (NMSetting *setting, NmCli *nmc)
{
	NMSettingSerial *s_serial;
	char *baud_str, *bits_str, *parity_str, *stopbits_str, *send_delay_str;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_SERIAL (setting), FALSE);
	s_serial = (NMSettingSerial *) setting;

	nmc->allowed_fields = nmc_fields_setting_serial;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_SERIAL_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	baud_str = g_strdup_printf ("%d", nm_setting_serial_get_baud (s_serial));
	bits_str = g_strdup_printf ("%d", nm_setting_serial_get_bits (s_serial));
	parity_str = g_strdup_printf ("%c", nm_setting_serial_get_parity (s_serial));
	stopbits_str = g_strdup_printf ("%d", nm_setting_serial_get_stopbits (s_serial));
	send_delay_str = g_strdup_printf ("%" G_GUINT64_FORMAT, nm_setting_serial_get_send_delay (s_serial));

	nmc->allowed_fields[0].value = NM_SETTING_SERIAL_SETTING_NAME;
	nmc->allowed_fields[1].value = baud_str;
	nmc->allowed_fields[2].value = bits_str;
	nmc->allowed_fields[3].value = parity_str;
	nmc->allowed_fields[4].value = stopbits_str;
	nmc->allowed_fields[5].value = send_delay_str;

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_free (baud_str);
	g_free (bits_str);
	g_free (parity_str);
	g_free (stopbits_str);
	g_free (send_delay_str);

	return TRUE;
}

gboolean
setting_ppp_details (NMSetting *setting, NmCli *nmc)
{
	NMSettingPPP *s_ppp;
	char *baud_str, *mru_str, *mtu_str, *lcp_echo_failure_str, *lcp_echo_interval_str;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_PPP (setting), FALSE);
	s_ppp = (NMSettingPPP *) setting;

	nmc->allowed_fields = nmc_fields_setting_ppp;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_PPP_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	baud_str = g_strdup_printf ("%d", nm_setting_ppp_get_baud (s_ppp));
	mru_str = g_strdup_printf ("%d", nm_setting_ppp_get_mru (s_ppp));
	mtu_str = g_strdup_printf ("%d", nm_setting_ppp_get_mtu (s_ppp));
	lcp_echo_failure_str = g_strdup_printf ("%d", nm_setting_ppp_get_lcp_echo_failure (s_ppp));
	lcp_echo_interval_str = g_strdup_printf ("%d", nm_setting_ppp_get_lcp_echo_interval (s_ppp));

	nmc->allowed_fields[0].value = NM_SETTING_PPP_SETTING_NAME;
	nmc->allowed_fields[1].value = nm_setting_ppp_get_noauth (s_ppp) ? _("yes") : _("no");
	nmc->allowed_fields[2].value = nm_setting_ppp_get_refuse_eap (s_ppp) ? _("yes") : _("no");
	nmc->allowed_fields[3].value = nm_setting_ppp_get_refuse_pap (s_ppp) ? _("yes") : _("no");
	nmc->allowed_fields[4].value = nm_setting_ppp_get_refuse_chap (s_ppp) ? _("yes") : _("no");
	nmc->allowed_fields[5].value = nm_setting_ppp_get_refuse_mschap (s_ppp) ? _("yes") : _("no");
	nmc->allowed_fields[6].value = nm_setting_ppp_get_refuse_mschapv2 (s_ppp) ? _("yes") : _("no");
	nmc->allowed_fields[7].value = nm_setting_ppp_get_nobsdcomp (s_ppp) ? _("yes") : _("no");
	nmc->allowed_fields[8].value = nm_setting_ppp_get_nodeflate (s_ppp) ? _("yes") : _("no");
	nmc->allowed_fields[9].value = nm_setting_ppp_get_no_vj_comp (s_ppp) ? _("yes") : _("no");
	nmc->allowed_fields[10].value = nm_setting_ppp_get_require_mppe (s_ppp) ? _("yes") : _("no");
	nmc->allowed_fields[11].value = nm_setting_ppp_get_require_mppe_128 (s_ppp) ? _("yes") : _("no");
	nmc->allowed_fields[12].value = nm_setting_ppp_get_mppe_stateful (s_ppp) ? _("yes") : _("no");
	nmc->allowed_fields[13].value = nm_setting_ppp_get_crtscts (s_ppp) ? _("yes") : _("no");
	nmc->allowed_fields[14].value = baud_str;
	nmc->allowed_fields[15].value = mru_str;
	nmc->allowed_fields[16].value = mtu_str;
	nmc->allowed_fields[17].value = lcp_echo_failure_str;
	nmc->allowed_fields[18].value = lcp_echo_interval_str;

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_free (baud_str);
	g_free (mru_str);
	g_free (mtu_str);
	g_free (lcp_echo_failure_str);
	g_free (lcp_echo_interval_str);

	return TRUE;
}

gboolean
setting_pppoe_details (NMSetting *setting, NmCli *nmc)
{
	NMSettingPPPOE *s_pppoe;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_PPPOE (setting), FALSE);
	s_pppoe = (NMSettingPPPOE *) setting;

	nmc->allowed_fields = nmc_fields_setting_pppoe;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_PPPOE_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	nmc->allowed_fields[0].value = NM_SETTING_PPPOE_SETTING_NAME;
	nmc->allowed_fields[1].value = nm_setting_pppoe_get_service (s_pppoe);
	nmc->allowed_fields[2].value = nm_setting_pppoe_get_username (s_pppoe);
	nmc->allowed_fields[3].value = nm_setting_pppoe_get_password (s_pppoe);

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	return TRUE;
}

gboolean
setting_gsm_details (NMSetting *setting, NmCli *nmc)
{
	NMSettingGsm *s_gsm;
	char *network_type_str, *allowed_bands_str;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), FALSE);
	s_gsm = (NMSettingGsm *) setting;

	nmc->allowed_fields = nmc_fields_setting_gsm;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_GSM_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	network_type_str = g_strdup_printf ("%d", nm_setting_gsm_get_network_type (s_gsm));
	allowed_bands_str = allowed_bands_to_string (nm_setting_gsm_get_allowed_bands (s_gsm));

	nmc->allowed_fields[0].value = NM_SETTING_GSM_SETTING_NAME;
	nmc->allowed_fields[1].value = nm_setting_gsm_get_number (s_gsm);
	nmc->allowed_fields[2].value = nm_setting_gsm_get_username (s_gsm);
	nmc->allowed_fields[3].value = nm_setting_gsm_get_password (s_gsm);
	nmc->allowed_fields[4].value = nm_setting_gsm_get_apn (s_gsm);
	nmc->allowed_fields[5].value = nm_setting_gsm_get_network_id (s_gsm);
	nmc->allowed_fields[6].value = network_type_str;
	nmc->allowed_fields[7].value = allowed_bands_str;
	nmc->allowed_fields[8].value = nm_setting_gsm_get_pin (s_gsm);
	nmc->allowed_fields[9].value = nm_setting_gsm_get_home_only (s_gsm) ? _("yes") : _("no");

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_free (network_type_str);
	g_free (allowed_bands_str);

	return TRUE;
}

gboolean
setting_cdma_details (NMSetting *setting, NmCli *nmc)
{
	NMSettingCdma *s_cdma;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_CDMA (setting), FALSE);
	s_cdma = (NMSettingCdma *) setting;

	nmc->allowed_fields = nmc_fields_setting_cdma;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_CDMA_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	nmc->allowed_fields[0].value = NM_SETTING_CDMA_SETTING_NAME;
	nmc->allowed_fields[1].value = nm_setting_cdma_get_number (s_cdma);
	nmc->allowed_fields[2].value = nm_setting_cdma_get_username (s_cdma);
	nmc->allowed_fields[3].value = nm_setting_cdma_get_password (s_cdma);

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	return TRUE;
}

gboolean
setting_bluetooth_details (NMSetting *setting, NmCli *nmc)
{
	NMSettingBluetooth *s_bluetooth;
	const GByteArray *bdaddr;
	char *bdaddr_str = NULL;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_BLUETOOTH (setting), FALSE);
	s_bluetooth = (NMSettingBluetooth *) setting;

	nmc->allowed_fields = nmc_fields_setting_bluetooth;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_BLUETOOTH_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	bdaddr = nm_setting_bluetooth_get_bdaddr (s_bluetooth);
	if (bdaddr)
		bdaddr_str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X", bdaddr->data[0], bdaddr->data[1], bdaddr->data[2],
		                                                               bdaddr->data[3], bdaddr->data[4], bdaddr->data[5]);
	nmc->allowed_fields[0].value = NM_SETTING_BLUETOOTH_SETTING_NAME;
	nmc->allowed_fields[1].value = bdaddr_str;
	nmc->allowed_fields[2].value = nm_setting_bluetooth_get_connection_type (s_bluetooth);

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_free (bdaddr_str);

	return TRUE;
}

gboolean
setting_olpc_mesh_details (NMSetting *setting, NmCli *nmc)
{
	NMSettingOlpcMesh *s_olpc_mesh;
	const GByteArray *ssid, *dhcp_anycast;
	char *ssid_str, *channel_str, *dhcp_anycast_str = NULL;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_OLPC_MESH (setting), FALSE);
	s_olpc_mesh = (NMSettingOlpcMesh *) setting;

	nmc->allowed_fields = nmc_fields_setting_olpc_mesh;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_OLPC_MESH_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	ssid = nm_setting_olpc_mesh_get_ssid (s_olpc_mesh);
	ssid_str = ssid_to_printable ((const char *) ssid->data, ssid->len);
	channel_str = g_strdup_printf ("%d", nm_setting_olpc_mesh_get_channel (s_olpc_mesh));
	dhcp_anycast = nm_setting_olpc_mesh_get_dhcp_anycast_address (s_olpc_mesh);
	if (dhcp_anycast)
		dhcp_anycast_str = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X", dhcp_anycast->data[0], dhcp_anycast->data[1], dhcp_anycast->data[2],
		                                                                     dhcp_anycast->data[3], dhcp_anycast->data[4], dhcp_anycast->data[5]);
	nmc->allowed_fields[0].value = NM_SETTING_OLPC_MESH_SETTING_NAME;
	nmc->allowed_fields[1].value = ssid_str;
	nmc->allowed_fields[2].value = channel_str;
	nmc->allowed_fields[3].value = dhcp_anycast_str;

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_free (ssid_str);
	g_free (channel_str);
	g_free (dhcp_anycast_str);

	return TRUE;
}

static void
vpn_data_item (const char *key, const char *value, gpointer user_data)
{
	GString *ret_str = (GString *) user_data;

	if (ret_str->len != 0)
		g_string_append (ret_str, ", ");

	g_string_append_printf (ret_str, "%s = %s", key, value);
}

gboolean
setting_vpn_details (NMSetting *setting, NmCli *nmc)
{
	NMSettingVPN *s_vpn;
	GString *data_item_str, *secret_str;
	guint32 mode_flag = (nmc->print_output == NMC_PRINT_PRETTY) ? NMC_PF_FLAG_PRETTY : (nmc->print_output == NMC_PRINT_TERSE) ? NMC_PF_FLAG_TERSE : 0;
	guint32 multiline_flag = nmc->multiline_output ? NMC_PF_FLAG_MULTILINE : 0;
	guint32 escape_flag = nmc->escape_values ? NMC_PF_FLAG_ESCAPE : 0;

	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), FALSE);
	s_vpn = (NMSettingVPN *) setting;

	nmc->allowed_fields = nmc_fields_setting_vpn;
	nmc->print_fields.indices = parse_output_fields (NMC_FIELDS_SETTING_VPN_ALL, nmc->allowed_fields, NULL);
	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_FIELD_NAMES;
	print_fields (nmc->print_fields, nmc->allowed_fields);  /* Print field names */

	data_item_str = g_string_new (NULL);
	secret_str = g_string_new (NULL);
	nm_setting_vpn_foreach_data_item (s_vpn, &vpn_data_item, data_item_str);
	nm_setting_vpn_foreach_secret (s_vpn, &vpn_data_item, secret_str);

	nmc->allowed_fields[0].value = NM_SETTING_VPN_SETTING_NAME;
	nmc->allowed_fields[1].value = nm_setting_vpn_get_service_type (s_vpn);
	nmc->allowed_fields[2].value = nm_setting_vpn_get_user_name (s_vpn);
	nmc->allowed_fields[3].value = data_item_str->str;
	nmc->allowed_fields[4].value = secret_str->str;

	nmc->print_fields.flags = multiline_flag | mode_flag | escape_flag | NMC_PF_FLAG_SECTION_PREFIX;
	print_fields (nmc->print_fields, nmc->allowed_fields); /* Print values */

	g_string_free (data_item_str, TRUE);
	g_string_free (secret_str, TRUE);

	return TRUE;
}

