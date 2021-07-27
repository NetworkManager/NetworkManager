/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_CONFIG_BASE_H__
#define __NM_CONFIG_BASE_H__

#define NM_CONFIG_KEYFILE_LIST_SEPARATOR ','

#define NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN                 ".intern."
#define NM_CONFIG_KEYFILE_GROUPPREFIX_CONNECTION             "connection"
#define NM_CONFIG_KEYFILE_GROUPPREFIX_DEVICE                 "device"
#define NM_CONFIG_KEYFILE_GROUPPREFIX_GLOBAL_DNS_DOMAIN      "global-dns-domain-"
#define NM_CONFIG_KEYFILE_GROUPPREFIX_TEST_APPEND_STRINGLIST ".test-append-stringlist"

#define NM_CONFIG_KEYFILE_GROUP_MAIN         "main"
#define NM_CONFIG_KEYFILE_GROUP_LOGGING      "logging"
#define NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY "connectivity"
#define NM_CONFIG_KEYFILE_GROUP_KEYFILE      "keyfile"
#define NM_CONFIG_KEYFILE_GROUP_IFUPDOWN     "ifupdown"
#define NM_CONFIG_KEYFILE_GROUP_GLOBAL_DNS   "global-dns"
#define NM_CONFIG_KEYFILE_GROUP_CONFIG       ".config"

#define NM_CONFIG_KEYFILE_KEY_MAIN_ASSUME_IPV6LL_ONLY          "assume-ipv6ll-only"
#define NM_CONFIG_KEYFILE_KEY_MAIN_AUTH_POLKIT                 "auth-polkit"
#define NM_CONFIG_KEYFILE_KEY_MAIN_AUTOCONNECT_RETRIES_DEFAULT "autoconnect-retries-default"
#define NM_CONFIG_KEYFILE_KEY_MAIN_CONFIGURE_AND_QUIT          "configure-and-quit"
#define NM_CONFIG_KEYFILE_KEY_MAIN_DEBUG                       "debug"
#define NM_CONFIG_KEYFILE_KEY_MAIN_DHCP                        "dhcp"
#define NM_CONFIG_KEYFILE_KEY_MAIN_DNS                         "dns"
#define NM_CONFIG_KEYFILE_KEY_MAIN_FIREWALL_BACKEND            "firewall-backend"
#define NM_CONFIG_KEYFILE_KEY_MAIN_HOSTNAME_MODE               "hostname-mode"
#define NM_CONFIG_KEYFILE_KEY_MAIN_IGNORE_CARRIER              "ignore-carrier"
#define NM_CONFIG_KEYFILE_KEY_MAIN_IWD_CONFIG_PATH             "iwd-config-path"
#define NM_CONFIG_KEYFILE_KEY_MAIN_MONITOR_CONNECTION_FILES    "monitor-connection-files"
#define NM_CONFIG_KEYFILE_KEY_MAIN_NO_AUTO_DEFAULT             "no-auto-default"
#define NM_CONFIG_KEYFILE_KEY_MAIN_PLUGINS                     "plugins"
#define NM_CONFIG_KEYFILE_KEY_MAIN_RC_MANAGER                  "rc-manager"
#define NM_CONFIG_KEYFILE_KEY_MAIN_SLAVES_ORDER                "slaves-order"
#define NM_CONFIG_KEYFILE_KEY_MAIN_SYSTEMD_RESOLVED            "systemd-resolved"

#define NM_CONFIG_KEYFILE_KEY_LOGGING_AUDIT   "audit"
#define NM_CONFIG_KEYFILE_KEY_LOGGING_BACKEND "backend"
#define NM_CONFIG_KEYFILE_KEY_LOGGING_DOMAINS "domains"
#define NM_CONFIG_KEYFILE_KEY_LOGGING_LEVEL   "level"

#define NM_CONFIG_KEYFILE_KEY_CONNECTIVITY_ENABLED  "enabled"
#define NM_CONFIG_KEYFILE_KEY_CONNECTIVITY_INTERVAL "interval"
#define NM_CONFIG_KEYFILE_KEY_CONNECTIVITY_RESPONSE "response"
#define NM_CONFIG_KEYFILE_KEY_CONNECTIVITY_URI      "uri"

#define NM_CONFIG_KEYFILE_KEY_KEYFILE_PATH              "path"
#define NM_CONFIG_KEYFILE_KEY_KEYFILE_UNMANAGED_DEVICES "unmanaged-devices"
#define NM_CONFIG_KEYFILE_KEY_KEYFILE_HOSTNAME          "hostname"

#define NM_CONFIG_KEYFILE_KEY_IFUPDOWN_MANAGED "managed"

#define NM_CONFIG_KEYFILE_KEY_GLOBAL_DNS_SEARCHES "searches"
#define NM_CONFIG_KEYFILE_KEY_GLOBAL_DNS_OPTIONS  "options"

#define NM_CONFIG_KEYFILE_KEY_GLOBAL_DNS_DOMAIN_SERVERS "servers"
#define NM_CONFIG_KEYFILE_KEY_GLOBAL_DNS_DOMAIN_OPTIONS "options"

#define NM_CONFIG_KEYFILE_KEY_DEVICE_MANAGED                    "managed"
#define NM_CONFIG_KEYFILE_KEY_DEVICE_IGNORE_CARRIER             "ignore-carrier"
#define NM_CONFIG_KEYFILE_KEY_DEVICE_SRIOV_NUM_VFS              "sriov-num-vfs"
#define NM_CONFIG_KEYFILE_KEY_DEVICE_KEEP_CONFIGURATION         "keep-configuration"
#define NM_CONFIG_KEYFILE_KEY_DEVICE_ALLOWED_CONNECTIONS        "allowed-connections"
#define NM_CONFIG_KEYFILE_KEY_DEVICE_WIFI_BACKEND               "wifi.backend"
#define NM_CONFIG_KEYFILE_KEY_DEVICE_WIFI_SCAN_RAND_MAC_ADDRESS "wifi.scan-rand-mac-address"
#define NM_CONFIG_KEYFILE_KEY_DEVICE_WIFI_SCAN_GENERATE_MAC_ADDRESS_MASK \
    "wifi.scan-generate-mac-address-mask"
#define NM_CONFIG_KEYFILE_KEY_DEVICE_CARRIER_WAIT_TIMEOUT "carrier-wait-timeout"
#define NM_CONFIG_KEYFILE_KEY_DEVICE_WIFI_IWD_AUTOCONNECT "wifi.iwd.autoconnect"

#define NM_CONFIG_KEYFILE_KEY_MATCH_DEVICE "match-device"
#define NM_CONFIG_KEYFILE_KEY_STOP_MATCH   "stop-match"

#define NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS ".was"   /* check-config-options skip */
#define NM_CONFIG_KEYFILE_KEY_CONFIG_ENABLE      "enable" /* check-config-options skip */

#define NM_CONFIG_KEYFILE_KEYPREFIX_WAS ".was."
#define NM_CONFIG_KEYFILE_KEYPREFIX_SET ".set."

#define NM_CONFIG_KEYFILE_GROUP_INTERN_GLOBAL_DNS \
    NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN NM_CONFIG_KEYFILE_GROUP_GLOBAL_DNS
#define NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN_GLOBAL_DNS_DOMAIN \
    NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN NM_CONFIG_KEYFILE_GROUPPREFIX_GLOBAL_DNS_DOMAIN

#endif /* __NM_CONFIG_BASE_H__ */
