/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2005 - 2017 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-device.h"

#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_addr.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>

#include "nm-utils/nm-dedup-multi.h"

#include "nm-common-macros.h"
#include "nm-device-private.h"
#include "NetworkManagerUtils.h"
#include "nm-manager.h"
#include "platform/nm-platform.h"
#include "platform/nmp-object.h"
#include "ndisc/nm-ndisc.h"
#include "ndisc/nm-lndp-ndisc.h"
#include "dhcp/nm-dhcp-manager.h"
#include "dhcp/nm-dhcp-utils.h"
#include "nm-act-request.h"
#include "nm-proxy-config.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-pacrunner-manager.h"
#include "dnsmasq/nm-dnsmasq-manager.h"
#include "nm-dhcp4-config.h"
#include "nm-dhcp6-config.h"
#include "nm-rfkill-manager.h"
#include "nm-firewall-manager.h"
#include "settings/nm-settings-connection.h"
#include "settings/nm-settings.h"
#include "nm-auth-utils.h"
#include "nm-netns.h"
#include "nm-dispatcher.h"
#include "nm-config.h"
#include "nm-utils/c-list.h"
#include "dns/nm-dns-manager.h"
#include "nm-core-internal.h"
#include "systemd/nm-sd.h"
#include "nm-lldp-listener.h"
#include "nm-audit-manager.h"
#include "nm-arping-manager.h"
#include "nm-connectivity.h"
#include "nm-dbus-interface.h"
#include "nm-device-vlan.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF (NMDevice);

/*****************************************************************************/

#define DHCP_RESTART_TIMEOUT   120
#define DHCP_NUM_TRIES_MAX     3
#define DEFAULT_AUTOCONNECT    TRUE

#define CARRIER_WAIT_TIME_MS 6000
#define CARRIER_WAIT_TIME_AFTER_MTU_MS 10000

#define NM_DEVICE_AUTH_RETRIES_UNSET    -1
#define NM_DEVICE_AUTH_RETRIES_INFINITY -2
#define NM_DEVICE_AUTH_RETRIES_DEFAULT  3

/*****************************************************************************/

typedef void (*ActivationHandleFunc) (NMDevice *self);

typedef struct {
	ActivationHandleFunc func;
	guint id;
} ActivationHandleData;

typedef enum {
	CLEANUP_TYPE_KEEP,
	CLEANUP_TYPE_REMOVED,
	CLEANUP_TYPE_DECONFIGURE,
} CleanupType;

typedef enum {
	IP_NONE = 0,
	IP_WAIT,
	IP_CONF,
	IP_DONE,
	IP_FAIL
} IpState;

typedef struct {
	CList lst_slave;
	NMDevice *slave;
	gulong watch_id;
	bool slave_is_enslaved;
	bool configure;
} SlaveInfo;

typedef struct {
	NMDevice *device;
	guint idle_add_id;
	int ifindex;
} DeleteOnDeactivateData;

typedef void (*ArpingCallback) (NMDevice *, NMIP4Config **, gboolean);

typedef struct {
	ArpingCallback callback;
	NMDevice *device;
	NMIP4Config **configs;
} ArpingData;

typedef enum {
	HW_ADDR_TYPE_UNSET = 0,
	HW_ADDR_TYPE_PERMANENT,
	HW_ADDR_TYPE_EXPLICIT,
	HW_ADDR_TYPE_GENERATED,
} HwAddrType;

typedef enum {
	FIREWALL_STATE_UNMANAGED = 0,
	FIREWALL_STATE_INITIALIZED,
	FIREWALL_STATE_WAIT_STAGE_3,
	FIREWALL_STATE_WAIT_IP_CONFIG,
} FirewallState;

typedef struct {
	NMIPConfig *orig;      /* the original configuration applied to the device */
	NMIPConfig *current;   /* configuration after external changes.  NULL means
	                          that the original configuration didn't change. */
} AppliedConfig;

/*****************************************************************************/

enum {
	STATE_CHANGED,
	AUTOCONNECT_ALLOWED,
	AUTH_REQUEST,
	IP4_CONFIG_CHANGED,
	IP6_CONFIG_CHANGED,
	IP6_PREFIX_DELEGATED,
	IP6_SUBNET_NEEDED,
	REMOVED,
	RECHECK_AUTO_ACTIVATE,
	RECHECK_ASSUME,
	LAST_SIGNAL,
};
static guint signals[LAST_SIGNAL] = { 0 };

NM_GOBJECT_PROPERTIES_DEFINE (NMDevice,
	PROP_UDI,
	PROP_IFACE,
	PROP_IP_IFACE,
	PROP_DRIVER,
	PROP_DRIVER_VERSION,
	PROP_FIRMWARE_VERSION,
	PROP_CAPABILITIES,
	PROP_CARRIER,
	PROP_MTU,
	PROP_IP4_ADDRESS,
	PROP_IP4_CONFIG,
	PROP_DHCP4_CONFIG,
	PROP_IP6_CONFIG,
	PROP_DHCP6_CONFIG,
	PROP_STATE,
	PROP_STATE_REASON,
	PROP_ACTIVE_CONNECTION,
	PROP_DEVICE_TYPE,
	PROP_LINK_TYPE,
	PROP_MANAGED,
	PROP_AUTOCONNECT,
	PROP_FIRMWARE_MISSING,
	PROP_NM_PLUGIN_MISSING,
	PROP_TYPE_DESC,
	PROP_RFKILL_TYPE,
	PROP_IFINDEX,
	PROP_AVAILABLE_CONNECTIONS,
	PROP_PHYSICAL_PORT_ID,
	PROP_MASTER,
	PROP_PARENT,
	PROP_HW_ADDRESS,
	PROP_PERM_HW_ADDRESS,
	PROP_HAS_PENDING_ACTION,
	PROP_METERED,
	PROP_LLDP_NEIGHBORS,
	PROP_REAL,
	PROP_SLAVES,
	PROP_REFRESH_RATE_MS,
	PROP_TX_BYTES,
	PROP_RX_BYTES,
	PROP_CONNECTIVITY,
);

typedef struct _NMDevicePrivate {
	bool in_state_changed;

	guint device_link_changed_id;
	guint device_ip_link_changed_id;

	NMDeviceState state;
	NMDeviceStateReason state_reason;
	struct {
		guint id;

		/* The @state/@reason is only valid, when @id is set. */
		NMDeviceState state;
		NMDeviceStateReason reason;
	} queued_state;

	guint queued_ip4_config_id;
	guint queued_ip6_config_id;
	GSList *pending_actions;
	GSList *dad6_failed_addrs;

	NMDevice *parent_device;

	char *        udi;
	char *        iface;   /* may change, could be renamed by user */
	int           ifindex;

	int parent_ifindex;

	int auth_retries;

	union {
		const guint8 hw_addr_len; /* read-only */
		guint8 hw_addr_len_;
	};

	HwAddrType hw_addr_type:5;

	bool          real:1;

	/* there was a IP config change, but no idle action was scheduled because device
	 * is still not platform-init */
	bool queued_ip4_config_pending:1;
	bool queued_ip6_config_pending:1;

	char *        ip_iface;
	int           ip_ifindex;
	NMDeviceType  type;
	char *        type_desc;
	NMLinkType    link_type;
	NMDeviceCapabilities capabilities;
	char *        driver;
	char *        driver_version;
	char *        firmware_version;
	RfKillType    rfkill_type;
	bool          firmware_missing:1;
	bool          nm_plugin_missing:1;
	bool          hw_addr_perm_fake:1; /* whether the permanent HW address could not be read and is a fake */

	NMUtilsStableType current_stable_id_type:3;

	bool          nm_owned:1; /* whether the device is a device owned and created by NM */

	bool          assume_state_guess_assume:1;
	char *        assume_state_connection_uuid;

	GHashTable *  available_connections;
	char *        hw_addr;
	char *        hw_addr_perm;
	char *        hw_addr_initial;
	char *        physical_port_id;
	guint         dev_id;

	NMUnmanagedFlags        unmanaged_mask;
	NMUnmanagedFlags        unmanaged_flags;
	DeleteOnDeactivateData *delete_on_deactivate_data; /* data for scheduled cleanup when deleting link (g_idle_add) */

	GCancellable *deactivating_cancellable;

	guint32         ip4_address;

	NMActRequest *  queued_act_request;
	bool            queued_act_request_is_waiting_for_carrier:1;
	bool            act_request_public:1;
	NMActRequest   *act_request;
	gulong          act_request_id;
	ActivationHandleData act_handle4; /* for layer2 and IPv4. */
	ActivationHandleData act_handle6;
	guint           recheck_assume_id;
	struct {
		guint               call_id;
		NMDeviceStateReason available_reason;
		NMDeviceStateReason unavailable_reason;
	}               recheck_available;
	struct {
		guint               call_id;
		NMDeviceState       post_state;
		NMDeviceStateReason post_state_reason;
	}               dispatcher;

	/* Link stuff */
	guint           link_connected_id;
	guint           link_disconnected_id;
	guint           carrier_defer_id;
	guint           carrier_wait_id;
	gulong          config_changed_id;
	guint32         mtu;
	guint32         ip6_mtu;
	guint32 mtu_initial;
	guint32 ip6_mtu_initial;

	guint32         v4_route_table;
	guint32         v6_route_table;

	/* when carrier goes away, we give a grace period of _get_carrier_wait_ms()
	 * until taking action.
	 *
	 * When changing MTU, the device might take longer then that. So, whenever
	 * NM changes the MTU it sets @carrier_wait_until_ms to CARRIER_WAIT_TIME_AFTER_MTU_MS
	 * in the future. This is used to extend the grace period in this particular case. */
	gint64          carrier_wait_until_ms;

	bool            carrier:1;
	bool            ignore_carrier:1;

	bool mtu_initialized:1;

	bool            up:1;   /* IFF_UP */

	bool            v4_commit_first_time:1;
	bool            v6_commit_first_time:1;

	bool            default_route_metric_penalty_ip4_has:1;
	bool            default_route_metric_penalty_ip6_has:1;

	NMDeviceSysIfaceState sys_iface_state:2;

	bool            v4_route_table_initialized:1;
	bool            v6_route_table_initialized:1;

	NMDeviceAutoconnectBlockedFlags autoconnect_blocked_flags:4;

	/* Generic DHCP stuff */
	char *          dhcp_anycast_address;

	char *          current_stable_id;

	/* Proxy Configuration */
	NMProxyConfig *proxy_config;
	NMPacrunnerManager *pacrunner_manager;
	NMPacrunnerCallId *pacrunner_call_id;

	/* IP4 configuration info */
	NMIP4Config *   ip4_config;     /* Combined config from VPN, settings, and device */
	union {
		const IpState   ip4_state;
		IpState         ip4_state_;
	};
	NMIP4Config *   con_ip4_config; /* config from the setting */
	AppliedConfig   dev_ip4_config; /* Config from DHCP, PPP, LLv4, etc */
	AppliedConfig   wwan_ip4_config; /* WWAN configuration */
	NMIP4Config *   ext_ip4_config; /* Stuff added outside NM */
	GSList *        vpn4_configs;   /* VPNs which use this device */

	bool v4_has_shadowed_routes;
	const char *ip4_rp_filter;

	/* DHCPv4 tracking */
	struct {
		NMDhcpClient *  client;
		gulong          state_sigid;
		NMDhcp4Config * config;
		guint           restart_id;
		guint           num_tries_left;
		char *          pac_url;
		bool            was_active;
	} dhcp4;

	struct {
		NMLogDomain log_domain;
		guint timeout;
		guint watch;
		GPid pid;
		const char *binary;
		const char *address;
		guint deadline;
	} gw_ping;

	/* dnsmasq stuff for shared connections */
	NMDnsMasqManager *dnsmasq_manager;
	gulong            dnsmasq_state_id;

	/* Firewall */
	FirewallState fw_state:4;
	NMFirewallManager *fw_mgr;
	NMFirewallManagerCallId fw_call;

	/* IPv4LL stuff */
	sd_ipv4ll *    ipv4ll;
	guint          ipv4ll_timeout;
	guint          rt6_temporary_not_available_id;

	/* IPv4 DAD stuff */
	struct {
		GSList *          dad_list;
		NMArpingManager * announcing;
	} arping;

	/* IP6 configuration info */
	NMIP6Config *  ip6_config;
	union {
		const IpState   ip6_state;
		IpState         ip6_state_;
	};
	NMIP6Config *  con_ip6_config; /* config from the setting */
	AppliedConfig  wwan_ip6_config;
	AppliedConfig  ac_ip6_config;  /* config from IPv6 autoconfiguration */
	NMIP6Config *  ext_ip6_config; /* Stuff added outside NM */
	NMIP6Config *  ext_ip6_config_captured; /* Configuration captured from platform. */
	GSList *       vpn6_configs;   /* VPNs which use this device */
	bool           nm_ipv6ll; /* TRUE if NM handles the device's IPv6LL address */
	NMIP6Config *  dad6_ip6_config;

	GHashTable *   rt6_temporary_not_available;

	NMNDisc *      ndisc;
	gulong         ndisc_changed_id;
	gulong         ndisc_timeout_id;
	NMSettingIP6ConfigPrivacy ndisc_use_tempaddr;

	guint          linklocal6_timeout_id;
	guint8         linklocal6_dad_counter;

	GHashTable *   ip6_saved_properties;

	struct {
		NMDhcpClient *   client;
		NMNDiscDHCPLevel mode;
		gulong           state_sigid;
		gulong           prefix_sigid;
		NMDhcp6Config *  config;
		/* IP6 config from DHCP */
		AppliedConfig    ip6_config;
		/* Event ID of the current IP6 config from DHCP */
		char *           event_id;
		guint            restart_id;
		guint            num_tries_left;
		guint            needed_prefixes;
		bool             was_active;
	} dhcp6;

	gboolean needs_ip6_subnet;

	/* master interface for bridge/bond/team slave */
	NMDevice *      master;
	bool            is_enslaved;
	bool            master_ready_handled;
	gulong          master_ready_id;

	/* slave management */
	CList           slaves;    /* list of SlaveInfo */

	NMMetered       metered;

	NMSettings *settings;

	NMNetns *netns;

	NMLldpListener *lldp_listener;
	NMConnectivityState connectivity_state;
	guint concheck_periodic_id;
	guint64 concheck_seq;

	guint check_delete_unrealized_id;

	struct {
		guint timeout_id;
		guint refresh_rate_ms;
		guint64 tx_bytes;
		guint64 rx_bytes;
	} stats;

} NMDevicePrivate;

G_DEFINE_ABSTRACT_TYPE (NMDevice, nm_device, NM_TYPE_DBUS_OBJECT)

#define NM_DEVICE_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMDevice, NM_IS_DEVICE)

/*****************************************************************************/

static const NMDBusInterfaceInfoExtended interface_info_device;
static const GDBusSignalInfo signal_info_state_changed;

static void nm_device_set_proxy_config (NMDevice *self, const char *pac_url);

static gboolean update_ext_ip_config (NMDevice *self, int addr_family, gboolean initial, gboolean intersect_configs);

static gboolean nm_device_set_ip4_config (NMDevice *self,
                                          NMIP4Config *config,
                                          gboolean commit,
                                          GPtrArray *ip4_dev_route_blacklist);
static gboolean ip4_config_merge_and_apply (NMDevice *self,
                                            gboolean commit);

static gboolean nm_device_set_ip6_config (NMDevice *self,
                                          NMIP6Config *config,
                                          gboolean commit);
static gboolean ip6_config_merge_and_apply (NMDevice *self,
                                            gboolean commit);

static gboolean nm_device_master_add_slave (NMDevice *self, NMDevice *slave, gboolean configure);
static void nm_device_slave_notify_enslave (NMDevice *self, gboolean success);
static void nm_device_slave_notify_release (NMDevice *self, NMDeviceStateReason reason);

static gboolean addrconf6_start_with_link_ready (NMDevice *self);
static NMActStageReturn linklocal6_start (NMDevice *self);

static void _carrier_wait_check_queued_act_request (NMDevice *self);
static gint64 _get_carrier_wait_ms (NMDevice *self);

static const char *_activation_func_to_string (ActivationHandleFunc func);
static void activation_source_handle_cb (NMDevice *self, int addr_family);

static void _set_state_full (NMDevice *self,
                             NMDeviceState state,
                             NMDeviceStateReason reason,
                             gboolean quitting);
static void queued_state_clear (NMDevice *device);
static gboolean queued_ip4_config_change (gpointer user_data);
static gboolean queued_ip6_config_change (gpointer user_data);
static void ip_check_ping_watch_cb (GPid pid, gint status, gpointer user_data);
static gboolean ip_config_valid (NMDeviceState state);
static NMActStageReturn dhcp4_start (NMDevice *self);
static gboolean dhcp6_start (NMDevice *self, gboolean wait_for_ll);
static void nm_device_start_ip_check (NMDevice *self);
static void realize_start_setup (NMDevice *self,
                                 const NMPlatformLink *plink,
                                 gboolean assume_state_guess_assume,
                                 const char *assume_state_connection_uuid,
                                 gboolean set_nm_owned,
                                 NMUnmanFlagOp unmanaged_user_explicit);
static void _set_mtu (NMDevice *self, guint32 mtu);
static void _commit_mtu (NMDevice *self, const NMIP4Config *config);
static void dhcp_schedule_restart (NMDevice *self, int addr_family, const char *reason);
static void _cancel_activation (NMDevice *self);

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (queued_state_to_string, NMDeviceState,
	NM_UTILS_LOOKUP_DEFAULT  (                              NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "???"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_UNKNOWN,      NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_UNMANAGED,    NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "unmanaged"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_UNAVAILABLE,  NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "unavailable"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_DISCONNECTED, NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "disconnected"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_PREPARE,      NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "prepare"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_CONFIG,       NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "config"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_NEED_AUTH,    NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "need-auth"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_IP_CONFIG,    NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "ip-config"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_IP_CHECK,     NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "ip-check"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_SECONDARIES,  NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "secondaries"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_ACTIVATED,    NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "activated"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_DEACTIVATING, NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "deactivating"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_FAILED,       NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE "failed"),
);

const char *
nm_device_state_to_str (NMDeviceState state)
{
	return queued_state_to_string (state) + NM_STRLEN (NM_PENDING_ACTIONPREFIX_QUEUED_STATE_CHANGE);
}

NM_UTILS_LOOKUP_STR_DEFINE (nm_device_state_reason_to_str, NMDeviceStateReason,
	NM_UTILS_LOOKUP_DEFAULT (NULL),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_UNKNOWN,                        "unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_NONE,                           "none"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_NOW_MANAGED,                    "managed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_NOW_UNMANAGED,                  "unmanaged"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_CONFIG_FAILED,                  "config-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE,          "ip-config-unavailable"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED,              "ip-config-expired"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_NO_SECRETS,                     "no-secrets"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT,          "supplicant-disconnect"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED,       "supplicant-config-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED,              "supplicant-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT,             "supplicant-timeout"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_PPP_START_FAILED,               "ppp-start-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_PPP_DISCONNECT,                 "ppp-disconnect"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_PPP_FAILED,                     "ppp-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_DHCP_START_FAILED,              "dhcp-start-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_DHCP_ERROR,                     "dhcp-error"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_DHCP_FAILED,                    "dhcp-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_SHARED_START_FAILED,            "sharing-start-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_SHARED_FAILED,                  "sharing-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED,            "autoip-start-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_AUTOIP_ERROR,                   "autoip-error"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_AUTOIP_FAILED,                  "autoip-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_MODEM_BUSY,                     "modem-busy"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_MODEM_NO_DIAL_TONE,             "modem-no-dialtone"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER,               "modem-no-carrier"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_MODEM_DIAL_TIMEOUT,             "modem-dial-timeout"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_MODEM_DIAL_FAILED,              "modem-dial-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_MODEM_INIT_FAILED,              "modem-init-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_GSM_APN_FAILED,                 "gsm-apn-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_GSM_REGISTRATION_NOT_SEARCHING, "gsm-registration-idle"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_GSM_REGISTRATION_DENIED,        "gsm-registration-denied"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_GSM_REGISTRATION_TIMEOUT,       "gsm-registration-timeout"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_GSM_REGISTRATION_FAILED,        "gsm-registration-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_GSM_PIN_CHECK_FAILED,           "gsm-pin-check-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_FIRMWARE_MISSING,               "firmware-missing"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_REMOVED,                        "removed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_SLEEPING,                       "sleeping"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_CONNECTION_REMOVED,             "connection-removed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_USER_REQUESTED,                 "user-requested"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_CARRIER,                        "carrier-changed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED,             "connection-assumed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_SUPPLICANT_AVAILABLE,           "supplicant-available"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_MODEM_NOT_FOUND,                "modem-not-found"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_BT_FAILED,                      "bluetooth-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_GSM_SIM_NOT_INSERTED,           "gsm-sim-not-inserted"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_GSM_SIM_PIN_REQUIRED,           "gsm-sim-pin-required"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_GSM_SIM_PUK_REQUIRED,           "gsm-sim-puk-required"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_GSM_SIM_WRONG,                  "gsm-sim-wrong"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_INFINIBAND_MODE,                "infiniband-mode"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED,              "dependency-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_BR2684_FAILED,                  "br2684-bridge-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_MODEM_MANAGER_UNAVAILABLE,      "modem-manager-unavailable"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_SSID_NOT_FOUND,                 "ssid-not-found"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_SECONDARY_CONNECTION_FAILED,    "secondary-connection-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED,                "dcb-fcoe-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_TEAMD_CONTROL_FAILED,           "teamd-control-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_MODEM_FAILED,                   "modem-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_MODEM_AVAILABLE,                "modem-available"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_SIM_PIN_INCORRECT,              "sim-pin-incorrect"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_NEW_ACTIVATION,                 "new-activation"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_PARENT_CHANGED,                 "parent-changed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_PARENT_MANAGED_CHANGED,         "parent-managed-changed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_OVSDB_FAILED,                   "ovsdb-failed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_IP_ADDRESS_DUPLICATE,           "ip-address-duplicate"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_STATE_REASON_IP_METHOD_UNSUPPORTED,          "ip-method-unsupported"),
);

#define reason_to_string(reason) \
	NM_UTILS_LOOKUP_STR (nm_device_state_reason_to_str, reason)

/*****************************************************************************/

NMSettings *
nm_device_get_settings (NMDevice *self)
{
	return NM_DEVICE_GET_PRIVATE (self)->settings;
}

NMNetns *
nm_device_get_netns (NMDevice *self)
{
	return NM_DEVICE_GET_PRIVATE (self)->netns;
}

NMDedupMultiIndex *
nm_device_get_multi_index (NMDevice *self)
{
	return nm_netns_get_multi_idx (nm_device_get_netns (self));
}

NMPlatform *
nm_device_get_platform (NMDevice *self)
{
	return nm_netns_get_platform (nm_device_get_netns (self));
}

static NMIP4Config *
_ip4_config_new (NMDevice *self)
{
	return nm_ip4_config_new (nm_device_get_multi_index (self),
	                          nm_device_get_ip_ifindex (self));
}

static NMIP6Config *
_ip6_config_new (NMDevice *self)
{
	return nm_ip6_config_new (nm_device_get_multi_index (self),
	                          nm_device_get_ip_ifindex (self));
}

static NMIPConfig *
_ip_config_new (NMDevice *self, int addr_family)
{
	nm_assert_addr_family (addr_family);

	return addr_family == AF_INET
	       ? (gpointer) _ip4_config_new (self)
	       : (gpointer) _ip6_config_new (self);
}

static void
applied_config_clear (AppliedConfig *config)
{
	g_clear_object (&config->current);
	g_clear_object (&config->orig);
}

static void
applied_config_init (AppliedConfig *config, gpointer ip_config)
{
	nm_g_object_ref (ip_config);
	applied_config_clear (config);
	config->orig = ip_config;
}

static void
applied_config_init_new (AppliedConfig *config, NMDevice *self, int addr_family)
{
	gs_unref_object NMIPConfig *c = _ip_config_new (self, addr_family);

	applied_config_init (config, c);
}

static NMIPConfig *
applied_config_get_current (AppliedConfig *config)
{
	return config->current ?: config->orig;
}

static void
applied_config_add_address (AppliedConfig *config, const NMPlatformIPAddress *address)
{
	if (config->orig)
		nm_ip_config_add_address (config->orig, address);
	else
		nm_assert (!config->current);

	if (config->current)
		nm_ip_config_add_address (config->current, address);
}

static void
applied_config_add_nameserver (AppliedConfig *config, const NMIPAddr *ns)
{
	if (config->orig)
		nm_ip_config_add_nameserver (config->orig, ns);
	else
		nm_assert (!config->current);

	if (config->current)
		nm_ip_config_add_nameserver (config->current, ns);
}

static void
applied_config_add_search (AppliedConfig *config, const char *new)
{
	if (config->orig)
		nm_ip_config_add_search (config->orig, new);
	else
		nm_assert (!config->current);

	if (config->current)
		nm_ip_config_add_search (config->current, new);
}

static void
applied_config_reset_searches (AppliedConfig *config)
{
	if (config->orig)
		nm_ip_config_reset_searches (config->orig);
	else
		nm_assert (!config->current);

	if (config->current)
		nm_ip_config_reset_searches (config->current);
}

static void
applied_config_reset_nameservers (AppliedConfig *config)
{
	if (config->orig)
		nm_ip_config_reset_nameservers (config->orig);
	else
		nm_assert (!config->current);

	if (config->current)
		nm_ip_config_reset_nameservers (config->current);
}

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_sys_iface_state_to_str, NMDeviceSysIfaceState,
	NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT ("unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_SYS_IFACE_STATE_EXTERNAL, "external"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_SYS_IFACE_STATE_ASSUME,   "assume"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_SYS_IFACE_STATE_MANAGED,  "managed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DEVICE_SYS_IFACE_STATE_REMOVED,  "removed"),
);

NMDeviceSysIfaceState
nm_device_sys_iface_state_get (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_DEVICE_SYS_IFACE_STATE_EXTERNAL);

	return NM_DEVICE_GET_PRIVATE (self)->sys_iface_state;
}

gboolean
nm_device_sys_iface_state_is_external (NMDevice *self)
{
	return NM_IN_SET (nm_device_sys_iface_state_get (self),
	                  NM_DEVICE_SYS_IFACE_STATE_EXTERNAL);
}

gboolean
nm_device_sys_iface_state_is_external_or_assume (NMDevice *self)
{
	return NM_IN_SET (nm_device_sys_iface_state_get (self),
	                  NM_DEVICE_SYS_IFACE_STATE_EXTERNAL,
	                  NM_DEVICE_SYS_IFACE_STATE_ASSUME);
}

void
nm_device_sys_iface_state_set (NMDevice *self,
                               NMDeviceSysIfaceState sys_iface_state)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));
	g_return_if_fail (NM_IN_SET (sys_iface_state,
	                             NM_DEVICE_SYS_IFACE_STATE_EXTERNAL,
	                             NM_DEVICE_SYS_IFACE_STATE_ASSUME,
	                             NM_DEVICE_SYS_IFACE_STATE_MANAGED,
	                             NM_DEVICE_SYS_IFACE_STATE_REMOVED));

	priv = NM_DEVICE_GET_PRIVATE (self);
	if (priv->sys_iface_state != sys_iface_state) {
		_LOGT (LOGD_DEVICE, "sys-iface-state: %s -> %s",
		       _sys_iface_state_to_str (priv->sys_iface_state),
		       _sys_iface_state_to_str (sys_iface_state));
		priv->sys_iface_state = sys_iface_state;
	}

	/* this function only sets a flag, no immediate actions are initiated.
	 *
	 * If you change this, make sure that all callers are fine with such actions. */

	nm_assert (priv->sys_iface_state == sys_iface_state);
}

static void
_active_connection_set_state_flags_full (NMDevice *self,
                                         NMActivationStateFlags flags,
                                         NMActivationStateFlags mask)
{
	NMActiveConnection *ac;

	ac = NM_ACTIVE_CONNECTION (nm_device_get_act_request (self));
	if (ac)
		nm_active_connection_set_state_flags_full (ac, flags, mask);
}

static void
_active_connection_set_state_flags (NMDevice *self,
                                    NMActivationStateFlags flags)
{
	_active_connection_set_state_flags_full (self, flags, flags);
}

/*****************************************************************************/

void
nm_device_assume_state_get (NMDevice *self,
                            gboolean *out_assume_state_guess_assume,
                            const char **out_assume_state_connection_uuid)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	NM_SET_OUT (out_assume_state_guess_assume, priv->assume_state_guess_assume);
	NM_SET_OUT (out_assume_state_connection_uuid, priv->assume_state_connection_uuid);
}

static void
_assume_state_set (NMDevice *self,
                   gboolean assume_state_guess_assume,
                   const char *assume_state_connection_uuid)
{
	NMDevicePrivate *priv;

	nm_assert (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	if (   priv->assume_state_guess_assume == !!assume_state_guess_assume
	    && nm_streq0 (priv->assume_state_connection_uuid, assume_state_connection_uuid))
		return;

	_LOGD (LOGD_DEVICE, "assume-state: set guess-assume=%c, connection=%s%s%s",
	       assume_state_guess_assume ? '1' : '0',
	       NM_PRINT_FMT_QUOTE_STRING (assume_state_connection_uuid));
	priv->assume_state_guess_assume = assume_state_guess_assume;
	g_free (priv->assume_state_connection_uuid);
	priv->assume_state_connection_uuid = g_strdup (assume_state_connection_uuid);
}

void
nm_device_assume_state_reset (NMDevice *self)
{
	g_return_if_fail (NM_IS_DEVICE (self));

	_assume_state_set (self, FALSE, NULL);
}

/*****************************************************************************/

static void
init_ip4_config_dns_priority (NMDevice *self, NMIP4Config *config)
{
	gs_free char *value = NULL;
	gint priority;

	value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
	                                               "ipv4.dns-priority",
	                                               self);
	priority = _nm_utils_ascii_str_to_int64 (value, 10, G_MININT, G_MAXINT, 0);
	nm_ip4_config_set_dns_priority (config, priority ?: NM_DNS_PRIORITY_DEFAULT_NORMAL);
}

static void
init_ip6_config_dns_priority (NMDevice *self, NMIP6Config *config)
{
	gs_free char *value = NULL;
	gint priority;

	value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
	                                               "ipv6.dns-priority",
	                                               self);
	priority = _nm_utils_ascii_str_to_int64 (value, 10, G_MININT, G_MAXINT, 0);
	nm_ip6_config_set_dns_priority (config, priority ?: NM_DNS_PRIORITY_DEFAULT_NORMAL);
}

/*****************************************************************************/

static gboolean
nm_device_ipv4_sysctl_set (NMDevice *self, const char *property, const char *value)
{
	NMPlatform *platform = nm_device_get_platform (self);
	gs_free char *value_to_free = NULL;
	const char *value_to_set;
	char buf[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];

	if (!nm_device_get_ip_ifindex (self))
		return FALSE;

	if (value) {
		value_to_set = value;
	} else {
		/* Set to a default value when we've got a NULL @value. */
		value_to_free = nm_platform_sysctl_get (platform,
		                                        NMP_SYSCTL_PATHID_ABSOLUTE (nm_utils_sysctl_ip_conf_path (AF_INET, buf, "default", property)));
		value_to_set = value_to_free;
	}

	return nm_platform_sysctl_set (platform,
	                               NMP_SYSCTL_PATHID_ABSOLUTE (nm_utils_sysctl_ip_conf_path (AF_INET, buf, nm_device_get_ip_iface (self), property)),
	                               value_to_set);
}

static guint32
nm_device_ipv4_sysctl_get_uint32 (NMDevice *self, const char *property, guint32 fallback)
{
	char buf[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];

	if (!nm_device_get_ip_ifindex (self))
		return fallback;

	return nm_platform_sysctl_get_int_checked (nm_device_get_platform (self),
	                                           NMP_SYSCTL_PATHID_ABSOLUTE (nm_utils_sysctl_ip_conf_path (AF_INET, buf, nm_device_get_ip_iface (self), property)),
	                                           10,
	                                           0,
	                                           G_MAXUINT32,
	                                           fallback);
}

gboolean
nm_device_ipv6_sysctl_set (NMDevice *self, const char *property, const char *value)
{
	char buf[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];

	if (!nm_device_get_ip_ifindex (self))
		return FALSE;

	return nm_platform_sysctl_set (nm_device_get_platform (self), NMP_SYSCTL_PATHID_ABSOLUTE (nm_utils_sysctl_ip_conf_path (AF_INET6, buf, nm_device_get_ip_iface (self), property)), value);
}

static guint32
nm_device_ipv6_sysctl_get_uint32 (NMDevice *self, const char *property, guint32 fallback)
{
	char buf[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];

	if (!nm_device_get_ip_ifindex (self))
		return fallback;

	return nm_platform_sysctl_get_int_checked (nm_device_get_platform (self),
	                                           NMP_SYSCTL_PATHID_ABSOLUTE (nm_utils_sysctl_ip_conf_path (AF_INET6, buf, nm_device_get_ip_iface (self), property)),
	                                           10,
	                                           0,
	                                           G_MAXUINT32,
	                                           fallback);
}

gboolean
nm_device_has_capability (NMDevice *self, NMDeviceCapabilities caps)
{
	return NM_FLAGS_ANY (NM_DEVICE_GET_PRIVATE (self)->capabilities, caps);
}

static void
_add_capabilities (NMDevice *self, NMDeviceCapabilities capabilities)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (!NM_FLAGS_ALL (priv->capabilities, capabilities)) {
		priv->capabilities |= capabilities;
		_notify (self, PROP_CAPABILITIES);
	}
}

/*****************************************************************************/

static const char *
_get_stable_id (NMDevice *self,
                NMConnection *connection,
                NMUtilsStableType *out_stable_type)
{
	NMDevicePrivate *priv;

	nm_assert (NM_IS_DEVICE (self));
	nm_assert (NM_IS_CONNECTION (connection));
	nm_assert (out_stable_type);

	priv = NM_DEVICE_GET_PRIVATE (self);

	/* we cache the generated stable ID for the time of an activation.
	 *
	 * The reason is, that we don't want the stable-id to change as long
	 * as the device is active.
	 *
	 * Especially with ${RANDOM} stable-id we want to generate *one* configuration
	 * for each activation. */
	if (G_UNLIKELY (!priv->current_stable_id)) {
		gs_free char *default_id = NULL;
		gs_free char *generated = NULL;
		NMUtilsStableType stable_type;
		NMSettingConnection *s_con;
		const char *stable_id;
		const char *uuid;

		s_con = nm_connection_get_setting_connection (connection);

		stable_id = nm_setting_connection_get_stable_id (s_con);

		if (!stable_id) {
			default_id = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
			                                                    "connection.stable-id",
			                                                    self);
			stable_id = default_id;
		}

		uuid = nm_connection_get_uuid (connection);

		stable_type = nm_utils_stable_id_parse (stable_id,
		                                        uuid,
		                                        NULL,
		                                        &generated);

		/* current_stable_id_type is a bitfield! */
		priv->current_stable_id_type = stable_type;
		nm_assert (stable_type <= (NMUtilsStableType) 0x3);
		nm_assert (stable_type + (NMUtilsStableType) 1 > (NMUtilsStableType) 0);
		nm_assert (priv->current_stable_id_type == stable_type);

		if (stable_type == NM_UTILS_STABLE_TYPE_UUID)
			priv->current_stable_id = g_strdup (uuid);
		else if (stable_type == NM_UTILS_STABLE_TYPE_STABLE_ID)
			priv->current_stable_id = g_strdup (stable_id);
		else if (stable_type == NM_UTILS_STABLE_TYPE_GENERATED)
			priv->current_stable_id = nm_str_realloc (nm_utils_stable_id_generated_complete (generated));
		else {
			nm_assert (stable_type == NM_UTILS_STABLE_TYPE_RANDOM);
			priv->current_stable_id = nm_str_realloc (nm_utils_stable_id_random ());
		}
		_LOGT (LOGD_DEVICE,
		       "stable-id: type=%d, \"%s\""
		       "%s%s%s",
		       (int) priv->current_stable_id_type,
		       priv->current_stable_id,
		       NM_PRINT_FMT_QUOTED (stable_type == NM_UTILS_STABLE_TYPE_GENERATED, " from \"", generated, "\"", ""));
	}

	*out_stable_type = priv->current_stable_id_type;
	return priv->current_stable_id;
}

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_ip_state_to_string, IpState,
	NM_UTILS_LOOKUP_DEFAULT_WARN ("unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (IP_NONE, "none"),
	NM_UTILS_LOOKUP_STR_ITEM (IP_WAIT, "wait"),
	NM_UTILS_LOOKUP_STR_ITEM (IP_CONF, "conf"),
	NM_UTILS_LOOKUP_STR_ITEM (IP_DONE, "done"),
	NM_UTILS_LOOKUP_STR_ITEM (IP_FAIL, "fail"),
);

static void
_set_ip_state (NMDevice *self, int addr_family, IpState new_state)
{
	IpState *p;
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	nm_assert_addr_family (addr_family);

	p =   (addr_family == AF_INET)
	    ? &priv->ip4_state_
	    : &priv->ip6_state_;

	if (*p != new_state) {
		_LOGT (LOGD_DEVICE, "ip%c-state: set to %d (%s)",
		       nm_utils_addr_family_to_char (addr_family),
		       (int) new_state,
		       _ip_state_to_string (new_state));
		*p = new_state;

		if (new_state == IP_DONE) {
			/* we only set the IPx_READY flag once we reach IP_DONE state. We don't
			 * ever clear it, even if we later enter IP_FAIL state.
			 *
			 * This is not documented/guaranteed behavior, but seems to make sense for now. */
			_active_connection_set_state_flags (self,
			                                    addr_family == AF_INET
			                                      ? NM_ACTIVATION_STATE_FLAG_IP4_READY
			                                      : NM_ACTIVATION_STATE_FLAG_IP6_READY);
		}
	}
}

/*****************************************************************************/

const char *
nm_device_get_udi (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->udi;
}

const char *
nm_device_get_iface (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->iface;
}

gboolean
nm_device_take_over_link (NMDevice *self, int ifindex, char **old_name)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const NMPlatformLink *plink;
	NMPlatform *platform;
	gboolean up, success = TRUE;
	gs_free char *name = NULL;

	g_return_val_if_fail (priv->ifindex <= 0, FALSE);

	NM_SET_OUT (old_name, NULL);

	platform = nm_device_get_platform (self);
	plink = nm_platform_link_get (platform, ifindex);
	if (!plink)
		return FALSE;

	if (!nm_streq (plink->name, nm_device_get_iface (self))) {
		up = NM_FLAGS_HAS (plink->n_ifi_flags, IFF_UP);
		name = g_strdup (plink->name);

		/* Rename the link to the device ifname */
		if (up)
			nm_platform_link_set_down (platform, ifindex);
		success = nm_platform_link_set_name (platform, ifindex, nm_device_get_iface (self));
		if (up)
			nm_platform_link_set_up (platform, ifindex, NULL);

		if (success)
			NM_SET_OUT (old_name, g_steal_pointer (&name));
	}

	if (success) {
		priv->ifindex = ifindex;
		_notify (self, PROP_IFINDEX);
	}

	return success;
}

int
nm_device_get_ifindex (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), 0);

	return NM_DEVICE_GET_PRIVATE (self)->ifindex;
}

/**
 * nm_device_is_software:
 * @self: the #NMDevice
 *
 * Indicates if the device is a software-based virtual device without
 * backing hardware, which can be added and removed programmatically.
 *
 * Returns: %TRUE if the device is a software-based device
 */
gboolean
nm_device_is_software (NMDevice *self)
{
	return NM_FLAGS_HAS (NM_DEVICE_GET_PRIVATE (self)->capabilities, NM_DEVICE_CAP_IS_SOFTWARE);
}

/**
 * nm_device_is_real:
 * @self: the #NMDevice
 *
 * Returns: %TRUE if the device exists, %FALSE if the device is a placeholder
 */
gboolean
nm_device_is_real (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	return NM_DEVICE_GET_PRIVATE (self)->real;
}

const char *
nm_device_get_ip_iface (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (self != NULL, NULL);

	priv = NM_DEVICE_GET_PRIVATE (self);
	/* If it's not set, default to iface */
	return priv->ip_iface ? priv->ip_iface : priv->iface;
}

int
nm_device_get_ip_ifindex (const NMDevice *self)
{
	const NMDevicePrivate *priv;

	g_return_val_if_fail (self != NULL, 0);

	priv = NM_DEVICE_GET_PRIVATE (self);
	/* If it's not set, default to ifindex */
	return priv->ip_iface ? priv->ip_ifindex : priv->ifindex;
}

static void
_set_ip_ifindex (NMDevice *self,
                 int ifindex,
                 const char *ifname)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMPlatform *platform;
	gboolean eq_name;

	/* normalize arguments */
	if (ifindex <= 0) {
		ifindex = 0;
		ifname = NULL;
	}

	eq_name = nm_streq0 (priv->ip_iface, ifname);

	if (   eq_name
	    && priv->ip_ifindex == ifindex)
		return;

	_LOGD (LOGD_DEVICE, "ip-ifindex: update ip-interface to %s%s%s, ifindex %d",
	       NM_PRINT_FMT_QUOTE_STRING (ifname),
	       ifindex);

	priv->ip_ifindex = ifindex;
	if (!eq_name) {
		g_free (priv->ip_iface);
		priv->ip_iface = g_strdup (ifname);
		_notify (self, PROP_IP_IFACE);
	}

	if (priv->ip_ifindex > 0) {
		platform = nm_device_get_platform (self);

		nm_platform_process_events_ensure_link (platform,
		                                        priv->ip_ifindex,
		                                        priv->ip_iface);

		if (nm_platform_check_kernel_support (platform,
		                                      NM_PLATFORM_KERNEL_SUPPORT_USER_IPV6LL))
			nm_platform_link_set_user_ipv6ll_enabled (platform, priv->ip_ifindex, TRUE);

		if (!nm_platform_link_is_up (platform, priv->ip_ifindex))
			nm_platform_link_set_up (platform, priv->ip_ifindex, NULL);
	}

	/* We don't care about any saved values from the old iface */
	g_hash_table_remove_all (priv->ip6_saved_properties);
}

gboolean
nm_device_set_ip_ifindex (NMDevice *self, int ifindex)
{
	char ifname_buf[IFNAMSIZ];
	const char *ifname = NULL;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (nm_device_is_activating (self), FALSE);

	if (ifindex > 0) {
		ifname = nm_platform_if_indextoname (nm_device_get_platform (self), ifindex, ifname_buf);
		if (!ifname)
			_LOGW (LOGD_DEVICE, "ip-ifindex: ifindex %d not found", ifindex);
	}

	_set_ip_ifindex (self, ifindex, ifname);
	return ifindex > 0;
}

/**
 * nm_device_set_ip_iface:
 * @self: the #NMDevice
 * @ifname: the new IP interface name
 *
 * Updates the IP interface name and possibly the ifindex.
 *
 * Returns: %TRUE if an interface with name @ifname exists,
 *   and %FALSE, if @ifname is %NULL or no such interface exists.
 */
gboolean
nm_device_set_ip_iface (NMDevice *self, const char *ifname)
{
	int ifindex = 0;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (nm_device_is_activating (self), FALSE);

	if (ifname) {
		ifindex = nm_platform_if_nametoindex (nm_device_get_platform (self), ifname);
		if (ifindex <= 0)
			_LOGW (LOGD_DEVICE, "ip-ifindex: ifname %s not found", ifname);
	}

	_set_ip_ifindex (self, ifindex, ifname);
	return ifindex > 0;
}

static gboolean
_ip_iface_update (NMDevice *self, const char *ip_iface)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_val_if_fail (priv->ip_iface, FALSE);
	g_return_val_if_fail (priv->ip_ifindex > 0, FALSE);
	g_return_val_if_fail (ip_iface, FALSE);

	if (!ip_iface[0])
		return FALSE;

	if (nm_streq (priv->ip_iface, ip_iface))
		return FALSE;

	_LOGI (LOGD_DEVICE, "ip-ifname: interface index %d renamed ip_iface (%d) from '%s' to '%s'",
	       priv->ifindex, priv->ip_ifindex,
	       priv->ip_iface, ip_iface);
	g_free (priv->ip_iface);
	priv->ip_iface = g_strdup (ip_iface);
	_notify (self, PROP_IP_IFACE);
	return TRUE;
}

/*****************************************************************************/

int
nm_device_parent_get_ifindex (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), 0);

	priv = NM_DEVICE_GET_PRIVATE (self);
	return priv->parent_ifindex;
}

NMDevice *
nm_device_parent_get_device (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	priv = NM_DEVICE_GET_PRIVATE (self);
	return priv->parent_device;
}

static void
parent_changed_notify (NMDevice *self,
                       int old_ifindex,
                       NMDevice *old_parent,
                       int new_ifindex,
                       NMDevice *new_parent)
{
	/* empty handler to allow subclasses to always chain up the virtual function. */
}

static gboolean
_parent_set_ifindex (NMDevice *self,
                     int parent_ifindex,
                     gboolean force_check)
{
	NMDevicePrivate *priv;
	NMDevice *parent_device;
	gboolean changed = FALSE;
	int old_ifindex;
	NMDevice *old_device;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (parent_ifindex <= 0)
		parent_ifindex = 0;

	old_ifindex = priv->parent_ifindex;
	old_device = priv->parent_device;

	if (priv->parent_ifindex == parent_ifindex) {
		if (parent_ifindex > 0) {
			if (   !force_check
			    && priv->parent_device
			    && nm_device_get_ifindex (priv->parent_device) == parent_ifindex)
				return FALSE;
		} else {
			if (!priv->parent_device)
				return FALSE;
		}
	} else {
		priv->parent_ifindex = parent_ifindex;
		changed = TRUE;
	}

	if (parent_ifindex > 0) {
		parent_device = nm_manager_get_device_by_ifindex (nm_manager_get (), parent_ifindex);
		if (parent_device == self)
			parent_device = NULL;
	} else
		parent_device = NULL;

	if (parent_device != priv->parent_device) {
		priv->parent_device = parent_device;
		changed = TRUE;
	}

	if (changed) {
		if (priv->parent_ifindex <= 0)
			_LOGD (LOGD_DEVICE, "parent: clear");
		else if (!priv->parent_device)
			_LOGD (LOGD_DEVICE, "parent: ifindex %d, no device", priv->parent_ifindex);
		else {
			_LOGD (LOGD_DEVICE, "parent: ifindex %d, device %p, %s", priv->parent_ifindex,
			       priv->parent_device, nm_device_get_iface (priv->parent_device));
		}

		NM_DEVICE_GET_CLASS (self)->parent_changed_notify (self, old_ifindex, old_device, priv->parent_ifindex, priv->parent_device);

		_notify (self, PROP_PARENT);
	}
	return changed;
}

void
nm_device_parent_set_ifindex (NMDevice *self,
                              int parent_ifindex)
{
	_parent_set_ifindex (self, parent_ifindex, FALSE);
}

gboolean
nm_device_parent_notify_changed (NMDevice *self,
                                 NMDevice *change_candidate,
                                 gboolean device_removed)
{
	NMDevicePrivate *priv;

	nm_assert (NM_IS_DEVICE (self));
	nm_assert (NM_IS_DEVICE (change_candidate));

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->parent_ifindex > 0) {
		if (   priv->parent_device == change_candidate
		    || priv->parent_ifindex == nm_device_get_ifindex (change_candidate))
			return _parent_set_ifindex (self, priv->parent_ifindex, device_removed);
	}
	return FALSE;
}

/*****************************************************************************/

static void
_stats_update_counters (NMDevice *self,
                        guint64 tx_bytes,
                        guint64 rx_bytes)
{
	NMDevicePrivate *priv;

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->stats.tx_bytes != tx_bytes) {
		priv->stats.tx_bytes = tx_bytes;
		_notify (self, PROP_TX_BYTES);
	}
	if (priv->stats.rx_bytes != rx_bytes) {
		priv->stats.rx_bytes = rx_bytes;
		_notify (self, PROP_RX_BYTES);
	}
}

static void
_stats_update_counters_from_pllink (NMDevice *self, const NMPlatformLink *pllink)
{
	_stats_update_counters (self, pllink->tx_bytes, pllink->rx_bytes);
}

static gboolean
_stats_timeout_cb (gpointer user_data)
{
	NMDevice *self = user_data;
	int ifindex;

	ifindex = nm_device_get_ip_ifindex (self);

	_LOGT (LOGD_DEVICE, "stats: refresh %d", ifindex);

	if (ifindex > 0)
		nm_platform_link_refresh (nm_device_get_platform (self), ifindex);

	return G_SOURCE_CONTINUE;
}

static guint
_stats_refresh_rate_real (guint refresh_rate_ms)
{
	const guint STATS_REFRESH_RATE_MS_MIN = 200;

	if (refresh_rate_ms == 0)
		return 0;

	if (refresh_rate_ms < STATS_REFRESH_RATE_MS_MIN) {
		/* you cannot set the refresh-rate arbitrarly small. E.g.
		 * setting to 1ms is just killing. Have a lowest number. */
		return STATS_REFRESH_RATE_MS_MIN;
	}

	return refresh_rate_ms;
}

static void
_stats_set_refresh_rate (NMDevice *self, guint refresh_rate_ms)
{
	NMDevicePrivate *priv;
	int ifindex;
	guint old_rate;

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->stats.refresh_rate_ms == refresh_rate_ms)
		return;

	old_rate = priv->stats.refresh_rate_ms;
	priv->stats.refresh_rate_ms = refresh_rate_ms;
	_notify (self, PROP_REFRESH_RATE_MS);

	_LOGD (LOGD_DEVICE, "stats: set refresh to %u ms", priv->stats.refresh_rate_ms);

	if (!nm_device_is_real (self))
		return;

	refresh_rate_ms = _stats_refresh_rate_real (refresh_rate_ms);
	if (_stats_refresh_rate_real (old_rate) == refresh_rate_ms)
		return;

	nm_clear_g_source (&priv->stats.timeout_id);

	if (!refresh_rate_ms)
		return;

	/* trigger an initial refresh of the data whenever the refresh-rate changes.
	 * As we process the result in an idle handler with device_link_changed(),
	 * we don't get the result right away. */
	ifindex = nm_device_get_ip_ifindex (self);
	if (ifindex > 0)
		nm_platform_link_refresh (nm_device_get_platform (self), ifindex);

	priv->stats.timeout_id = g_timeout_add (refresh_rate_ms, _stats_timeout_cb, self);
}

/*****************************************************************************/

static gboolean
get_ip_iface_identifier (NMDevice *self, NMUtilsIPv6IfaceId *out_iid)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const NMPlatformLink *pllink;
	int ifindex;
	gboolean success;

	/* If we get here, we *must* have a kernel netdev, which implies an ifindex */
	ifindex = nm_device_get_ip_ifindex (self);
	g_return_val_if_fail (ifindex > 0, FALSE);

	pllink = nm_platform_link_get (nm_device_get_platform (self), ifindex);
	if (   !pllink
	    || NM_IN_SET (pllink->type, NM_LINK_TYPE_NONE, NM_LINK_TYPE_UNKNOWN))
		return FALSE;

	if (pllink->addr.len <= 0)
		return FALSE;
	if (pllink->addr.len > NM_UTILS_HWADDR_LEN_MAX)
		g_return_val_if_reached (FALSE);

	success = nm_utils_get_ipv6_interface_identifier (pllink->type,
	                                                  pllink->addr.data,
	                                                  pllink->addr.len,
	                                                  priv->dev_id,
	                                                  out_iid);
	if (!success) {
		_LOGW (LOGD_PLATFORM, "failed to generate interface identifier "
		       "for link type %u hwaddr_len %u", pllink->type, (unsigned) pllink->addr.len);
	}
	return success;
}

/**
 * nm_device_get_ip_iface_identifier:
 * @self: an #NMDevice
 * @iid: where to place the interface identifier
 * @ignore_token: force creation of a non-tokenized address
 *
 * Return the interface's identifier for the EUI64 address generation mode.
 * It's either a manually set token or and identifier generated in a
 * hardware-specific way.
 *
 * Unless @ignore_token is set the token is preferred. That is the case
 * for link-local addresses (to mimic kernel behavior).
 *
 * Returns: #TRUE if the @iid could be set
 */
static gboolean
nm_device_get_ip_iface_identifier (NMDevice *self, NMUtilsIPv6IfaceId *iid, gboolean ignore_token)
{
	NMSettingIP6Config *s_ip6;
	const char *token = NULL;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (!ignore_token) {
		s_ip6 = (NMSettingIP6Config *)
		    nm_device_get_applied_setting (self, NM_TYPE_SETTING_IP6_CONFIG);
		g_return_val_if_fail (s_ip6, FALSE);
		token = nm_setting_ip6_config_get_token (s_ip6);
	}
	if (token)
		return nm_utils_ipv6_interface_identifier_get_from_token (iid, token);
	else
		return NM_DEVICE_GET_CLASS (self)->get_ip_iface_identifier (self, iid);
}

const char *
nm_device_get_driver (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->driver;
}

const char *
nm_device_get_driver_version (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->driver_version;
}

NMDeviceType
nm_device_get_device_type (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_DEVICE_TYPE_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (self)->type;
}

NMLinkType
nm_device_get_link_type (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_LINK_TYPE_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (self)->link_type;
}

/**
 * nm_device_get_metered:
 * @setting: the #NMDevice
 *
 * Returns: the #NMDevice:metered property of the device.
 *
 * Since: 1.2
 **/
NMMetered
nm_device_get_metered (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_METERED_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (self)->metered;
}

guint32
nm_device_get_route_metric_default (NMDeviceType device_type)
{
	/* Device 'priority' is used for the default route-metric and is based on
	 * the device type. The settings ipv4.route-metric and ipv6.route-metric
	 * can overwrite this default.
	 *
	 * For both IPv4 and IPv6 we use the same default values.
	 *
	 * The route-metric is used for the metric of the routes of device.
	 * This also applies to the default route. Therefore it affects also
	 * which device is the "best".
	 *
	 * For comparison, note that iproute2 by default adds IPv4 routes with
	 * metric 0, and IPv6 routes with metric 1024. The latter is the IPv6
	 * "user default" in the kernel (NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6).
	 * In kernel, the full uint32_t range is available for route
	 * metrics (except for IPv6, where 0 means 1024).
	 */

	switch (device_type) {
	/* 50 is reserved for VPN (NM_VPN_ROUTE_METRIC_DEFAULT) */
	case NM_DEVICE_TYPE_ETHERNET:
	case NM_DEVICE_TYPE_VETH:
		return 100;
	case NM_DEVICE_TYPE_MACSEC:
		return 125;
	case NM_DEVICE_TYPE_INFINIBAND:
		return 150;
	case NM_DEVICE_TYPE_ADSL:
		return 200;
	case NM_DEVICE_TYPE_WIMAX:
		return 250;
	case NM_DEVICE_TYPE_BOND:
		return 300;
	case NM_DEVICE_TYPE_TEAM:
		return 350;
	case NM_DEVICE_TYPE_VLAN:
		return 400;
	case NM_DEVICE_TYPE_MACVLAN:
		return 410;
	case NM_DEVICE_TYPE_BRIDGE:
		return 425;
	case NM_DEVICE_TYPE_TUN:
		return 450;
	case NM_DEVICE_TYPE_PPP:
		return 460;
	case NM_DEVICE_TYPE_VXLAN:
		return 500;
	case NM_DEVICE_TYPE_DUMMY:
		return 550;
	case NM_DEVICE_TYPE_WIFI:
		return 600;
	case NM_DEVICE_TYPE_OLPC_MESH:
		return 650;
	case NM_DEVICE_TYPE_IP_TUNNEL:
		return 675;
	case NM_DEVICE_TYPE_MODEM:
		return 700;
	case NM_DEVICE_TYPE_BT:
		return 750;
	case NM_DEVICE_TYPE_OVS_BRIDGE:
	case NM_DEVICE_TYPE_OVS_INTERFACE:
	case NM_DEVICE_TYPE_OVS_PORT:
		return 800;
	case NM_DEVICE_TYPE_GENERIC:
		return 950;
	case NM_DEVICE_TYPE_UNKNOWN:
		return 10000;
	case NM_DEVICE_TYPE_UNUSED1:
	case NM_DEVICE_TYPE_UNUSED2:
		/* omit default: to get compiler warning about missing switch cases */
		break;
	}
	return 11000;
}

static gboolean
default_route_metric_penalty_detect (NMDevice *self)
{
#if WITH_CONCHECK
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	/* currently we don't differentiate between IPv4 and IPv6 when detecting
	 * connectivity. */
	if (   priv->connectivity_state != NM_CONNECTIVITY_FULL
		&& nm_connectivity_check_enabled (nm_connectivity_get ())) {
		return TRUE;
	}
#endif

	return FALSE;
}

static guint32
default_route_metric_penalty_get (NMDevice *self, int addr_family)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	nm_assert_addr_family (addr_family);

	if (  addr_family == AF_INET
	    ? priv->default_route_metric_penalty_ip4_has
	    : priv->default_route_metric_penalty_ip6_has)
		return 20000;
	return 0;
}

guint32
nm_device_get_route_metric (NMDevice *self,
                            int addr_family)
{
	char *value;
	gint64 route_metric;
	NMSettingIPConfig *s_ip;
	NMConnection *connection;

	g_return_val_if_fail (NM_IS_DEVICE (self), G_MAXUINT32);
	g_return_val_if_fail (NM_IN_SET (addr_family, AF_INET, AF_INET6), G_MAXUINT32);

	connection = nm_device_get_applied_connection (self);
	if (connection) {
		s_ip = addr_family == AF_INET
		       ? nm_connection_get_setting_ip4_config (connection)
		       : nm_connection_get_setting_ip6_config (connection);

		/* Slave interfaces don't have IP settings, but we may get here when
		 * external changes are made or when noticing IP changes when starting
		 * the slave connection.
		 */
		if (s_ip) {
			route_metric = nm_setting_ip_config_get_route_metric (s_ip);
			if (route_metric >= 0)
				goto out;
		}
	}

	/* use the current NMConfigData, which makes this configuration reloadable.
	 * Note that that means that the route-metric might change between SIGHUP.
	 * You must cache the returned value if that is a problem. */
	value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
	                                               addr_family == AF_INET ? "ipv4.route-metric" : "ipv6.route-metric", self);
	if (value) {
		route_metric = _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXUINT32, -1);
		g_free (value);

		if (route_metric >= 0)
			goto out;
	}

	route_metric = nm_manager_device_route_metric_reserve (nm_manager_get (),
	                                                       nm_device_get_ip_ifindex (self),
	                                                       nm_device_get_device_type (self));
out:
	return nm_utils_ip_route_metric_normalize (addr_family, route_metric);
}

static NMSettingConnectionMdns
_get_mdns (NMDevice *self)
{
	NMConnection *connection;
	NMSettingConnectionMdns mdns = NM_SETTING_CONNECTION_MDNS_DEFAULT;

	g_return_val_if_fail (NM_IS_DEVICE (self), NM_SETTING_CONNECTION_MDNS_DEFAULT);

	connection = nm_device_get_applied_connection (self);
	if (connection)
		mdns = nm_setting_connection_get_mdns (nm_connection_get_setting_connection (connection));

	if (mdns == NM_SETTING_CONNECTION_MDNS_DEFAULT) {
		gs_free char *value = NULL;

		value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
		                                               "connection.mdns",
		                                               self);
		mdns = _nm_utils_ascii_str_to_int64 (value,
		                                     10,
		                                     NM_SETTING_CONNECTION_MDNS_NO,
		                                     NM_SETTING_CONNECTION_MDNS_YES,
		                                     NM_SETTING_CONNECTION_MDNS_DEFAULT);
	}

	return mdns;
}

guint32
nm_device_get_route_table (NMDevice *self,
                           int addr_family,
                           gboolean fallback_main)
{
	NMDevicePrivate *priv;
	NMConnection *connection;
	NMSettingIPConfig *s_ip;
	guint32 route_table = 0;

	nm_assert_addr_family (addr_family);

	g_return_val_if_fail (NM_IS_DEVICE (self), RT_TABLE_MAIN);

	priv = NM_DEVICE_GET_PRIVATE (self);

	/* the route table setting affects how we sync routes. We shall
	 * not change it while the device is active, hence, cache it. */
	if (addr_family == AF_INET) {
		if (priv->v4_route_table_initialized)
			return priv->v4_route_table ?: (fallback_main ? RT_TABLE_MAIN : 0);
	} else {
		if (priv->v6_route_table_initialized)
			return priv->v6_route_table ?: (fallback_main ? RT_TABLE_MAIN : 0);
	}

	connection = nm_device_get_applied_connection (self);
	if (connection) {
		if (addr_family == AF_INET)
			s_ip = nm_connection_get_setting_ip4_config (connection);
		else
			s_ip = nm_connection_get_setting_ip6_config (connection);

		if (s_ip)
			route_table = nm_setting_ip_config_get_route_table (s_ip);

		/* we only lookup the global default if we also have an applied
		 * connection. Otherwise, the connection is not active, and the
		 * connection default doesn't matter. */
		if (route_table == 0) {
			gs_free char *value = NULL;

			value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
			                                               addr_family == AF_INET
			                                                 ? "ipv4.route-table"
			                                                 : "ipv6.route-table",
			                                               self);
			route_table = _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXUINT32, 0);
		}
	}

	if (addr_family == AF_INET) {
		priv->v4_route_table_initialized = TRUE;
		priv->v4_route_table = route_table;
	} else {
		priv->v6_route_table_initialized = TRUE;
		priv->v6_route_table = route_table;
	}

	_LOGT (LOGD_DEVICE,
	       "ipv%c.route-table = %u%s",
	       addr_family == AF_INET ? '4' : '6',
	       (guint) (route_table ?: RT_TABLE_MAIN),
	       route_table ? "" : " (policy routing not enabled)");

	return route_table ?: (fallback_main ? RT_TABLE_MAIN : 0);
}

const NMPObject *
nm_device_get_best_default_route (NMDevice *self,
                                  int addr_family)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	switch (addr_family) {
	case AF_INET:
		return priv->ip4_config ? nm_ip4_config_best_default_route_get (priv->ip4_config) : NULL;
	case AF_INET6:
		return priv->ip6_config ? nm_ip6_config_best_default_route_get (priv->ip6_config) : NULL;
	case AF_UNSPEC:
		return    (priv->ip4_config ? nm_ip4_config_best_default_route_get (priv->ip4_config) : NULL)
		       ?: (priv->ip6_config ? nm_ip6_config_best_default_route_get (priv->ip6_config) : NULL);
	default:
		g_return_val_if_reached (NULL);
	}
}

const char *
nm_device_get_type_desc (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_DEVICE_GET_PRIVATE (self)->type_desc;
}

const char *
nm_device_get_type_description (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	/* Beware: this function should return the same
	 * value as nm_device_get_type_description() in libnm. */

	return NM_DEVICE_GET_CLASS (self)->get_type_description (self);
}

static const char *
get_type_description (NMDevice *self)
{
	NMDeviceClass *klass;

	nm_assert (NM_IS_DEVICE (self));

	klass = NM_DEVICE_GET_CLASS (self);
	if (G_UNLIKELY (!klass->default_type_description)) {
		const char *typename;
		gs_free char *s = NULL;

		typename = G_OBJECT_TYPE_NAME (self);
		if (g_str_has_prefix (typename, "NMDevice"))
			typename += 8;
		s = g_ascii_strdown (typename, -1);
		klass->default_type_description = g_intern_string (s);
	}

	return klass->default_type_description;
}

gboolean
nm_device_has_carrier (NMDevice *self)
{
	return NM_DEVICE_GET_PRIVATE (self)->carrier;
}

NMActRequest *
nm_device_get_act_request (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->act_request;
}

NMSettingsConnection *
nm_device_get_settings_connection (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	return priv->act_request ? nm_act_request_get_settings_connection (priv->act_request) : NULL;
}

NMConnection *
nm_device_get_applied_connection (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	priv = NM_DEVICE_GET_PRIVATE (self);

	return priv->act_request ? nm_act_request_get_applied_connection (priv->act_request) : NULL;
}

gboolean
nm_device_has_unmodified_applied_connection (NMDevice *self, NMSettingCompareFlags compare_flags)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (!priv->act_request)
		return FALSE;

	return nm_active_connection_has_unmodified_applied_connection ((NMActiveConnection *) priv->act_request, compare_flags);
}

NMSetting *
nm_device_get_applied_setting (NMDevice *self, GType setting_type)
{
	NMConnection *connection;

	connection = nm_device_get_applied_connection (self);
	return connection ? nm_connection_get_setting (connection, setting_type) : NULL;
}

RfKillType
nm_device_get_rfkill_type (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	return NM_DEVICE_GET_PRIVATE (self)->rfkill_type;
}

static const char *
nm_device_get_physical_port_id (NMDevice *self)
{
	return NM_DEVICE_GET_PRIVATE (self)->physical_port_id;
}

/*****************************************************************************/

static void
update_connectivity_state (NMDevice *self, NMConnectivityState state)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	/* If the connectivity check is disabled, make an optimistic guess. */
	if (state == NM_CONNECTIVITY_UNKNOWN) {
		if (priv->state == NM_DEVICE_STATE_ACTIVATED) {
			if (nm_device_get_best_default_route (self, AF_UNSPEC))
				state = NM_CONNECTIVITY_FULL;
			else
				state = NM_CONNECTIVITY_LIMITED;
		} else {
			state = NM_CONNECTIVITY_NONE;
		}
	}

	if (priv->connectivity_state != state) {
#if WITH_CONCHECK
		_LOGD (LOGD_CONCHECK, "state changed from %s to %s",
		       nm_connectivity_state_to_string (priv->connectivity_state),
		       nm_connectivity_state_to_string (state));
#endif
		priv->connectivity_state = state;
		_notify (self, PROP_CONNECTIVITY);

		if (   priv->state == NM_DEVICE_STATE_ACTIVATED
		    && !nm_device_sys_iface_state_is_external (self)) {
			if (   nm_device_get_best_default_route (self, AF_INET)
			    && !ip4_config_merge_and_apply (self, TRUE))
				_LOGW (LOGD_IP4, "Failed to update IPv4 route metric");
			if (   nm_device_get_best_default_route (self, AF_INET6)
			    && !ip6_config_merge_and_apply (self, TRUE))
				_LOGW (LOGD_IP6, "Failed to update IPv6 route metric");
		}
	}
}

typedef struct {
	NMDevice *self;
	NMDeviceConnectivityCallback callback;
	gpointer user_data;
	guint64 seq;
} ConnectivityCheckData;

static void
concheck_done (ConnectivityCheckData *data)
{
	NMDevice *self = data->self;
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	/* The unsolicited connectivity checks don't hook a callback. */
	if (data->callback)
		data->callback (data->self, priv->connectivity_state, data->user_data);
	g_object_unref (data->self);
	g_slice_free (ConnectivityCheckData, data);
}

#if WITH_CONCHECK
static void
concheck_cb (GObject *source_object, GAsyncResult *result, gpointer user_data)
{
	ConnectivityCheckData *data = user_data;
	NMDevice *self = data->self;
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnectivity *connectivity = NM_CONNECTIVITY (source_object);
	NMConnectivityState state;
	GError *error = NULL;

	state = nm_connectivity_check_finish (connectivity, result, &error);
	if (error) {
		_LOGW (LOGD_DEVICE, "connectivity checking on '%s' failed: %s",
		       nm_device_get_iface (self), error->message);
		g_error_free (error);
	}

	if (data->seq == priv->concheck_seq)
		update_connectivity_state (data->self, state);
	concheck_done (data);
}
#endif /* WITH_CONCHECK */

static gboolean
no_concheck (gpointer user_data)
{
	ConnectivityCheckData *data = user_data;

	concheck_done (data);
	return G_SOURCE_REMOVE;
}

void
nm_device_check_connectivity (NMDevice *self,
                              NMDeviceConnectivityCallback callback,
                              gpointer user_data)
{
	ConnectivityCheckData *data;
#if WITH_CONCHECK
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
#endif

	data = g_slice_new0 (ConnectivityCheckData);
	data->self = g_object_ref (self);
	data->callback = callback;
	data->user_data = user_data;

#if WITH_CONCHECK
	if (priv->concheck_periodic_id) {
		data->seq = ++priv->concheck_seq;

		/* Kick off a real connectivity check. */
		nm_connectivity_check_async (nm_connectivity_get (),
		                             nm_device_get_ip_iface (self),
		                             concheck_cb,
		                             data);
		return;
	}
#endif

	/* Fake one. */
	g_idle_add (no_concheck, data);
}

NMConnectivityState
nm_device_get_connectivity_state (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_CONNECTIVITY_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (self)->connectivity_state;
}

#if WITH_CONCHECK
static void
concheck_periodic (NMConnectivity *connectivity, NMDevice *self)
{
	nm_device_check_connectivity (self, NULL, NULL);
}
#endif

static void
concheck_periodic_update (NMDevice *self)
{
#if WITH_CONCHECK
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean check_enable;

	check_enable =    (priv->state == NM_DEVICE_STATE_ACTIVATED)
	               && nm_device_get_best_default_route (self, AF_UNSPEC);

	if (check_enable && !priv->concheck_periodic_id) {
		/* We just gained a default route. Enable periodic checking. */
		priv->concheck_periodic_id = g_signal_connect (nm_connectivity_get (),
		                                               NM_CONNECTIVITY_PERIODIC_CHECK,
		                                               G_CALLBACK (concheck_periodic), self);
		/* Also kick off a check right away. */
		nm_device_check_connectivity (self, NULL, NULL);
	} else if (!check_enable && priv->concheck_periodic_id) {
		/* The default route has gone off, and so has connectivity. */
		g_signal_handler_disconnect (nm_connectivity_get (), priv->concheck_periodic_id);
		priv->concheck_periodic_id = 0;
		update_connectivity_state (self, NM_CONNECTIVITY_NONE);
	}
#else
	/* update_connectivity_state() figures out how to lie about
	 * connectivity state if the actual state is not really known. */
	update_connectivity_state (self, NM_CONNECTIVITY_UNKNOWN);
#endif
}

/*****************************************************************************/

static SlaveInfo *
find_slave_info (NMDevice *self, NMDevice *slave)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	CList *iter;
	SlaveInfo *info;

	c_list_for_each (iter, &priv->slaves) {
		info = c_list_entry (iter, SlaveInfo, lst_slave);
		if (info->slave == slave)
			return info;
	}
	return NULL;
}

/**
 * nm_device_master_enslave_slave:
 * @self: the master device
 * @slave: the slave device to enslave
 * @connection: (allow-none): the slave device's connection
 *
 * If @self is capable of enslaving other devices (ie it's a bridge, bond, team,
 * etc) then this function enslaves @slave.
 *
 * Returns: %TRUE on success, %FALSE on failure or if this device cannot enslave
 *  other devices.
 */
static gboolean
nm_device_master_enslave_slave (NMDevice *self, NMDevice *slave, NMConnection *connection)
{
	SlaveInfo *info;
	gboolean success = FALSE;
	gboolean configure;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (slave != NULL, FALSE);
	g_return_val_if_fail (NM_DEVICE_GET_CLASS (self)->enslave_slave != NULL, FALSE);

	info = find_slave_info (self, slave);
	if (!info)
		return FALSE;

	if (info->slave_is_enslaved)
		success = TRUE;
	else {
		configure = (info->configure && connection != NULL);
		if (configure)
			g_return_val_if_fail (nm_device_get_state (slave) >= NM_DEVICE_STATE_DISCONNECTED, FALSE);

		success = NM_DEVICE_GET_CLASS (self)->enslave_slave (self, slave, connection, configure);
		info->slave_is_enslaved = success;
	}

	nm_device_slave_notify_enslave (info->slave, success);

	/* Ensure the device's hardware address is up-to-date; it often changes
	 * when slaves change.
	 */
	nm_device_update_hw_address (self);

	/* Restart IP configuration if we're waiting for slaves.  Do this
	 * after updating the hardware address as IP config may need the
	 * new address.
	 */
	if (success) {
		if (NM_DEVICE_GET_PRIVATE (self)->ip4_state == IP_WAIT)
			nm_device_activate_stage3_ip4_start (self);

		if (NM_DEVICE_GET_PRIVATE (self)->ip6_state == IP_WAIT)
			nm_device_activate_stage3_ip6_start (self);
	}

	/* Since slave devices don't have their own IP configuration,
	 * set the MTU here.
	 */
	_commit_mtu (slave, NM_DEVICE_GET_PRIVATE (slave)->ip4_config);

	return success;
}

/**
 * nm_device_master_release_one_slave:
 * @self: the master device
 * @slave: the slave device to release
 * @configure: whether @self needs to actually release @slave
 * @reason: the state change reason for the @slave
 *
 * If @self is capable of enslaving other devices (ie it's a bridge, bond, team,
 * etc) then this function releases the previously enslaved @slave and/or
 * updates the state of @self and @slave to reflect its release.
 */
static void
nm_device_master_release_one_slave (NMDevice *self, NMDevice *slave, gboolean configure, NMDeviceStateReason reason)
{
	NMDevicePrivate *priv;
	NMDevicePrivate *slave_priv;
	SlaveInfo *info;
	gs_unref_object NMDevice *self_free = NULL;

	g_return_if_fail (NM_DEVICE (self));
	g_return_if_fail (NM_DEVICE (slave));
	g_return_if_fail (NM_DEVICE_GET_CLASS (self)->release_slave != NULL);

	info = find_slave_info (self, slave);

	_LOGT (LOGD_CORE, "master: release one slave %p/%s%s", slave, nm_device_get_iface (slave),
	       !info ? " (not registered)" : "");

	if (!info)
		g_return_if_reached ();

	priv = NM_DEVICE_GET_PRIVATE (self);
	slave_priv = NM_DEVICE_GET_PRIVATE (slave);

	g_return_if_fail (self == slave_priv->master);
	nm_assert (slave == info->slave);

	/* first, let subclasses handle the release ... */
	if (info->slave_is_enslaved)
		NM_DEVICE_GET_CLASS (self)->release_slave (self, slave, configure);

	/* raise notifications about the release, including clearing is_enslaved. */
	nm_device_slave_notify_release (slave, reason);

	/* keep both alive until the end of the function.
	 * Transfers ownership from slave_priv->master.  */
	self_free = self;

	c_list_unlink (&info->lst_slave);
	slave_priv->master = NULL;

	g_signal_handler_disconnect (slave, info->watch_id);
	g_object_unref (slave);
	g_slice_free (SlaveInfo, info);

	if (c_list_is_empty (&priv->slaves)) {
		_active_connection_set_state_flags_full (self,
		                                         0,
		                                         NM_ACTIVATION_STATE_FLAG_MASTER_HAS_SLAVES);
	}

	/* Ensure the device's hardware address is up-to-date; it often changes
	 * when slaves change.
	 */
	nm_device_update_hw_address (self);
	nm_device_set_unmanaged_by_flags (slave, NM_UNMANAGED_IS_SLAVE, NM_UNMAN_FLAG_OP_FORGET, NM_DEVICE_STATE_REASON_REMOVED);
}

/**
 * can_unmanaged_external_down:
 * @self: the device
 *
 * Check whether the device should stay NM_UNMANAGED_EXTERNAL_DOWN unless
 * IFF_UP-ed externally.
 */
static gboolean
can_unmanaged_external_down (NMDevice *self)
{
	return    !NM_DEVICE_GET_PRIVATE (self)->nm_owned
	       && nm_device_is_software (self);
}

static NMUnmanFlagOp
is_unmanaged_external_down (NMDevice *self, gboolean consider_can)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (   consider_can
	    && !NM_DEVICE_GET_CLASS (self)->can_unmanaged_external_down (self))
		return NM_UNMAN_FLAG_OP_FORGET;

	/* Manage externally-created software interfaces only when they are IFF_UP */
	if (   priv->ifindex <= 0
	    || !priv->up
	    || !(   !c_list_is_empty (&priv->slaves)
	         || nm_platform_link_can_assume (nm_device_get_platform (self), priv->ifindex)))
		return NM_UNMAN_FLAG_OP_SET_UNMANAGED;

	return NM_UNMAN_FLAG_OP_SET_MANAGED;
}

static void
set_unmanaged_external_down (NMDevice *self, gboolean only_if_unmanaged)
{
	NMUnmanFlagOp ext_flags;

	if (!nm_device_get_unmanaged_mask (self, NM_UNMANAGED_EXTERNAL_DOWN))
		return;

	if (only_if_unmanaged) {
		if (!nm_device_get_unmanaged_flags (self, NM_UNMANAGED_EXTERNAL_DOWN))
			return;
	}

	ext_flags = is_unmanaged_external_down (self, FALSE);
	if (ext_flags != NM_UNMAN_FLAG_OP_SET_UNMANAGED) {
		/* Ensure the assume check is queued before any queued state changes
		 * from the transition to UNAVAILABLE.
		 */
		nm_device_queue_recheck_assume (self);
	}

	nm_device_set_unmanaged_by_flags (self,
	                                  NM_UNMANAGED_EXTERNAL_DOWN,
	                                  ext_flags,
	                                  NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
}

void
nm_device_update_dynamic_ip_setup (NMDevice *self)
{
	NMDevicePrivate *priv;
	GError *error = NULL;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);

	g_hash_table_remove_all (priv->ip6_saved_properties);

	if (priv->dhcp4.client) {
		if (!nm_device_dhcp4_renew (self, FALSE)) {
			nm_device_state_changed (self,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_DHCP_FAILED);
			return;
		}
	}
	if (priv->dhcp6.client) {
		if (!nm_device_dhcp6_renew (self, FALSE)) {
			nm_device_state_changed (self,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_DHCP_FAILED);
			return;
		}
	}
	if (priv->ndisc) {
		/* FIXME: todo */
	}
	if (priv->dnsmasq_manager) {
		/* FIXME: todo */
	}

	if (priv->lldp_listener && nm_lldp_listener_is_running (priv->lldp_listener)) {
		nm_lldp_listener_stop (priv->lldp_listener);
		if (!nm_lldp_listener_start (priv->lldp_listener, nm_device_get_ifindex (self), &error)) {
			_LOGD (LOGD_DEVICE, "LLDP listener %p could not be restarted: %s",
			       priv->lldp_listener, error->message);
			g_clear_error (&error);
		}
	}
}

/*****************************************************************************/

static void
carrier_changed_notify (NMDevice *self, gboolean carrier)
{
	/* stub */
}

static void
carrier_changed (NMDevice *self, gboolean carrier)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->state <= NM_DEVICE_STATE_UNMANAGED)
		return;

	nm_device_recheck_available_connections (self);

	/* ignore-carrier devices ignore all carrier-down events */
	if (priv->ignore_carrier && !carrier)
		return;

	if (nm_device_is_master (self)) {
		if (carrier) {
			/* Force master to retry getting ip addresses when carrier
			* is restored. */
			if (priv->state == NM_DEVICE_STATE_ACTIVATED)
				nm_device_update_dynamic_ip_setup (self);
			else {
				if (nm_device_activate_ip4_state_in_wait (self))
					nm_device_activate_stage3_ip4_start (self);
				if (nm_device_activate_ip6_state_in_wait (self))
					nm_device_activate_stage3_ip6_start (self);
			}
			return;
		}
		/* fall-through and change state of device */
	} else if (priv->is_enslaved && !carrier) {
		/* Slaves don't deactivate when they lose carrier; for
		 * bonds/teams in particular that would be actively
		 * counterproductive.
		 */
		return;
	}

	if (carrier) {
		if (priv->state == NM_DEVICE_STATE_UNAVAILABLE) {
			nm_device_queue_state (self, NM_DEVICE_STATE_DISCONNECTED,
			                       NM_DEVICE_STATE_REASON_CARRIER);
		} else if (priv->state == NM_DEVICE_STATE_DISCONNECTED) {
			/* If the device is already in DISCONNECTED state without a carrier
			 * (probably because it is tagged for carrier ignore) ensure that
			 * when the carrier appears, auto connections are rechecked for
			 * the device.
			 */
			nm_device_emit_recheck_auto_activate (self);
		} else if (priv->state == NM_DEVICE_STATE_ACTIVATED) {
			/* If the device is active without a carrier (probably because it is
			 * tagged for carrier ignore) ensure that when the carrier appears we
			 * renew DHCP leases and such.
			 */
			nm_device_update_dynamic_ip_setup (self);
		}
	} else {
		if (priv->state == NM_DEVICE_STATE_UNAVAILABLE) {
			if (   priv->queued_state.id
			    && priv->queued_state.state >= NM_DEVICE_STATE_DISCONNECTED)
				queued_state_clear (self);
		} else {
			nm_device_queue_state (self, NM_DEVICE_STATE_UNAVAILABLE,
			                       NM_DEVICE_STATE_REASON_CARRIER);
		}
	}
}

static gboolean
carrier_disconnected_action_cb (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	_LOGD (LOGD_DEVICE, "carrier: link disconnected (calling deferred action) (id=%u)", priv->carrier_defer_id);

	priv->carrier_defer_id = 0;
	carrier_changed (self, FALSE);
	return FALSE;
}

static void
carrier_disconnected_action_cancel (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint id = priv->carrier_defer_id;

	if (nm_clear_g_source (&priv->carrier_defer_id)) {
		_LOGD (LOGD_DEVICE, "carrier: link disconnected (canceling deferred action) (id=%u)",
		       id);
	}
}

void
nm_device_set_carrier (NMDevice *self, gboolean carrier)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceState state = nm_device_get_state (self);

	if (priv->carrier == carrier)
		return;

	priv->carrier = carrier;
	_notify (self, PROP_CARRIER);

	if (priv->carrier) {
		_LOGI (LOGD_DEVICE, "carrier: link connected");
		carrier_disconnected_action_cancel (self);
		NM_DEVICE_GET_CLASS (self)->carrier_changed_notify (self, carrier);
		carrier_changed (self, TRUE);

		if (priv->carrier_wait_id) {
			nm_device_remove_pending_action (self, NM_PENDING_ACTION_CARRIER_WAIT, FALSE);
			_carrier_wait_check_queued_act_request (self);
		}
	} else {
		if (priv->carrier_wait_id)
			nm_device_add_pending_action (self, NM_PENDING_ACTION_CARRIER_WAIT, FALSE);
		NM_DEVICE_GET_CLASS (self)->carrier_changed_notify (self, carrier);
		if (   state <= NM_DEVICE_STATE_DISCONNECTED
		    && !priv->queued_act_request) {
			_LOGD (LOGD_DEVICE, "carrier: link disconnected");
			carrier_changed (self, FALSE);
		} else {
			gint64 now_ms, until_ms;

			now_ms = nm_utils_get_monotonic_timestamp_ms ();
			until_ms = NM_MAX (now_ms + _get_carrier_wait_ms (self), priv->carrier_wait_until_ms);
			priv->carrier_defer_id = g_timeout_add (until_ms - now_ms, carrier_disconnected_action_cb, self);
			_LOGD (LOGD_DEVICE, "carrier: link disconnected (deferring action for %ld milli seconds) (id=%u)",
			       (long) (until_ms - now_ms), priv->carrier_defer_id);
		}
	}
}

static void
nm_device_set_carrier_from_platform (NMDevice *self)
{
	if (nm_device_has_capability (self, NM_DEVICE_CAP_CARRIER_DETECT)) {
		if (!nm_device_has_capability (self, NM_DEVICE_CAP_NONSTANDARD_CARRIER)) {
			nm_device_set_carrier (self,
			                       nm_platform_link_is_connected (nm_device_get_platform (self),
			                                                      nm_device_get_ip_ifindex (self)));
		}
	} else {
		NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

		/* Fake online link when carrier detection is not available. */
		if (!priv->carrier) {
			priv->carrier = TRUE;
			_notify (self, PROP_CARRIER);
		}
	}
}

/*****************************************************************************/

static void
device_recheck_slave_status (NMDevice *self, const NMPlatformLink *plink)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDevice *master;
	nm_auto_nmpobj const NMPObject *plink_master_keep_alive = NULL;
	const NMPlatformLink *plink_master;

	g_return_if_fail (plink);

	if (plink->master <= 0)
		return;

	master = nm_manager_get_device_by_ifindex (nm_manager_get (), plink->master);
	plink_master = nm_platform_link_get (nm_device_get_platform (self), plink->master);
	plink_master_keep_alive = nmp_object_ref (NMP_OBJECT_UP_CAST (plink_master));

	if (   master == NULL
	    && plink_master
	    && g_strcmp0 (plink_master->name, "ovs-system") == 0
	    && plink_master->type == NM_LINK_TYPE_OPENVSWITCH) {
		_LOGD (LOGD_DEVICE, "the device claimed by openvswitch");
		return;
	}

	if (priv->master) {
		if (   plink->master > 0
		    && plink->master == nm_device_get_ifindex (priv->master)) {
			/* call add-slave again. We expect @self already to be added to
			 * the master, but this also triggers a recheck-assume. */
			nm_device_master_add_slave (priv->master, self, FALSE);
			return;
		}

		nm_device_master_release_one_slave (priv->master, self, FALSE, NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
	}

	if (master && NM_DEVICE_GET_CLASS (master)->enslave_slave)
		nm_device_master_add_slave (master, self, FALSE);
	else if (master) {
		_LOGI (LOGD_DEVICE, "enslaved to non-master-type device %s; ignoring",
		       nm_device_get_iface (master));
	} else {
		_LOGW (LOGD_DEVICE, "enslaved to unknown device %d (%s%s%s)",
		       plink->master,
		       NM_PRINT_FMT_QUOTED (plink_master, "\"", plink_master->name, "\"", "??"));
	}
}

static void
ndisc_set_router_config (NMNDisc *ndisc, NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gint32 now;
	GArray *addresses, *dns_servers, *dns_domains;
	guint len, i;
	const NMDedupMultiHeadEntry *head_entry;
	NMDedupMultiIter ipconf_iter;

	if (nm_ndisc_get_node_type (ndisc) != NM_NDISC_NODE_TYPE_ROUTER)
		return;

	now = nm_utils_get_monotonic_timestamp_s ();

	head_entry = nm_ip6_config_lookup_addresses (priv->ip6_config);
	addresses = g_array_sized_new (FALSE, TRUE, sizeof (NMNDiscAddress),
	                               head_entry ? head_entry->len : 0);
	nm_dedup_multi_iter_for_each (&ipconf_iter, head_entry) {
		const NMPlatformIP6Address *addr = NMP_OBJECT_CAST_IP6_ADDRESS (ipconf_iter.current->obj);
		NMNDiscAddress *ndisc_addr;
		guint32 lifetime, preferred;
		gint32 base;

		if (IN6_IS_ADDR_LINKLOCAL (&addr->address))
			continue;

		if (   addr->n_ifa_flags & IFA_F_TENTATIVE
		    || addr->n_ifa_flags & IFA_F_DADFAILED)
			continue;

		if (addr->plen != 64)
			continue;

		/* resolve the timestamps relative to a new base.
		 *
		 * Note that for convenience, platform @addr might have timestamp and/or
		 * lifetime unset. We don't allow that flexibility for ndisc and require
		 * well defined timestamps. */
		if (addr->timestamp) {
			nm_assert (addr->timestamp < G_MAXINT32);
			base = addr->timestamp;
		} else
			base = now;

		lifetime = nm_utils_lifetime_get (addr->timestamp, addr->lifetime, addr->preferred,
		                                  base, &preferred);
		if (!lifetime)
			continue;

		g_array_set_size (addresses, addresses->len+1);
		ndisc_addr = &g_array_index (addresses, NMNDiscAddress, addresses->len-1);
		ndisc_addr->address = addr->address;
		ndisc_addr->timestamp = base;
		ndisc_addr->lifetime = lifetime;
		ndisc_addr->preferred = preferred;
	}

	len = nm_ip6_config_get_num_nameservers (priv->ip6_config);
	dns_servers = g_array_sized_new (FALSE, TRUE, sizeof (NMNDiscDNSServer), len);
	g_array_set_size (dns_servers, len);
	for (i = 0; i < len; i++) {
		const struct in6_addr *nameserver = nm_ip6_config_get_nameserver (priv->ip6_config, i);
		NMNDiscDNSServer *ndisc_nameserver;

		ndisc_nameserver = &g_array_index (dns_servers, NMNDiscDNSServer, i);
		ndisc_nameserver->address = *nameserver;
		ndisc_nameserver->timestamp = now;
		ndisc_nameserver->lifetime = NM_NDISC_ROUTER_LIFETIME;
	}

	len = nm_ip6_config_get_num_searches (priv->ip6_config);
	dns_domains = g_array_sized_new (FALSE, TRUE, sizeof (NMNDiscDNSDomain), len);
	g_array_set_size (dns_domains, len);
	for (i = 0; i < len; i++) {
		const char *search = nm_ip6_config_get_search (priv->ip6_config, i);
		NMNDiscDNSDomain *ndisc_search;

		ndisc_search = &g_array_index (dns_domains, NMNDiscDNSDomain, i);
		ndisc_search->domain = (char *) search;
		ndisc_search->timestamp = now;
		ndisc_search->lifetime = NM_NDISC_ROUTER_LIFETIME;
	}

	nm_ndisc_set_config (ndisc, addresses, dns_servers, dns_domains);
	g_array_unref (addresses);
	g_array_unref (dns_servers);
	g_array_unref (dns_domains);
}

static gboolean
device_link_changed (NMDevice *self)
{
	NMDeviceClass *klass = NM_DEVICE_GET_CLASS (self);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean ip_ifname_changed = FALSE;
	nm_auto_nmpobj const NMPObject *pllink_keep_alive = NULL;
	const NMPlatformLink *pllink;
	int ifindex;
	gboolean was_up;
	gboolean update_unmanaged_specs = FALSE;
	gboolean got_hw_addr = FALSE, had_hw_addr;

	priv->device_link_changed_id = 0;

	ifindex = nm_device_get_ifindex (self);
	pllink = nm_platform_link_get (nm_device_get_platform (self), ifindex);
	if (!pllink)
		return G_SOURCE_REMOVE;

	pllink_keep_alive = nmp_object_ref (NMP_OBJECT_UP_CAST (pllink));

	nm_device_update_from_platform_link (self, pllink);

	had_hw_addr = (priv->hw_addr != NULL);
	nm_device_update_hw_address (self);
	got_hw_addr = (!had_hw_addr && priv->hw_addr);
	nm_device_update_permanent_hw_address (self, FALSE);

	if (pllink->name[0] && strcmp (priv->iface, pllink->name) != 0) {
		_LOGI (LOGD_DEVICE, "interface index %d renamed iface from '%s' to '%s'",
		       priv->ifindex, priv->iface, pllink->name);
		g_free (priv->iface);
		priv->iface = g_strdup (pllink->name);

		/* If the device has no explicit ip_iface, then changing iface changes ip_iface too. */
		ip_ifname_changed = !priv->ip_iface;

		if (nm_device_get_unmanaged_flags (self, NM_UNMANAGED_PLATFORM_INIT))
			nm_device_set_unmanaged_by_user_settings (self);
		else
			update_unmanaged_specs = TRUE;

		_notify (self, PROP_IFACE);
		if (ip_ifname_changed)
			_notify (self, PROP_IP_IFACE);

		/* Re-match available connections against the new interface name */
		nm_device_recheck_available_connections (self);

		/* Let any connections that use the new interface name have a chance
		 * to auto-activate on the device.
		 */
		nm_device_emit_recheck_auto_activate (self);
	}

	if (priv->ndisc && pllink->inet6_token.id) {
		if (nm_ndisc_set_iid (priv->ndisc, pllink->inet6_token))
			_LOGD (LOGD_DEVICE, "IPv6 tokenized identifier present on device %s", priv->iface);
	}

	/* Update carrier from link event if applicable. */
	if (   nm_device_has_capability (self, NM_DEVICE_CAP_CARRIER_DETECT)
	    && !nm_device_has_capability (self, NM_DEVICE_CAP_NONSTANDARD_CARRIER))
		nm_device_set_carrier (self, pllink->connected);

	klass->link_changed (self, pllink);

	/* Update DHCP, etc, if needed */
	if (ip_ifname_changed)
		nm_device_update_dynamic_ip_setup (self);

	was_up = priv->up;
	priv->up = NM_FLAGS_HAS (pllink->n_ifi_flags, IFF_UP);

	if (   pllink->initialized
	    && nm_device_get_unmanaged_flags (self, NM_UNMANAGED_PLATFORM_INIT)) {
		NMDeviceStateReason reason;

		nm_device_set_unmanaged_by_user_udev (self);
		nm_device_set_unmanaged_by_user_conf (self);

		reason = NM_DEVICE_STATE_REASON_NOW_MANAGED;

		/* If the device is a external-down candidated but no longer has external
		 * down set, we must clear the platform-unmanaged flag with reason
		 * "assumed". */
		if (    nm_device_get_unmanaged_mask (self, NM_UNMANAGED_EXTERNAL_DOWN)
		    && !nm_device_get_unmanaged_flags (self, NM_UNMANAGED_EXTERNAL_DOWN)) {
			/* actually, user-udev overwrites external-down. So we only assume the device,
			 * when it is a external-down candidate, which is not managed via udev. */
			if (!nm_device_get_unmanaged_mask (self, NM_UNMANAGED_USER_UDEV)) {
				/* Ensure the assume check is queued before any queued state changes
				 * from the transition to UNAVAILABLE.
				 */
				nm_device_queue_recheck_assume (self);
				reason = NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED;
			}
		}

		nm_device_set_unmanaged_by_flags (self, NM_UNMANAGED_PLATFORM_INIT, FALSE, reason);
	}

	set_unmanaged_external_down (self, FALSE);

	device_recheck_slave_status (self, pllink);

	if (priv->up && !was_up) {
		/* the link was down and just came up. That happens for example, while changing MTU.
		 * We must restore IP configuration. */
		if (priv->ip4_state == IP_DONE) {
			if (!ip4_config_merge_and_apply (self, TRUE))
				_LOGW (LOGD_IP4, "failed applying IP4 config after link comes up again");
		}
		if (priv->ip6_state == IP_DONE) {
			if (!ip6_config_merge_and_apply (self, TRUE))
				_LOGW (LOGD_IP6, "failed applying IP6 config after link comes up again");
		}
	}

	if (update_unmanaged_specs)
		nm_device_set_unmanaged_by_user_settings (self);

	if (   got_hw_addr
	    && !priv->up
	    && nm_device_get_state (self) == NM_DEVICE_STATE_UNAVAILABLE) {
		/*
		 * If the device is UNAVAILABLE, any previous try to
		 * bring it up probably has failed because of the
		 * invalid hardware address; try again.
		 */
		nm_device_bring_up (self, TRUE, NULL);
		nm_device_queue_recheck_available (self,
		                                   NM_DEVICE_STATE_REASON_NONE,
		                                   NM_DEVICE_STATE_REASON_NONE);
	}

	return G_SOURCE_REMOVE;
}

static gboolean
device_ip_link_changed (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const NMPlatformLink *pllink;

	priv->device_ip_link_changed_id = 0;

	if (!priv->ip_ifindex)
		return G_SOURCE_REMOVE;

	pllink = nm_platform_link_get (nm_device_get_platform (self), priv->ip_ifindex);
	if (!pllink)
		return G_SOURCE_REMOVE;

	if (priv->ifindex <= 0 && pllink->mtu)
		_set_mtu (self, pllink->mtu);

	_stats_update_counters_from_pllink (self, pllink);

	if (_ip_iface_update (self, pllink->name))
		nm_device_update_dynamic_ip_setup (self);

	return G_SOURCE_REMOVE;
}

static void
link_changed_cb (NMPlatform *platform,
                 int obj_type_i,
                 int ifindex,
                 NMPlatformLink *info,
                 int change_type_i,
                 NMDevice *self)
{
	const NMPlatformSignalChangeType change_type = change_type_i;
	NMDevicePrivate *priv;

	if (change_type != NM_PLATFORM_SIGNAL_CHANGED)
		return;

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (ifindex == nm_device_get_ifindex (self)) {
		if (!priv->device_link_changed_id) {
			priv->device_link_changed_id = g_idle_add ((GSourceFunc) device_link_changed, self);
			_LOGD (LOGD_DEVICE, "queued link change for ifindex %d", ifindex);
		}
	} else if (ifindex == nm_device_get_ip_ifindex (self)) {
		if (!priv->device_ip_link_changed_id) {
			priv->device_ip_link_changed_id = g_idle_add ((GSourceFunc) device_ip_link_changed, self);
			_LOGD (LOGD_DEVICE, "queued link change for ip-ifindex %d", ifindex);
		}
	}
}

/*****************************************************************************/

typedef struct {
	in_addr_t network;
	guint8 plen;
} IP4RPFilterData;

static guint
_v4_has_shadowed_routes_detect_hash (const IP4RPFilterData *d)
{
	NMHashState h;

	nm_hash_init (&h, 1105201169u);
	nm_hash_update_vals (&h,
	                     d->network,
	                     d->plen);
	return nm_hash_complete (&h);
}

static gboolean
_v4_has_shadowed_routes_detect_equal (const IP4RPFilterData *d1, const IP4RPFilterData *d2)
{
	return d1->network == d2->network && d1->plen == d2->plen;
}

static gboolean
_v4_has_shadowed_routes_detect (NMDevice *self)
{
	NMPlatform *platform;
	int ifindex;
	NMPLookup lookup;
	const NMDedupMultiHeadEntry *head_entry;
	NMDedupMultiIter iter;
	const NMPObject *o;
	guint data_len;
	gs_unref_hashtable GHashTable *data_hash = NULL;
	gs_free IP4RPFilterData *data_arr = NULL;

	ifindex = nm_device_get_ip_ifindex (self);
	if (ifindex <= 0)
		return FALSE;

	platform = nm_device_get_platform (self);

	head_entry = nm_platform_lookup (platform,
	                                 nmp_lookup_init_object (&lookup,
	                                                         NMP_OBJECT_TYPE_IP4_ROUTE,
	                                                         ifindex));
	if (!head_entry)
		return FALSE;

	/* first, create a lookup index @data_hash for all network/plen pairs. */
	data_len = 0;
	data_arr = g_new (IP4RPFilterData, head_entry->len);
	data_hash = g_hash_table_new ((GHashFunc) _v4_has_shadowed_routes_detect_hash,
	                              (GEqualFunc) _v4_has_shadowed_routes_detect_equal);

	nmp_cache_iter_for_each (&iter, head_entry, &o) {
		const NMPlatformIP4Route *r = NMP_OBJECT_CAST_IP4_ROUTE (o);
		IP4RPFilterData *d;

		nm_assert (r->ifindex == ifindex);

		if (   NM_PLATFORM_IP_ROUTE_IS_DEFAULT (r)
		    || r->table_coerced)
			continue;

		d = &data_arr[data_len++];
		d->network = nm_utils_ip4_address_clear_host_address (r->network, r->plen);
		d->plen = r->plen;
		g_hash_table_add (data_hash, d);
	}

	/* then, search if there is any route on another interface with the same
	 * network/plen destination. If yes, we consider this a multihoming
	 * setup. */
	head_entry = nm_platform_lookup (platform,
	                                 nmp_lookup_init_obj_type (&lookup,
	                                                           NMP_OBJECT_TYPE_IP4_ROUTE));
	nmp_cache_iter_for_each (&iter, head_entry, &o) {
		const NMPlatformIP4Route *r = NMP_OBJECT_CAST_IP4_ROUTE (o);
		IP4RPFilterData d;

		if (   r->ifindex == ifindex
		    || NM_PLATFORM_IP_ROUTE_IS_DEFAULT (r)
		    || r->table_coerced)
			continue;

		d.network = nm_utils_ip4_address_clear_host_address (r->network, r->plen);
		d.plen = r->plen;
		if (g_hash_table_contains (data_hash, &d))
			return TRUE;
	}

	return FALSE;
}

static void
ip4_rp_filter_update (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *ip4_rp_filter;

	if (   priv->v4_has_shadowed_routes
	    || nm_device_get_best_default_route (self, AF_INET)) {
		if (nm_device_ipv4_sysctl_get_uint32 (self, "rp_filter", 0) != 1) {
			/* Don't touch the rp_filter if it's not strict. */
			return;
		}
		/* Loose rp_filter */
		ip4_rp_filter = "2";
	} else {
		/* Default rp_filter */
		ip4_rp_filter = NULL;
	}

	if (ip4_rp_filter != priv->ip4_rp_filter) {
		nm_device_ipv4_sysctl_set (self, "rp_filter", ip4_rp_filter);
		priv->ip4_rp_filter = ip4_rp_filter;
	}
}

static void
link_changed (NMDevice *self, const NMPlatformLink *pllink)
{
	/* stub implementation of virtual function to allow subclasses to chain up. */
}

static gboolean
link_type_compatible (NMDevice *self,
                      NMLinkType link_type,
                      gboolean *out_compatible,
                      GError **error)
{
	NMDeviceClass *klass;
	NMLinkType device_type;
	guint i = 0;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	klass = NM_DEVICE_GET_CLASS (self);

	if (!klass->link_types) {
		NM_SET_OUT (out_compatible, FALSE);
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "Device does not support platform links");
		return FALSE;
	}

	device_type = self->_priv->link_type;
	if (device_type > NM_LINK_TYPE_UNKNOWN && device_type != link_type) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		             "Needed link type 0x%x does not match the platform link type 0x%X",
		             device_type, link_type);
		return FALSE;
	}

	for (i = 0; klass->link_types[i] > NM_LINK_TYPE_UNKNOWN; i++) {
		if (klass->link_types[i] == link_type)
			return TRUE;
		if (klass->link_types[i] == NM_LINK_TYPE_ANY)
			return TRUE;
	}

	NM_SET_OUT (out_compatible, FALSE);
	g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
	             "Device does not support platform link type 0x%X",
	             link_type);
	return FALSE;
}

/**
 * nm_device_realize_start():
 * @self: the #NMDevice
 * @plink: an existing platform link or %NULL
 * @assume_state_guess_assume: set the guess_assume state.
 * @assume_state_connection_uuid: set the connection uuid to assume.
 * @set_nm_owned: for software device, if TRUE set nm-owned.
 * @unmanaged_user_explicit: the user-explicit unmanaged flag to apply
 *   on the device initially.
 * @out_compatible: %TRUE on return if @self is compatible with @plink
 * @error: location to store error, or %NULL
 *
 * Initializes and sets up the device using existing backing resources. Before
 * the device is ready for use nm_device_realize_finish() must be called.
 * @out_compatible will only be set if @plink is not %NULL, and
 *
 * Important: if nm_device_realize_start() returns %TRUE, the caller MUST
 * also call nm_device_realize_finish() to balance g_object_freeze_notify().
 *
 * Returns: %TRUE on success, %FALSE on error
 */
gboolean
nm_device_realize_start (NMDevice *self,
                         const NMPlatformLink *plink,
                         gboolean assume_state_guess_assume,
                         const char *assume_state_connection_uuid,
                         gboolean set_nm_owned,
                         NMUnmanFlagOp unmanaged_user_explicit,
                         gboolean *out_compatible,
                         GError **error)
{
	nm_auto_nmpobj const NMPObject *plink_keep_alive = NULL;

	nm_assert (!plink || NMP_OBJECT_GET_TYPE (NMP_OBJECT_UP_CAST (plink)) == NMP_OBJECT_TYPE_LINK);

	NM_SET_OUT (out_compatible, TRUE);

	if (plink) {
		if (g_strcmp0 (nm_device_get_iface (self), plink->name) != 0) {
			NM_SET_OUT (out_compatible, FALSE);
			g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
			                     "Device interface name does not match platform link");
			return FALSE;
		}

		if (!link_type_compatible (self, plink->type, out_compatible, error))
			return FALSE;

		plink_keep_alive = nmp_object_ref (NMP_OBJECT_UP_CAST (plink));
	}

	realize_start_setup (self,
	                     plink,
	                     assume_state_guess_assume,
	                     assume_state_connection_uuid,
	                     set_nm_owned,
	                     unmanaged_user_explicit);
	return TRUE;
}

/**
 * nm_device_create_and_realize():
 * @self: the #NMDevice
 * @connection: the #NMConnection being activated
 * @parent: the parent #NMDevice if any
 * @error: location to store error, or %NULL
 *
 * Creates any backing resources needed to realize the device to proceed
 * with activating @connection.
 *
 * Returns: %TRUE on success, %FALSE on error
 */
gboolean
nm_device_create_and_realize (NMDevice *self,
                              NMConnection *connection,
                              NMDevice *parent,
                              GError **error)
{
	nm_auto_nmpobj const NMPObject *plink_keep_alive = NULL;
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const NMPlatformLink *plink = NULL;

	/* Must be set before device is realized */
	priv->nm_owned = !nm_platform_link_get_by_ifname (nm_device_get_platform (self), priv->iface);

	_LOGD (LOGD_DEVICE, "create (is %snm-owned)", priv->nm_owned ? "" : "not ");

	/* Create any resources the device needs */
	if (NM_DEVICE_GET_CLASS (self)->create_and_realize) {
		if (!NM_DEVICE_GET_CLASS (self)->create_and_realize (self, connection, parent, &plink, error))
			return FALSE;
		if (plink) {
			nm_assert (NMP_OBJECT_GET_TYPE (NMP_OBJECT_UP_CAST (plink)) == NMP_OBJECT_TYPE_LINK);
			plink_keep_alive = nmp_object_ref (NMP_OBJECT_UP_CAST (plink));
		}
	}

	realize_start_setup (self,
	                     plink,
	                     FALSE, /* assume_state_guess_assume */
	                     NULL,  /* assume_state_connection_uuid */
	                     FALSE, NM_UNMAN_FLAG_OP_FORGET);
	nm_device_realize_finish (self, plink);

	if (nm_device_get_managed (self, FALSE)) {
		nm_device_state_changed (self,
		                         NM_DEVICE_STATE_UNAVAILABLE,
		                         NM_DEVICE_STATE_REASON_NOW_MANAGED);
	}
	return TRUE;
}

void
nm_device_update_from_platform_link (NMDevice *self, const NMPlatformLink *plink)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *str;
	int ifindex;
	guint32 mtu;

	g_return_if_fail (plink == NULL || link_type_compatible (self, plink->type, NULL, NULL));

	str = plink ? nm_platform_link_get_udi (nm_device_get_platform (self), plink->ifindex) : NULL;
	if (g_strcmp0 (str, priv->udi)) {
		g_free (priv->udi);
		priv->udi = g_strdup (str);
		_notify (self, PROP_UDI);
	}

	str = plink ? plink->name : NULL;
	if (str && g_strcmp0 (str, priv->iface)) {
		g_free (priv->iface);
		priv->iface = g_strdup (str);
		_notify (self, PROP_IFACE);
	}

	str = plink ? plink->driver : NULL;
	if (g_strcmp0 (str, priv->driver) != 0) {
		g_free (priv->driver);
		priv->driver = g_strdup (str);
		_notify (self, PROP_DRIVER);
	}

	if (plink) {
		priv->up = NM_FLAGS_HAS (plink->n_ifi_flags, IFF_UP);
		if (plink->ifindex == nm_device_get_ip_ifindex (self))
			_stats_update_counters_from_pllink (self, plink);
	} else {
		priv->up = FALSE;
	}

	mtu = plink ? plink->mtu : 0;
	_set_mtu (self, mtu);

	ifindex = plink ? plink->ifindex : 0;
	if (priv->ifindex != ifindex) {
		priv->ifindex = ifindex;
		_notify (self, PROP_IFINDEX);
		NM_DEVICE_GET_CLASS (self)->link_changed (self, plink);
	}
}

static void
device_init_sriov_num_vfs (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gs_free char *value = NULL;
	int num_vfs;

	if (   priv->ifindex > 0
	    && nm_device_has_capability (self, NM_DEVICE_CAP_SRIOV)) {
		value = nm_config_data_get_device_config (NM_CONFIG_GET_DATA,
		                                          NM_CONFIG_KEYFILE_KEY_DEVICE_SRIOV_NUM_VFS,
		                                          self,
		                                          NULL);
		num_vfs = _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXINT32, -1);
		if (num_vfs >= 0) {
			nm_platform_link_set_sriov_num_vfs (nm_device_get_platform (self),
			                                    priv->ifindex, num_vfs);
		}
	}
}

static void
config_changed (NMConfig *config,
                NMConfigData *config_data,
                NMConfigChangeFlags changes,
                NMConfigData *old_data,
                NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (   priv->state <= NM_DEVICE_STATE_DISCONNECTED
	    || priv->state > NM_DEVICE_STATE_ACTIVATED)
		priv->ignore_carrier = nm_config_data_get_ignore_carrier (config_data, self);

	if (NM_FLAGS_HAS (changes, NM_CONFIG_CHANGE_VALUES))
		device_init_sriov_num_vfs (self);
}

static void
realize_start_notify (NMDevice *self,
                      const NMPlatformLink *pllink)
{
	/* the default implementation of realize_start_notify() just calls
	 * link_changed() -- which by default does nothing. */
	NM_DEVICE_GET_CLASS (self)->link_changed (self, pllink);
}

/**
 * realize_start_setup():
 * @self: the #NMDevice
 * @plink: the #NMPlatformLink if backed by a kernel netdevice
 * @assume_state_guess_assume: set the guess_assume state.
 * @assume_state_connection_uuid: set the connection uuid to assume.
 * @set_nm_owned: if TRUE and device is a software-device, set nm-owned.
 *    TRUE.
 * @unmanaged_user_explicit: the user-explict unmanaged flag to set.
 *
 * Update the device from backing resource properties (like hardware
 * addresses, carrier states, driver/firmware info, etc).  This function
 * should only change properties for this device, and should not perform
 * any tasks that affect other interfaces (like master/slave or parent/child
 * stuff).
 */
static void
realize_start_setup (NMDevice *self,
                     const NMPlatformLink *plink,
                     gboolean assume_state_guess_assume,
                     const char *assume_state_connection_uuid,
                     gboolean set_nm_owned,
                     NMUnmanFlagOp unmanaged_user_explicit)
{
	NMDevicePrivate *priv;
	NMDeviceClass *klass;
	static guint32 id = 0;
	NMDeviceCapabilities capabilities = 0;
	NMConfig *config;
	guint real_rate;

	/* plink is a NMPlatformLink type, however, we require it to come from the platform
	 * cache (where else would it come from?). */
	nm_assert (!plink || NMP_OBJECT_GET_TYPE (NMP_OBJECT_UP_CAST (plink)) == NMP_OBJECT_TYPE_LINK);

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);

	/* The device should not be realized */
	g_return_if_fail (!priv->real);
	g_return_if_fail (nm_device_get_unmanaged_flags (self, NM_UNMANAGED_PLATFORM_INIT));
	g_return_if_fail (priv->ip_ifindex <= 0);
	g_return_if_fail (priv->ip_iface == NULL);
	g_return_if_fail (!priv->queued_ip4_config_id);
	g_return_if_fail (!priv->queued_ip6_config_id);

	_LOGD (LOGD_DEVICE, "start setup of %s, kernel ifindex %d", G_OBJECT_TYPE_NAME (self), plink ? plink->ifindex : 0);

	klass = NM_DEVICE_GET_CLASS (self);

	/* Balanced by a thaw in nm_device_realize_finish() */
	g_object_freeze_notify (G_OBJECT (self));

	priv->mtu_initialized = FALSE;
	priv->mtu_initial = 0;
	priv->ip6_mtu_initial = 0;
	priv->ip6_mtu = 0;
	_set_mtu (self, 0);

	_assume_state_set (self, assume_state_guess_assume, assume_state_connection_uuid);

	nm_device_sys_iface_state_set (self, NM_DEVICE_SYS_IFACE_STATE_EXTERNAL);

	if (plink)
		nm_device_update_from_platform_link (self, plink);

	if (priv->ifindex > 0) {
		priv->physical_port_id = nm_platform_link_get_physical_port_id (nm_device_get_platform (self), priv->ifindex);
		_notify (self, PROP_PHYSICAL_PORT_ID);

		priv->dev_id = nm_platform_link_get_dev_id (nm_device_get_platform (self), priv->ifindex);

		if (nm_platform_link_is_software (nm_device_get_platform (self), priv->ifindex))
			capabilities |= NM_DEVICE_CAP_IS_SOFTWARE;

		_set_mtu (self,
		          nm_platform_link_get_mtu (nm_device_get_platform (self),
		                                    priv->ifindex));

		nm_platform_link_get_driver_info (nm_device_get_platform (self),
		                                  priv->ifindex,
		                                  NULL,
		                                  &priv->driver_version,
		                                  &priv->firmware_version);
		if (priv->driver_version)
			_notify (self, PROP_DRIVER_VERSION);
		if (priv->firmware_version)
			_notify (self, PROP_FIRMWARE_VERSION);

		if (nm_platform_check_kernel_support (nm_device_get_platform (self),
		                                      NM_PLATFORM_KERNEL_SUPPORT_USER_IPV6LL))
			priv->nm_ipv6ll = nm_platform_link_get_user_ipv6ll_enabled (nm_device_get_platform (self), priv->ifindex);

		if (nm_platform_link_supports_sriov (nm_device_get_platform (self), priv->ifindex))
			capabilities |= NM_DEVICE_CAP_SRIOV;
	}

	if (klass->get_generic_capabilities)
		capabilities |= klass->get_generic_capabilities (self);

	_add_capabilities (self, capabilities);

	if (   !priv->nm_owned
	    && set_nm_owned
	    && nm_device_is_software (self)) {
		priv->nm_owned = TRUE;
		_LOGD (LOGD_DEVICE, "set nm-owned from state file");
	}

	if (!priv->udi) {
		/* Use a placeholder UDI until we get a real one */
		priv->udi = g_strdup_printf ("/virtual/device/placeholder/%d", id++);
		_notify (self, PROP_UDI);
	}

	priv->queued_ip4_config_pending = TRUE;
	priv->queued_ip6_config_pending = TRUE;

	nm_device_update_hw_address (self);
	nm_device_update_initial_hw_address (self);
	nm_device_update_permanent_hw_address (self, FALSE);

	/* Note: initial hardware address must be read before calling get_ignore_carrier() */
	config = nm_config_get ();
	priv->ignore_carrier = nm_config_data_get_ignore_carrier (nm_config_get_data (config), self);
	if (!priv->config_changed_id) {
		priv->config_changed_id = g_signal_connect (config,
		                                            NM_CONFIG_SIGNAL_CONFIG_CHANGED,
		                                            G_CALLBACK (config_changed),
		                                            self);
	}

	nm_device_set_carrier_from_platform (self);

	device_init_sriov_num_vfs (self);

	nm_assert (!priv->stats.timeout_id);
	real_rate = _stats_refresh_rate_real (priv->stats.refresh_rate_ms);
	if (real_rate)
		priv->stats.timeout_id = g_timeout_add (real_rate, _stats_timeout_cb, self);

	klass->realize_start_notify (self, plink);

	nm_assert (!nm_device_get_unmanaged_mask (self, NM_UNMANAGED_USER_EXPLICIT));
	nm_device_set_unmanaged_flags (self,
	                               NM_UNMANAGED_USER_EXPLICIT,
	                               unmanaged_user_explicit);

	/* Do not manage externally created software devices until they are IFF_UP
	 * or have IP addressing */
	nm_device_set_unmanaged_flags (self,
	                               NM_UNMANAGED_EXTERNAL_DOWN,
	                               is_unmanaged_external_down (self, TRUE));

	/* Unmanaged the loopback device with an explicit NM_UNMANAGED_LOOPBACK flag.
	 * Later we might want to manage 'lo' too. Currently that doesn't work because
	 * NetworkManager might down the interface or remove the 127.0.0.1 address. */
	nm_device_set_unmanaged_flags (self, NM_UNMANAGED_LOOPBACK, priv->ifindex == 1);

	nm_device_set_unmanaged_by_user_udev (self);
	nm_device_set_unmanaged_by_user_conf (self);

	nm_device_set_unmanaged_flags (self, NM_UNMANAGED_PLATFORM_INIT,
	                               plink && !plink->initialized);
}

/**
 * nm_device_realize_finish():
 * @self: the #NMDevice
 * @plink: the #NMPlatformLink if backed by a kernel netdevice
 *
 * Update the device's master/slave or parent/child relationships from
 * backing resource properties.  After this function finishes, the device
 * is ready for network connectivity.
 */
void
nm_device_realize_finish (NMDevice *self, const NMPlatformLink *plink)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));
	g_return_if_fail (!plink || link_type_compatible (self, plink->type, NULL, NULL));

	priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_if_fail (!priv->real);

	if (plink)
		device_recheck_slave_status (self, plink);

	priv->real = TRUE;
	_notify (self, PROP_REAL);

	nm_device_recheck_available_connections (self);

	/* Balanced by a freeze in realize_start_setup(). */
	g_object_thaw_notify (G_OBJECT (self));
}

static void
unrealize_notify (NMDevice *self)
{
	/* Stub implementation for unrealize_notify(). It does nothing,
	 * but allows derived classes to uniformly invoke the parent
	 * implementation. */
}

static gboolean
available_connections_check_delete_unrealized_on_idle (gpointer user_data)
{
	NMDevice *self = user_data;
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), G_SOURCE_REMOVE);

	priv = NM_DEVICE_GET_PRIVATE (self);

	priv->check_delete_unrealized_id = 0;

	if (   g_hash_table_size (priv->available_connections) == 0
	    && !nm_device_is_real (self))
		g_signal_emit (self, signals[REMOVED], 0);

	return G_SOURCE_REMOVE;
}

static void
available_connections_check_delete_unrealized (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	/* always rescheadule the remove signal. */
	nm_clear_g_source (&priv->check_delete_unrealized_id);

	if (   g_hash_table_size (priv->available_connections) == 0
	    && !nm_device_is_real (self))
		priv->check_delete_unrealized_id = g_idle_add (available_connections_check_delete_unrealized_on_idle, self);
}

/**
 * nm_device_unrealize():
 * @self: the #NMDevice
 * @remove_resources: if %TRUE, remove backing resources
 * @error: location to store error, or %NULL
 *
 * Clears any properties that depend on backing resources (kernel devices,
 * etc) and removes those resources if @remove_resources is %TRUE.
 *
 * Returns: %TRUE on success, %FALSE on error
 */
gboolean
nm_device_unrealize (NMDevice *self, gboolean remove_resources, GError **error)
{
	NMDevicePrivate *priv;
	int ifindex;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (!nm_device_is_software (self) || !nm_device_is_real (self)) {
		g_set_error_literal (error,
		                     NM_DEVICE_ERROR,
		                     NM_DEVICE_ERROR_NOT_SOFTWARE,
		                     "This device is not a software device or is not realized");
		return FALSE;
	}

	priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_val_if_fail (priv->iface != NULL, FALSE);
	g_return_val_if_fail (priv->real, FALSE);


	ifindex = nm_device_get_ifindex (self);

	_LOGD (LOGD_DEVICE, "unrealize (ifindex %d)", ifindex > 0 ? ifindex : 0);

	nm_device_assume_state_reset (self);

	if (remove_resources) {
		if (NM_DEVICE_GET_CLASS (self)->unrealize) {
			if (!NM_DEVICE_GET_CLASS (self)->unrealize (self, error))
				return FALSE;
		} else if (ifindex > 0) {
			nm_platform_link_delete (nm_device_get_platform (self), ifindex);
		}
	}

	g_object_freeze_notify (G_OBJECT (self));
	NM_DEVICE_GET_CLASS (self)->unrealize_notify (self);

	_parent_set_ifindex (self, 0, FALSE);

	if (priv->ifindex > 0) {
		priv->ifindex = 0;
		_notify (self, PROP_IFINDEX);
	}
	priv->ip_ifindex = 0;
	if (nm_clear_g_free (&priv->ip_iface))
		_notify (self, PROP_IP_IFACE);

	_set_mtu (self, 0);

	if (priv->driver_version) {
		g_clear_pointer (&priv->driver_version, g_free);
		_notify (self, PROP_DRIVER_VERSION);
	}
	if (priv->firmware_version) {
		g_clear_pointer (&priv->firmware_version, g_free);
		_notify (self, PROP_FIRMWARE_VERSION);
	}
	if (priv->udi) {
		g_clear_pointer (&priv->udi, g_free);
		_notify (self, PROP_UDI);
	}
	if (priv->physical_port_id) {
		g_clear_pointer (&priv->physical_port_id, g_free);
		_notify (self, PROP_PHYSICAL_PORT_ID);
	}

	nm_clear_g_source (&priv->stats.timeout_id);
	_stats_update_counters (self, 0, 0);

	priv->hw_addr_len_ = 0;
	if (nm_clear_g_free (&priv->hw_addr))
		_notify (self, PROP_HW_ADDRESS);
	priv->hw_addr_type = HW_ADDR_TYPE_UNSET;
	if (nm_clear_g_free (&priv->hw_addr_perm))
		_notify (self, PROP_PERM_HW_ADDRESS);
	g_clear_pointer (&priv->hw_addr_initial, g_free);

	priv->capabilities = NM_DEVICE_CAP_NM_SUPPORTED;
	if (NM_DEVICE_GET_CLASS (self)->get_generic_capabilities)
		priv->capabilities |= NM_DEVICE_GET_CLASS (self)->get_generic_capabilities (self);
	_notify (self, PROP_CAPABILITIES);

	nm_clear_g_signal_handler (nm_config_get (), &priv->config_changed_id);

	priv->real = FALSE;
	_notify (self, PROP_REAL);

	g_object_thaw_notify (G_OBJECT (self));

	nm_device_set_unmanaged_flags (self,
	                               NM_UNMANAGED_PLATFORM_INIT,
	                               TRUE);

	nm_device_set_unmanaged_flags (self,
	                               NM_UNMANAGED_PARENT |
	                               NM_UNMANAGED_LOOPBACK |
	                               NM_UNMANAGED_USER_UDEV |
	                               NM_UNMANAGED_USER_EXPLICIT |
	                               NM_UNMANAGED_EXTERNAL_DOWN |
	                               NM_UNMANAGED_IS_SLAVE,
	                               NM_UNMAN_FLAG_OP_FORGET);

	nm_device_state_changed (self,
	                         NM_DEVICE_STATE_UNMANAGED,
	                         remove_resources ?
	                             NM_DEVICE_STATE_REASON_USER_REQUESTED : NM_DEVICE_STATE_REASON_NOW_UNMANAGED);

	/* Garbage-collect unneeded unrealized devices. */
	nm_device_recheck_available_connections (self);

	return TRUE;
}

/**
 * nm_device_notify_component_added():
 * @self: the #NMDevice
 * @component: the component being added by a plugin
 *
 * Called by the manager to notify the device that a new component has
 * been found.  The device implementation should return %TRUE if it
 * wishes to claim the component, or %FALSE if it cannot.
 *
 * Returns: %TRUE to claim the component, %FALSE if the component cannot be
 * claimed.
 */
gboolean
nm_device_notify_component_added (NMDevice *self, GObject *component)
{
	NMDeviceClass *klass;
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	klass = NM_DEVICE_GET_CLASS (self);

	if (priv->state == NM_DEVICE_STATE_DISCONNECTED) {
		/* A device could have stayed disconnected because it would
		 * want to register with a network server that now become
		 * available. */
		nm_device_recheck_available_connections (self);
		if (g_hash_table_size (priv->available_connections) > 0)
			nm_device_emit_recheck_auto_activate (self);
	}

	if (klass->component_added)
		return klass->component_added (self, component);

	return FALSE;
}

/**
 * nm_device_owns_iface():
 * @self: the #NMDevice
 * @iface: an interface name
 *
 * Called by the manager to ask if the device or any of its components owns
 * @iface.  For example, a WWAN implementation would return %TRUE for an
 * ethernet interface name that was owned by the WWAN device's modem component,
 * because that ethernet interface is controlled by the WWAN device and cannot
 * be used independently of the WWAN device.
 *
 * Returns: %TRUE if @self or it's components owns the interface name,
 * %FALSE if not
 */
gboolean
nm_device_owns_iface (NMDevice *self, const char *iface)
{
	if (NM_DEVICE_GET_CLASS (self)->owns_iface)
		return NM_DEVICE_GET_CLASS (self)->owns_iface (self, iface);
	return FALSE;
}

NMConnection *
nm_device_new_default_connection (NMDevice *self)
{
	if (NM_DEVICE_GET_CLASS (self)->new_default_connection)
		return NM_DEVICE_GET_CLASS (self)->new_default_connection (self);
	return NULL;
}

static void
slave_state_changed (NMDevice *slave,
                     NMDeviceState slave_new_state,
                     NMDeviceState slave_old_state,
                     NMDeviceStateReason reason,
                     NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean release = FALSE;
	gboolean configure;

	_LOGD (LOGD_DEVICE, "slave %s state change %d (%s) -> %d (%s)",
	       nm_device_get_iface (slave),
	       slave_old_state,
	       nm_device_state_to_str (slave_old_state),
	       slave_new_state,
	       nm_device_state_to_str (slave_new_state));

	/* Don't try to enslave slaves until the master is ready */
	if (priv->state < NM_DEVICE_STATE_CONFIG)
		return;

	if (slave_new_state == NM_DEVICE_STATE_IP_CONFIG)
		nm_device_master_enslave_slave (self, slave, nm_device_get_applied_connection (slave));
	else if (slave_new_state > NM_DEVICE_STATE_ACTIVATED)
		release = TRUE;
	else if (   slave_new_state <= NM_DEVICE_STATE_DISCONNECTED
	         && slave_old_state > NM_DEVICE_STATE_DISCONNECTED) {
		/* Catch failures due to unavailable or unmanaged */
		release = TRUE;
	}

	if (release) {
		configure =    priv->sys_iface_state == NM_DEVICE_SYS_IFACE_STATE_MANAGED
		            && nm_device_sys_iface_state_get (slave) != NM_DEVICE_SYS_IFACE_STATE_EXTERNAL;

		nm_device_master_release_one_slave (self, slave,
		                                    configure,
		                                    reason);
		/* Bridge/bond/team interfaces are left up until manually deactivated */
		if (   c_list_is_empty (&priv->slaves)
		    && priv->state == NM_DEVICE_STATE_ACTIVATED)
			_LOGD (LOGD_DEVICE, "last slave removed; remaining activated");
	}
}

/**
 * nm_device_master_add_slave:
 * @self: the master device
 * @slave: the slave device to enslave
 * @configure: pass %TRUE if the slave should be configured by the master, or
 * %FALSE if it is already configured outside NetworkManager
 *
 * If @self is capable of enslaving other devices (ie it's a bridge, bond, team,
 * etc) then this function adds @slave to the slave list for later enslavement.
 *
 * Returns: %TRUE if the slave was enslaved. %FALSE means, the slave was already
 *   enslaved and nothing was done.
 */
static gboolean
nm_device_master_add_slave (NMDevice *self, NMDevice *slave, gboolean configure)
{
	NMDevicePrivate *priv;
	NMDevicePrivate *slave_priv;
	SlaveInfo *info;
	gboolean changed = FALSE;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (NM_IS_DEVICE (slave), FALSE);
	g_return_val_if_fail (NM_DEVICE_GET_CLASS (self)->enslave_slave != NULL, FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	slave_priv = NM_DEVICE_GET_PRIVATE (slave);

	info = find_slave_info (self, slave);

	_LOGT (LOGD_CORE, "master: add one slave %p/%s%s", slave, nm_device_get_iface (slave),
	       info ? " (already registered)" : "");

	if (configure)
		g_return_val_if_fail (nm_device_get_state (slave) >= NM_DEVICE_STATE_DISCONNECTED, FALSE);

	if (!info) {
		g_return_val_if_fail (!slave_priv->master, FALSE);
		g_return_val_if_fail (!slave_priv->is_enslaved, FALSE);

		info = g_slice_new0 (SlaveInfo);
		info->slave = g_object_ref (slave);
		info->configure = configure;
		info->watch_id = g_signal_connect (slave,
		                                   NM_DEVICE_STATE_CHANGED,
		                                   G_CALLBACK (slave_state_changed), self);
		c_list_link_tail (&priv->slaves, &info->lst_slave);
		slave_priv->master = g_object_ref (self);

		_active_connection_set_state_flags (self,
		                                    NM_ACTIVATION_STATE_FLAG_MASTER_HAS_SLAVES);

		/* no need to emit
		 *
		 *   _notify (slave, PROP_MASTER);
		 *
		 * because slave_priv->is_enslaved is not true, thus the value
		 * didn't change yet. */

		g_warn_if_fail (!NM_FLAGS_HAS (slave_priv->unmanaged_mask, NM_UNMANAGED_IS_SLAVE));
		nm_device_set_unmanaged_by_flags (slave, NM_UNMANAGED_IS_SLAVE, FALSE, NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
		changed = TRUE;
	} else
		g_return_val_if_fail (slave_priv->master == self, FALSE);

	nm_device_queue_recheck_assume (self);
	nm_device_queue_recheck_assume (slave);

	return changed;
}

/**
 * nm_device_master_check_slave_physical_port:
 * @self: the master device
 * @slave: a slave device
 * @log_domain: domain to log a warning in
 *
 * Checks if @self already has a slave with the same #NMDevice:physical-port-id
 * as @slave, and logs a warning if so.
 */
void
nm_device_master_check_slave_physical_port (NMDevice *self, NMDevice *slave,
                                            NMLogDomain log_domain)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *slave_physical_port_id, *existing_physical_port_id;
	SlaveInfo *info;
	CList *iter;

	slave_physical_port_id = nm_device_get_physical_port_id (slave);
	if (!slave_physical_port_id)
		return;

	c_list_for_each (iter, &priv->slaves) {
		info = c_list_entry (iter, SlaveInfo, lst_slave);
		if (info->slave == slave)
			continue;

		existing_physical_port_id = nm_device_get_physical_port_id (info->slave);
		if (!g_strcmp0 (slave_physical_port_id, existing_physical_port_id)) {
			_LOGW (log_domain, "slave %s shares a physical port with existing slave %s",
			       nm_device_get_ip_iface (slave),
			       nm_device_get_ip_iface (info->slave));
			/* Since this function will get called for every slave, we only have
			 * to warn about the first match we find; if there are other matches
			 * later in the list, we will have already warned about them matching
			 * @existing earlier.
			 */
			return;
		}
	}
}

/* release all slaves */
static void
nm_device_master_release_slaves (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceStateReason reason;
	gboolean configure = TRUE;
	CList *iter, *safe;

	/* Don't release the slaves if this connection doesn't belong to NM. */
	if (nm_device_sys_iface_state_is_external (self))
		return;

	reason = priv->state_reason;
	if (priv->state == NM_DEVICE_STATE_FAILED)
		reason = NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED;

	if (!nm_platform_link_get (nm_device_get_platform (self), priv->ifindex))
		configure = FALSE;

	c_list_for_each_safe (iter, safe, &priv->slaves) {
		SlaveInfo *info = c_list_entry (iter, SlaveInfo, lst_slave);

		nm_device_master_release_one_slave (self, info->slave, configure, reason);
	}
}

/**
 * nm_device_is_master:
 * @self: the device
 *
 * Returns: %TRUE if the device can have slaves
 */
gboolean
nm_device_is_master (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	return NM_DEVICE_GET_CLASS (self)->is_master;
}

/**
 * nm_device_get_master:
 * @self: the device
 *
 * If @self has been enslaved by another device, this returns that
 * device. Otherwise it returns %NULL. (In particular, note that if
 * @self is in the process of activating as a slave, but has not yet
 * been enslaved by its master, this will return %NULL.)
 *
 * Returns: (transfer none): @self's master, or %NULL
 */
NMDevice *
nm_device_get_master (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->is_enslaved) {
		g_return_val_if_fail (priv->master, NULL);
		return priv->master;
	}
	return NULL;
}

static gboolean
get_ip_config_may_fail (NMDevice *self, int addr_family)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip = NULL;

	connection = nm_device_get_applied_connection (self);

	/* Fail the connection if the failed IP method is required to complete */
	switch (addr_family) {
	case AF_INET:
		s_ip = nm_connection_get_setting_ip4_config (connection);
		break;
	case AF_INET6:
		s_ip = nm_connection_get_setting_ip6_config (connection);
		break;
	default:
		nm_assert_not_reached ();
	}

	return !s_ip || nm_setting_ip_config_get_may_fail (s_ip);
}

/*
 * check_ip_state
 *
 * When @full_state_update is TRUE, transition the device from IP_CONFIG to the
 * next state according to the outcome of IPv4 and IPv6 configuration. @may_fail
 * indicates that we are called just after the initial configuration and thus
 * IPv4/IPv6 are allowed to fail if the ipvx.may-fail properties say so, because
 * the IP methods couldn't even be started.
 * If @full_state_update is FALSE, just check if the connection should be failed
 * due to the state of both ip families and the ipvx.may-fail settings.
 */
static void
check_ip_state (NMDevice *self, gboolean may_fail, gboolean full_state_update)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean ip4_disabled = FALSE, ip6_ignore = FALSE;
	NMSettingIPConfig *s_ip4, *s_ip6;
	NMDeviceState state;

	if (   full_state_update
	    && nm_device_get_state (self) != NM_DEVICE_STATE_IP_CONFIG)
		return;

	/* Don't progress into IP_CHECK or SECONDARIES if we're waiting for the
	 * master to enslave us. */
	if (   nm_active_connection_get_master (NM_ACTIVE_CONNECTION (priv->act_request))
	    && !priv->is_enslaved)
		return;

	s_ip4 = (NMSettingIPConfig *) nm_device_get_applied_setting (self, NM_TYPE_SETTING_IP4_CONFIG);
	if (s_ip4 && nm_streq0 (nm_setting_ip_config_get_method (s_ip4),
	                        NM_SETTING_IP4_CONFIG_METHOD_DISABLED))
		ip4_disabled = TRUE;

	s_ip6 = (NMSettingIPConfig *) nm_device_get_applied_setting (self, NM_TYPE_SETTING_IP6_CONFIG);
	if (s_ip6 && nm_streq0 (nm_setting_ip_config_get_method (s_ip6),
	                        NM_SETTING_IP6_CONFIG_METHOD_IGNORE))
		ip6_ignore = TRUE;

	if (   priv->ip4_state == IP_DONE
	    && priv->ip6_state == IP_DONE) {
		/* Both method completed (or disabled), proceed with activation */
		nm_device_state_changed (self, NM_DEVICE_STATE_IP_CHECK, NM_DEVICE_STATE_REASON_NONE);
		return;
	}

	if (   (priv->ip4_state == IP_FAIL || (ip4_disabled && priv->ip4_state == IP_DONE))
	    && (priv->ip6_state == IP_FAIL || (ip6_ignore && priv->ip6_state == IP_DONE))) {
		/* Either both methods failed, or only one failed and the other is
		 * disabled */
		if (nm_device_sys_iface_state_is_external_or_assume (self)) {
			/* We have assumed configuration, but couldn't redo it. No problem,
			 * move to check state. */
			_set_ip_state (self, AF_INET, IP_DONE);
			_set_ip_state (self, AF_INET6, IP_DONE);
			state = NM_DEVICE_STATE_IP_CHECK;
		} else if (   may_fail
		           && get_ip_config_may_fail (self, AF_INET)
		           && get_ip_config_may_fail (self, AF_INET6)) {
			/* Couldn't start either IPv6 and IPv4 autoconfiguration,
			 * but both are allowed to fail. */
			state = NM_DEVICE_STATE_SECONDARIES;
		} else {
			/* Autoconfiguration attempted without success. */
			state = NM_DEVICE_STATE_FAILED;
		}

		if (   full_state_update
		    || state == NM_DEVICE_STATE_FAILED) {
			nm_device_state_changed (self,
			                         state,
			                         NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
		}
		return;
	}

	/* If a method is still pending but required, wait */
	if (priv->ip4_state != IP_DONE && !get_ip_config_may_fail (self, AF_INET))
		return;
	if (priv->ip6_state != IP_DONE && !get_ip_config_may_fail (self, AF_INET6))
		return;

	/* If at least a method has completed, proceed with activation */
	if (   (priv->ip4_state == IP_DONE && !ip4_disabled)
	    || (priv->ip6_state == IP_DONE && !ip6_ignore)) {
		if (full_state_update)
			nm_device_state_changed (self, NM_DEVICE_STATE_IP_CHECK, NM_DEVICE_STATE_REASON_NONE);
		return;
	}
}

/**
 * nm_device_slave_notify_enslave:
 * @self: the slave device
 * @success: whether the enslaving operation succeeded
 *
 * Notifies a slave that either it has been enslaved, or else its master tried
 * to enslave it and failed.
 */
static void
nm_device_slave_notify_enslave (NMDevice *self, gboolean success)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection = nm_device_get_applied_connection (self);
	gboolean activating = (priv->state == NM_DEVICE_STATE_IP_CONFIG);

	g_return_if_fail (priv->master);

	if (!priv->is_enslaved) {
		if (success) {
			if (activating) {
				_LOGI (LOGD_DEVICE, "Activation: connection '%s' enslaved, continuing activation",
				       nm_connection_get_id (connection));
			} else
				_LOGI (LOGD_DEVICE, "enslaved to %s", nm_device_get_iface (priv->master));

			priv->is_enslaved = TRUE;

			_notify (self, PROP_MASTER);
			_notify (priv->master, PROP_SLAVES);
		} else if (activating) {
			_LOGW (LOGD_DEVICE, "Activation: connection '%s' could not be enslaved",
			       nm_connection_get_id (connection));
		}
	}

	if (activating) {
		if (success)
			check_ip_state (self, FALSE, TRUE);
		else
			nm_device_queue_state (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_UNKNOWN);
	} else
		nm_device_queue_recheck_assume (self);
}

/**
 * nm_device_slave_notify_release:
 * @self: the slave device
 * @reason: the reason associated with the state change
 *
 * Notifies a slave that it has been released, and why.
 */
static void
nm_device_slave_notify_release (NMDevice *self, NMDeviceStateReason reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection = nm_device_get_applied_connection (self);
	NMDeviceState new_state;
	const char *master_status;

	g_return_if_fail (priv->master);

	if (   priv->state > NM_DEVICE_STATE_DISCONNECTED
	    && priv->state <= NM_DEVICE_STATE_ACTIVATED) {
		switch (nm_device_state_reason_check (reason)) {
		case NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED:
			new_state = NM_DEVICE_STATE_FAILED;
			master_status = "failed";
			break;
		case NM_DEVICE_STATE_REASON_USER_REQUESTED:
			new_state = NM_DEVICE_STATE_DEACTIVATING;
			reason = NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED;
			master_status = "deactivated by user request";
			break;
		default:
			new_state = NM_DEVICE_STATE_DISCONNECTED;
			master_status = "deactivated";
			break;
		}

		_LOGD (LOGD_DEVICE, "Activation: connection '%s' master %s",
		       nm_connection_get_id (connection),
		       master_status);

		/* Cancel any pending activation sources */
		_cancel_activation (self);
		nm_device_queue_state (self, new_state, reason);
	} else
		_LOGI (LOGD_DEVICE, "released from master device %s", nm_device_get_iface (priv->master));

	if (priv->is_enslaved) {
		priv->is_enslaved = FALSE;
		_notify (self, PROP_MASTER);
		_notify (priv->master, PROP_SLAVES);
	}
}

/**
 * nm_device_removed:
 * @self: the #NMDevice
 * @unconfigure_ip_config: whether to clear the IP config objects
 *   of the device (provided, it is still not cleared at this point).
 *
 * Called by the manager when the device was removed. Releases the device from
 * the master in case it's enslaved.
 */
void
nm_device_removed (NMDevice *self, gboolean unconfigure_ip_config)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	if (priv->master) {
		/* this is called when something externally messes with the slave or during shut-down.
		 * Release the slave from master, but don't touch the device. */
		nm_device_master_release_one_slave (priv->master, self, FALSE, NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
	}

	if (!unconfigure_ip_config)
		return;

	nm_device_set_ip4_config (self, NULL, FALSE, NULL);
	nm_device_set_ip6_config (self, NULL, FALSE);
}

static gboolean
is_available (NMDevice *self, NMDeviceCheckDevAvailableFlags flags)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (   priv->carrier
	    || priv->ignore_carrier)
		return TRUE;

	if (NM_FLAGS_HAS (flags, _NM_DEVICE_CHECK_DEV_AVAILABLE_IGNORE_CARRIER))
		return TRUE;

	/* master types are always available even without carrier. */
	if (nm_device_is_master (self))
		return TRUE;

	return FALSE;
}

/**
 * nm_device_is_available:
 * @self: the #NMDevice
 * @flags: additional flags to influence the check. Flags have the
 *   meaning to increase the availability of a device.
 *
 * Checks if @self would currently be capable of activating a
 * connection. In particular, it checks that the device is ready (eg,
 * is not missing firmware), that it has carrier (if necessary), and
 * that any necessary external software (eg, ModemManager,
 * wpa_supplicant) is available.
 *
 * @self can only be in a state higher than
 * %NM_DEVICE_STATE_UNAVAILABLE when nm_device_is_available() returns
 * %TRUE. (But note that it can still be %NM_DEVICE_STATE_UNMANAGED
 * when it is available.)
 *
 * Returns: %TRUE or %FALSE
 */
gboolean
nm_device_is_available (NMDevice *self, NMDeviceCheckDevAvailableFlags flags)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->firmware_missing)
		return FALSE;

	return NM_DEVICE_GET_CLASS (self)->is_available (self, flags);
}

gboolean
nm_device_ignore_carrier_by_default (NMDevice *self)
{
	/* master types ignore-carrier by default. */
	return nm_device_is_master (self);
}

gboolean
nm_device_get_enabled (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (NM_DEVICE_GET_CLASS (self)->get_enabled)
		return NM_DEVICE_GET_CLASS (self)->get_enabled (self);
	return TRUE;
}

void
nm_device_set_enabled (NMDevice *self, gboolean enabled)
{
	g_return_if_fail (NM_IS_DEVICE (self));

	if (NM_DEVICE_GET_CLASS (self)->set_enabled)
		NM_DEVICE_GET_CLASS (self)->set_enabled (self, enabled);
}

NM_UTILS_FLAGS2STR_DEFINE_STATIC (_autoconnect_blocked_flags_to_string, NMDeviceAutoconnectBlockedFlags,
	NM_UTILS_FLAGS2STR (NM_DEVICE_AUTOCONNECT_BLOCKED_NONE,              "none"),
	NM_UTILS_FLAGS2STR (NM_DEVICE_AUTOCONNECT_BLOCKED_USER,              "user"),
	NM_UTILS_FLAGS2STR (NM_DEVICE_AUTOCONNECT_BLOCKED_WRONG_PIN,         "wrong-pin"),
	NM_UTILS_FLAGS2STR (NM_DEVICE_AUTOCONNECT_BLOCKED_MANUAL_DISCONNECT, "manual-disconnect"),
);

NMDeviceAutoconnectBlockedFlags
nm_device_autoconnect_blocked_get (NMDevice *self, NMDeviceAutoconnectBlockedFlags mask)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (mask == 0)
		mask = NM_DEVICE_AUTOCONNECT_BLOCKED_ALL;

	priv = NM_DEVICE_GET_PRIVATE (self);
	return priv->autoconnect_blocked_flags & mask;
}

void
nm_device_autoconnect_blocked_set_full (NMDevice *self, NMDeviceAutoconnectBlockedFlags mask, NMDeviceAutoconnectBlockedFlags value)
{
	NMDevicePrivate *priv;
	gboolean changed;
	char buf1[128], buf2[128];

	g_return_if_fail (NM_IS_DEVICE (self));
	nm_assert (mask);
	nm_assert (!NM_FLAGS_ANY (mask, ~NM_DEVICE_AUTOCONNECT_BLOCKED_ALL));
	nm_assert (!NM_FLAGS_ANY (value, ~mask));

	priv = NM_DEVICE_GET_PRIVATE (self);

	value = (priv->autoconnect_blocked_flags & ~mask) | (mask & value);
	if (value == priv->autoconnect_blocked_flags)
		return;

	changed = ((!value) != (!priv->autoconnect_blocked_flags));

	_LOGT (LOGD_DEVICE, "autoconnect-blocked: set \"%s\" (was \"%s\")",
	       _autoconnect_blocked_flags_to_string (value, buf1, sizeof (buf1)),
	       _autoconnect_blocked_flags_to_string (priv->autoconnect_blocked_flags, buf2, sizeof (buf2)));

	priv->autoconnect_blocked_flags = value;
	nm_assert (priv->autoconnect_blocked_flags == value);
	if (changed)
		_notify (self, PROP_AUTOCONNECT);
}

static gboolean
autoconnect_allowed_accumulator (GSignalInvocationHint *ihint,
                                 GValue *return_accu,
                                 const GValue *handler_return, gpointer data)
{
	if (!g_value_get_boolean (handler_return))
		g_value_set_boolean (return_accu, FALSE);
	return TRUE;
}

/**
 * nm_device_autoconnect_allowed:
 * @self: the #NMDevice
 *
 * Returns: %TRUE if the device can be auto-connected immediately, taking
 * transient conditions into account (like companion devices that may wish to
 * block autoconnect for a time).
 */
gboolean
nm_device_autoconnect_allowed (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceClass *klass = NM_DEVICE_GET_CLASS (self);
	GValue instance = G_VALUE_INIT;
	GValue retval = G_VALUE_INIT;

	if (nm_device_autoconnect_blocked_get (self, NM_DEVICE_AUTOCONNECT_BLOCKED_ALL))
		return FALSE;

	if (   klass->get_autoconnect_allowed
	    && !klass->get_autoconnect_allowed (self))
		return FALSE;

	if (!nm_device_get_enabled (self))
		return FALSE;

	if (nm_device_is_real (self)) {
		if (priv->state < NM_DEVICE_STATE_DISCONNECTED)
			return FALSE;
	} else {
		/* Unrealized devices can always autoconnect. */
	}

	/* The 'autoconnect-allowed' signal is emitted on a device to allow
	 * other listeners to block autoconnect on the device if they wish.
	 * This is mainly used by the OLPC Mesh devices to block autoconnect
	 * on their companion WiFi device as they share radio resources and
	 * cannot be connected at the same time.
	 */

	g_value_init (&instance, G_TYPE_OBJECT);
	g_value_set_object (&instance, self);

	g_value_init (&retval, G_TYPE_BOOLEAN);
	g_value_set_boolean (&retval, TRUE);

	/* Use g_signal_emitv() rather than g_signal_emit() to avoid the return
	 * value being changed if no handlers are connected */
	g_signal_emitv (&instance, signals[AUTOCONNECT_ALLOWED], 0, &retval);
	g_value_unset (&instance);

	return g_value_get_boolean (&retval);
}

static gboolean
can_auto_connect (NMDevice *self,
                  NMConnection *connection,
                  char **specific_object)
{
	nm_assert (!specific_object || !*specific_object);
	return TRUE;
}

/**
 * nm_device_can_auto_connect:
 * @self: an #NMDevice
 * @connection: a #NMConnection
 * @specific_object: (out) (transfer full): on output, the path of an
 *   object associated with the returned connection, to be passed to
 *   nm_manager_activate_connection(), or %NULL.
 *
 * Checks if @connection can be auto-activated on @self right now.
 * This requires, at a minimum, that the connection be compatible with
 * @self, and that it have the #NMSettingConnection:autoconnect property
 * set, and that the device allow auto connections. Some devices impose
 * additional requirements. (Eg, a Wi-Fi connection can only be activated
 * if its SSID was seen in the last scan.)
 *
 * Returns: %TRUE, if the @connection can be auto-activated.
 **/
gboolean
nm_device_can_auto_connect (NMDevice *self,
                            NMConnection *connection,
                            char **specific_object)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (!specific_object || !*specific_object, FALSE);

	/* the caller must ensure that nm_device_autoconnect_allowed() returns
	 * TRUE as well. This is done, because nm_device_can_auto_connect()
	 * has only one caller, and it iterates over a list of available
	 * connections.
	 *
	 * Hence, we don't need to re-check nm_device_autoconnect_allowed()
	 * over and over again. The caller is supposed to do that. */
	nm_assert (nm_device_autoconnect_allowed (self));

	if (!nm_device_check_connection_available (self, connection, NM_DEVICE_CHECK_CON_AVAILABLE_NONE, NULL))
		return FALSE;

	if (!NM_DEVICE_GET_CLASS (self)->can_auto_connect (self, connection, specific_object))
		return FALSE;

	return TRUE;
}

static gboolean
device_has_config (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	/* Check for IP configuration. */
	if (priv->ip4_config && nm_ip4_config_get_num_addresses (priv->ip4_config))
		return TRUE;
	if (priv->ip6_config && nm_ip6_config_get_num_addresses (priv->ip6_config))
		return TRUE;

	/* The existence of a software device is good enough. */
	if (nm_device_is_software (self) && nm_device_is_real (self))
		return TRUE;

	/* Master-slave relationship is also a configuration */
	if (   !c_list_is_empty (&priv->slaves)
	    || nm_platform_link_get_master (nm_device_get_platform (self), priv->ifindex) > 0)
		return TRUE;

	return FALSE;
}

/**
 * nm_device_master_update_slave_connection:
 * @self: the master #NMDevice
 * @slave: the slave #NMDevice
 * @connection: the #NMConnection to update with the slave settings
 * @GError: (out): error description
 *
 * Reads the slave configuration for @slave and updates @connection with those
 * properties. This invokes a virtual function on the master device @self.
 *
 * Returns: %TRUE if the configuration was read and @connection updated,
 * %FALSE on failure.
 */
gboolean
nm_device_master_update_slave_connection (NMDevice *self,
                                          NMDevice *slave,
                                          NMConnection *connection,
                                          GError **error)
{
	NMDeviceClass *klass;
	gboolean success;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (slave, FALSE);
	g_return_val_if_fail (connection, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);
	g_return_val_if_fail (nm_connection_get_setting_connection (connection), FALSE);

	g_return_val_if_fail (nm_device_get_iface (self), FALSE);

	klass = NM_DEVICE_GET_CLASS (self);
	if (klass->master_update_slave_connection) {
		success = klass->master_update_slave_connection (self, slave, connection, error);

		g_return_val_if_fail (!error || (success && !*error) || *error, success);
		return success;
	}

	g_set_error (error,
	             NM_DEVICE_ERROR,
	             NM_DEVICE_ERROR_FAILED,
	             "master device '%s' cannot update a slave connection for slave device '%s' (master type not supported?)",
	             nm_device_get_iface (self), nm_device_get_iface (slave));
	return FALSE;
}

NMConnection *
nm_device_generate_connection (NMDevice *self,
                               NMDevice *master,
                               gboolean *out_maybe_later,
                               GError **error)
{
	NMDeviceClass *klass = NM_DEVICE_GET_CLASS (self);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *ifname = nm_device_get_iface (self);
	gs_unref_object NMConnection *connection = NULL;
	NMSetting *s_con;
	NMSetting *s_ip4;
	NMSetting *s_ip6;
	char uuid[37];
	const char *ip4_method, *ip6_method;
	GError *local = NULL;
	const NMPlatformLink *pllink;

	NM_SET_OUT (out_maybe_later, FALSE);

	/* If update_connection() is not implemented, just fail. */
	if (!klass->update_connection) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		             "device class %s does not support generating a connection",
		             G_OBJECT_TYPE_NAME (self));
		return NULL;
	}

	/* Return NULL if device is unconfigured. */
	if (!device_has_config (self)) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		             "device has no existing configuration");
		return NULL;
	}

	connection = nm_simple_connection_new ();
	s_con = nm_setting_connection_new ();

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_buf (uuid),
	              NM_SETTING_CONNECTION_ID, ifname,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, ifname,
	              NM_SETTING_CONNECTION_TIMESTAMP, (guint64) time (NULL),
	              NULL);
	if (klass->connection_type)
		g_object_set (s_con, NM_SETTING_CONNECTION_TYPE, klass->connection_type, NULL);
	nm_connection_add_setting (connection, s_con);

	/* If the device is a slave, update various slave settings */
	if (master) {
		if (!nm_device_master_update_slave_connection (master,
		                                               self,
		                                               connection,
		                                               &local)) {
			g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
			             "master device '%s' failed to update slave connection: %s",
			             nm_device_get_iface (master), local->message);
			g_error_free (local);
			return NULL;
		}
	} else {
		/* Only regular and master devices get IP configuration; slaves do not */
		s_ip4 = nm_ip4_config_create_setting (priv->ip4_config);
		nm_connection_add_setting (connection, s_ip4);

		s_ip6 = nm_ip6_config_create_setting (priv->ip6_config);
		nm_connection_add_setting (connection, s_ip6);

		nm_connection_add_setting (connection, nm_setting_proxy_new ());

		pllink = nm_platform_link_get (nm_device_get_platform (self), priv->ifindex);
		if (pllink && pllink->inet6_token.id) {
			g_object_set (s_ip6,
			              NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE, NM_IN6_ADDR_GEN_MODE_EUI64,
			              NM_SETTING_IP6_CONFIG_TOKEN, nm_utils_inet6_interface_identifier_to_token (pllink->inet6_token, NULL),
			              NULL);
		}
	}

	klass->update_connection (self, connection);

	if (!nm_connection_verify (connection, &local)) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		             "generated connection does not verify: %s",
		             local->message);
		g_error_free (local);
		return NULL;
	}

	/* Ignore the connection if it has no IP configuration,
	 * no slave configuration, and is not a master interface.
	 */
	ip4_method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	ip6_method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
	if (   g_strcmp0 (ip4_method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0
	    && g_strcmp0 (ip6_method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) == 0
	    && !nm_setting_connection_get_master (NM_SETTING_CONNECTION (s_con))
	    && c_list_is_empty (&priv->slaves)) {
		NM_SET_OUT (out_maybe_later, TRUE);
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                     "ignoring generated connection (no IP and not in master-slave relationship)");
		return NULL;
	}

	/* Ignore any IPv6LL-only, not master connections without slaves,
	 * unless they are in the assume-ipv6ll-only list.
	 */
	if (   g_strcmp0 (ip4_method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0
	    && g_strcmp0 (ip6_method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0
	    && !nm_setting_connection_get_master (NM_SETTING_CONNECTION (s_con))
	    && c_list_is_empty (&priv->slaves)
	    && !nm_config_data_get_assume_ipv6ll_only (NM_CONFIG_GET_DATA, self)) {
		_LOGD (LOGD_DEVICE, "ignoring generated connection (IPv6LL-only and not in master-slave relationship)");
		NM_SET_OUT (out_maybe_later, TRUE);
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED,
		                    "ignoring generated connection (IPv6LL-only and not in master-slave relationship)");
		return NULL;
	}

	return g_steal_pointer (&connection);
}

gboolean
nm_device_complete_connection (NMDevice *self,
                               NMConnection *connection,
                               const char *specific_object,
                               const GSList *existing_connections,
                               GError **error)
{
	gboolean success = FALSE;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (connection != NULL, FALSE);

	if (!NM_DEVICE_GET_CLASS (self)->complete_connection) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		             "Device class %s had no complete_connection method",
		             G_OBJECT_TYPE_NAME (self));
		return FALSE;
	}

	success = NM_DEVICE_GET_CLASS (self)->complete_connection (self,
	                                                           connection,
	                                                           specific_object,
	                                                           existing_connections,
	                                                           error);
	if (success)
		success = nm_connection_verify (connection, error);

	return success;
}

gboolean
nm_device_match_parent (NMDevice *self, const char *parent)
{
	NMDevice *parent_device;

	g_return_val_if_fail (parent, FALSE);

	parent_device = nm_device_parent_get_device (self);
	if (!parent_device)
		return FALSE;

	if (nm_utils_is_uuid (parent)) {
		NMConnection *connection;

		/* If the parent is a UUID, the connection matches when there is
		 * no connection active on the device or when a connection with
		 * that UUID is active.
		 */
		connection = nm_device_get_applied_connection (self);
		if (!connection)
			return TRUE;

		if (!nm_streq0 (parent, nm_connection_get_uuid (connection)))
			return FALSE;
	} else {
		/* Interface name */
		if (!nm_streq0 (parent, nm_device_get_ip_iface (parent_device)))
			return FALSE;
	}

	return TRUE;
}

gboolean
nm_device_match_hwaddr (NMDevice *device,
                        NMConnection *connection,
                        gboolean fail_if_no_hwaddr)
{
	NMSettingWired *s_wired;
	NMDevice *parent_device;
	const char *setting_mac;
	const char *parent_mac;

	s_wired = nm_connection_get_setting_wired (connection);
	if (!s_wired)
		return !fail_if_no_hwaddr;

	setting_mac = nm_setting_wired_get_mac_address (s_wired);
	if (!setting_mac)
		return !fail_if_no_hwaddr;

	parent_device = nm_device_parent_get_device (device);
	if (!parent_device)
		return !fail_if_no_hwaddr;

	parent_mac = nm_device_get_permanent_hw_address (parent_device);
	return parent_mac && nm_utils_hwaddr_matches (setting_mac, -1, parent_mac, -1);
}

static gboolean
check_connection_compatible (NMDevice *self, NMConnection *connection)
{
	const char *device_iface = nm_device_get_iface (self);
	gs_free char *conn_iface = nm_manager_get_connection_iface (nm_manager_get (),
	                                                            connection,
	                                                            NULL, NULL);

	/* We always need a interface name for virtual devices, but for
	 * physical ones a connection without interface name is fine for
	 * any device. */
	if (!conn_iface)
		return !nm_connection_is_virtual (connection);

	if (strcmp (conn_iface, device_iface) != 0)
		return FALSE;

	return TRUE;
}

/**
 * nm_device_check_connection_compatible:
 * @self: an #NMDevice
 * @connection: an #NMConnection
 *
 * Checks if @connection could potentially be activated on @self.
 * This means only that @self has the proper capabilities, and that
 * @connection is not locked to some other device. It does not
 * necessarily mean that @connection could be activated on @self
 * right now. (Eg, it might refer to a Wi-Fi network that is not
 * currently available.)
 *
 * Returns: #TRUE if @connection could potentially be activated on
 *   @self.
 */
gboolean
nm_device_check_connection_compatible (NMDevice *self, NMConnection *connection)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	return NM_DEVICE_GET_CLASS (self)->check_connection_compatible (self, connection);
}

gboolean
nm_device_check_slave_connection_compatible (NMDevice *self, NMConnection *slave)
{
	NMSettingConnection *s_con;
	const char *connection_type, *slave_type;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (slave), FALSE);

	if (!nm_device_is_master (self))
		return FALSE;

	/* All masters should have connection type set */
	connection_type = NM_DEVICE_GET_CLASS (self)->connection_type;
	g_return_val_if_fail (connection_type, FALSE);

	s_con = nm_connection_get_setting_connection (slave);
	g_assert (s_con);
	slave_type = nm_setting_connection_get_slave_type (s_con);
	if (!slave_type)
		return FALSE;

	return strcmp (connection_type, slave_type) == 0;
}

/**
 * nm_device_can_assume_connections:
 * @self: #NMDevice instance
 *
 * This is a convenience function to determine whether connection assumption
 * is available for this device.
 *
 * Returns: %TRUE if the device is capable of assuming connections, %FALSE if not
 */
static gboolean
nm_device_can_assume_connections (NMDevice *self)
{
	return !!NM_DEVICE_GET_CLASS (self)->update_connection;
}

static gboolean
unmanaged_on_quit (NMDevice *self)
{
	NMConnection *connection;

	/* NMDeviceWifi overwrites this function to always unmanage wifi devices.
	 *
	 * For all other types, if the device type can assume connections, we leave
	 * it up on quit.
	 *
	 * Originally, we would only keep devices up that can be assumed afterwards.
	 * However, that meant we unmanged layer-2 only devices. So, this was step
	 * by step refined to unmanage less (commit 25aaaab3, rh#1311988, rh#1333983).
	 * But there are more scenarios where we also want to keep the device up
	 * (rh#1378418, rh#1371126). */
	if (!nm_device_can_assume_connections (self))
		return TRUE;

	/* the only exception are IPv4 shared connections. We unmanage them on quit. */
	connection = nm_device_get_applied_connection (self);
	if (connection) {
		if (NM_IN_STRSET (nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG),
		                  NM_SETTING_IP4_CONFIG_METHOD_SHARED)) {
			/* shared connections are to be unmangaed. */
			return TRUE;
		}
	}

	return FALSE;
}

gboolean
nm_device_unmanage_on_quit (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	return NM_DEVICE_GET_CLASS (self)->unmanaged_on_quit (self);
}

static gboolean
nm_device_emit_recheck_assume (gpointer user_data)
{
	NMDevice *self = user_data;
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), G_SOURCE_REMOVE);

	priv = NM_DEVICE_GET_PRIVATE (self);

	priv->recheck_assume_id = 0;
	if (!nm_device_get_act_request (self))
		g_signal_emit (self, signals[RECHECK_ASSUME], 0);

	return G_SOURCE_REMOVE;
}

void
nm_device_queue_recheck_assume (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (   !priv->recheck_assume_id
	    && nm_device_can_assume_connections (self))
		priv->recheck_assume_id = g_idle_add (nm_device_emit_recheck_assume, self);
}

static gboolean
recheck_available (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean now_available;
	NMDeviceState state = nm_device_get_state (self);
	NMDeviceState new_state = NM_DEVICE_STATE_UNKNOWN;

	priv->recheck_available.call_id = 0;

	now_available = nm_device_is_available (self, NM_DEVICE_CHECK_DEV_AVAILABLE_NONE);

	if (state == NM_DEVICE_STATE_UNAVAILABLE && now_available) {
		new_state = NM_DEVICE_STATE_DISCONNECTED;
		nm_device_queue_state (self, new_state, priv->recheck_available.available_reason);
	} else if (state >= NM_DEVICE_STATE_DISCONNECTED && !now_available) {
		new_state = NM_DEVICE_STATE_UNAVAILABLE;
		nm_device_queue_state (self, new_state, priv->recheck_available.unavailable_reason);
	}

	if (new_state > NM_DEVICE_STATE_UNKNOWN) {
		_LOGD (LOGD_DEVICE, "is %savailable, %s %s",
		       now_available ? "" : "not ",
		       new_state == NM_DEVICE_STATE_UNAVAILABLE ? "no change required for" : "will transition to",
		       nm_device_state_to_str (new_state == NM_DEVICE_STATE_UNAVAILABLE ? state : new_state));

		priv->recheck_available.available_reason = NM_DEVICE_STATE_REASON_NONE;
		priv->recheck_available.unavailable_reason = NM_DEVICE_STATE_REASON_NONE;
	}

	if (priv->recheck_available.call_id == 0)
		nm_device_remove_pending_action (self, NM_PENDING_ACTION_RECHECK_AVAILABLE, TRUE);

	return G_SOURCE_REMOVE;
}

void
nm_device_queue_recheck_available (NMDevice *self,
                                   NMDeviceStateReason available_reason,
                                   NMDeviceStateReason unavailable_reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->recheck_available.available_reason = available_reason;
	priv->recheck_available.unavailable_reason = unavailable_reason;
	if (!priv->recheck_available.call_id) {
		priv->recheck_available.call_id = g_idle_add (recheck_available, self);
		nm_device_add_pending_action (self, NM_PENDING_ACTION_RECHECK_AVAILABLE,
		                              FALSE /* cannot assert, because of how recheck_available() first clears
		                                       the call-id and postpones removing the pending-action. */);
	}
}

void
nm_device_emit_recheck_auto_activate (NMDevice *self)
{
	g_signal_emit (self, signals[RECHECK_AUTO_ACTIVATE], 0);
}

static void
dnsmasq_state_changed_cb (NMDnsMasqManager *manager, guint32 status, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	switch (status) {
	case NM_DNSMASQ_STATUS_DEAD:
		nm_device_ip_method_failed (self, AF_INET, NM_DEVICE_STATE_REASON_SHARED_START_FAILED);
		break;
	default:
		break;
	}
}

/*****************************************************************************/

static gboolean
activation_source_handle_cb4 (gpointer user_data)
{
	activation_source_handle_cb (user_data, AF_INET);
	return G_SOURCE_REMOVE;
}

static gboolean
activation_source_handle_cb6 (gpointer user_data)
{
	activation_source_handle_cb (user_data, AF_INET6);
	return G_SOURCE_REMOVE;
}

static ActivationHandleData *
activation_source_get_by_family (NMDevice *self,
                                 int addr_family,
                                 GSourceFunc *out_idle_func)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	switch (addr_family) {
	case AF_INET6:
		NM_SET_OUT (out_idle_func, activation_source_handle_cb6);
		return &priv->act_handle6;
	case AF_INET:
		NM_SET_OUT (out_idle_func, activation_source_handle_cb4);
		return &priv->act_handle4;
	}
	g_return_val_if_reached (NULL);
}

static void
activation_source_clear (NMDevice *self,
                         int addr_family)
{
	ActivationHandleData *act_data;

	act_data = activation_source_get_by_family (self, addr_family, NULL);

	if (act_data->id) {
		_LOGD (LOGD_DEVICE, "activation-stage: clear %s,v%c (id %u)",
		       _activation_func_to_string (act_data->func),
		       nm_utils_addr_family_to_char (addr_family),
		       act_data->id);
		nm_clear_g_source (&act_data->id);
		act_data->func = NULL;
	}
}

static void
activation_source_handle_cb (NMDevice *self,
                             int addr_family)
{
	ActivationHandleData *act_data, a;

	g_return_if_fail (NM_IS_DEVICE (self));

	act_data = activation_source_get_by_family (self, addr_family, NULL);

	g_return_if_fail (act_data->id);
	g_return_if_fail (act_data->func);

	a = *act_data;

	act_data->func = NULL;
	act_data->id = 0;

	_LOGD (LOGD_DEVICE, "activation-stage: invoke %s,v%c (id %u)",
	       _activation_func_to_string (a.func),
	       nm_utils_addr_family_to_char (addr_family),
	       a.id);

	a.func (self);

	_LOGD (LOGD_DEVICE, "activation-stage: complete %s,v%c (id %u)",
	       _activation_func_to_string (a.func),
	       nm_utils_addr_family_to_char (addr_family),
	       a.id);
}

static void
activation_source_schedule (NMDevice *self, ActivationHandleFunc func, int addr_family)
{
	ActivationHandleData *act_data;
	GSourceFunc source_func = NULL;
	guint new_id = 0;

	act_data = activation_source_get_by_family (self, addr_family, &source_func);

	if (act_data->id && act_data->func == func) {
		/* Don't bother rescheduling the same function that's about to
		 * run anyway.  Fixes issues with crappy wireless drivers sending
		 * streams of associate events before NM has had a chance to process
		 * the first one.
		 */
		_LOGD (LOGD_DEVICE, "activation-stage: already scheduled %s,v%c (id %u)",
		       _activation_func_to_string (func),
		       nm_utils_addr_family_to_char (addr_family),
		       act_data->id);
		return;
	}

	new_id = g_idle_add (source_func, self);

	if (act_data->id) {
		_LOGW (LOGD_DEVICE, "activation-stage: schedule %s,v%c which replaces %s,v%c (id %u -> %u)",
		       _activation_func_to_string (func),
		       nm_utils_addr_family_to_char (addr_family),
		       _activation_func_to_string (act_data->func),
		       nm_utils_addr_family_to_char (addr_family),
		       act_data->id, new_id);
		nm_clear_g_source (&act_data->id);
	} else {
		_LOGD (LOGD_DEVICE, "activation-stage: schedule %s,v%c (id %u)",
		       _activation_func_to_string (func),
		       nm_utils_addr_family_to_char (addr_family),
		       new_id);
	}

	act_data->func = func;
	act_data->id = new_id;
}

static gboolean
activation_source_is_scheduled (NMDevice *self,
                                ActivationHandleFunc func,
                                int addr_family)
{
	ActivationHandleData *act_data;

	act_data = activation_source_get_by_family (self, addr_family, NULL);
	return act_data->func == func;
}

/*****************************************************************************/

static void
master_ready (NMDevice *self,
              NMActiveConnection *active)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActiveConnection *master_connection;
	NMDevice *master;

	g_return_if_fail (priv->state == NM_DEVICE_STATE_PREPARE);
	g_return_if_fail (!priv->master_ready_handled);

	/* Notify a master device that it has a new slave */
	g_return_if_fail (nm_active_connection_get_master_ready (active));
	master_connection = nm_active_connection_get_master (active);

	priv->master_ready_handled = TRUE;
	nm_clear_g_signal_handler (active, &priv->master_ready_id);

	master = nm_active_connection_get_device (master_connection);

	_LOGD (LOGD_DEVICE, "master connection ready; master device %s",
	       nm_device_get_iface (master));

	if (priv->master && priv->master != master)
		nm_device_master_release_one_slave (priv->master, self, FALSE, NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);

	/* If the master didn't change, add-slave only rechecks whether to assume a connection. */
	nm_device_master_add_slave (master,
	                            self,
	                            !nm_device_sys_iface_state_is_external_or_assume (self));
}

static void
master_ready_cb (NMActiveConnection *active,
                 GParamSpec *pspec,
                 NMDevice *self)
{
	master_ready (self, active);
	nm_device_activate_schedule_stage2_device_config (self);
}

static void
lldp_neighbors_changed (NMLldpListener *lldp_listener, GParamSpec *pspec,
                        gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	_notify (self, PROP_LLDP_NEIGHBORS);
}

static gboolean
lldp_rx_enabled (NMDevice *self)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingConnectionLldp lldp = NM_SETTING_CONNECTION_LLDP_DEFAULT;

	connection = nm_device_get_applied_connection (self);
	g_return_val_if_fail (connection, FALSE);

	s_con = nm_connection_get_setting_connection (connection);
	g_return_val_if_fail (s_con, FALSE);

	lldp = nm_setting_connection_get_lldp (s_con);
	if (lldp == NM_SETTING_CONNECTION_LLDP_DEFAULT) {
		gs_free char *value = NULL;

		value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
		                                               "connection.lldp",
		                                               self);
		lldp = _nm_utils_ascii_str_to_int64 (value, 10,
		                                     NM_SETTING_CONNECTION_LLDP_DEFAULT,
		                                     NM_SETTING_CONNECTION_LLDP_ENABLE_RX,
		                                     NM_SETTING_CONNECTION_LLDP_DEFAULT);
		if (lldp == NM_SETTING_CONNECTION_LLDP_DEFAULT)
			lldp = NM_SETTING_CONNECTION_LLDP_DISABLE;
	}
	return lldp == NM_SETTING_CONNECTION_LLDP_ENABLE_RX;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *self, NMDeviceStateReason *out_failure_reason)
{
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

/*
 * activate_stage1_device_prepare
 *
 * Prepare for device activation
 *
 */
static void
activate_stage1_device_prepare (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;

	_set_ip_state (self, AF_INET, IP_NONE);
	_set_ip_state (self, AF_INET6, IP_NONE);

	/* Notify the new ActiveConnection along with the state change */
	priv->act_request_public = TRUE;
	_notify (self, PROP_ACTIVE_CONNECTION);

	nm_device_state_changed (self, NM_DEVICE_STATE_PREPARE, NM_DEVICE_STATE_REASON_NONE);

	/* Assumed connections were already set up outside NetworkManager */
	if (!nm_device_sys_iface_state_is_external_or_assume (self)) {
		NMDeviceStateReason failure_reason = NM_DEVICE_STATE_REASON_NONE;

		ret = NM_DEVICE_GET_CLASS (self)->act_stage1_prepare (self, &failure_reason);
		if (ret == NM_ACT_STAGE_RETURN_POSTPONE) {
			return;
		} else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, failure_reason);
			return;
		}
		g_return_if_fail (ret == NM_ACT_STAGE_RETURN_SUCCESS);
	}

	nm_device_activate_schedule_stage2_device_config (self);
}


/*
 * nm_device_activate_schedule_stage1_device_prepare
 *
 * Prepare a device for activation
 *
 */
void
nm_device_activate_schedule_stage1_device_prepare (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	activation_source_schedule (self, activate_stage1_device_prepare, AF_INET);
}

static NMActStageReturn
act_stage2_config (NMDevice *self, NMDeviceStateReason *out_failure_reason)
{
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
lldp_init (NMDevice *self, gboolean restart)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->ifindex > 0 && lldp_rx_enabled (self)) {
		gs_free_error GError *error = NULL;

		if (priv->lldp_listener) {
			if (restart && nm_lldp_listener_is_running (priv->lldp_listener))
				nm_lldp_listener_stop (priv->lldp_listener);
		} else {
			priv->lldp_listener = nm_lldp_listener_new ();
			g_signal_connect (priv->lldp_listener,
			                  "notify::" NM_LLDP_LISTENER_NEIGHBORS,
			                  G_CALLBACK (lldp_neighbors_changed),
			                  self);
		}

		if (!nm_lldp_listener_is_running (priv->lldp_listener)) {
			if (nm_lldp_listener_start (priv->lldp_listener, nm_device_get_ifindex (self), &error))
				_LOGD (LOGD_DEVICE, "LLDP listener %p started", priv->lldp_listener);
			else {
				_LOGD (LOGD_DEVICE, "LLDP listener %p could not be started: %s",
				       priv->lldp_listener, error->message);
			}
		}
	} else {
		if (priv->lldp_listener)
			nm_lldp_listener_stop (priv->lldp_listener);
	}
}

static gboolean
tc_commit (NMDevice *self)
{
	NMConnection *connection = NULL;
	gs_unref_ptrarray GPtrArray *qdiscs = NULL;
	gs_unref_ptrarray GPtrArray *tfilters = NULL;
	NMSettingTCConfig *s_tc = NULL;
	int ip_ifindex;
	guint nqdiscs, ntfilters;
	int i;

	connection = nm_device_get_applied_connection (self);
	if (connection)
		s_tc = nm_connection_get_setting_tc_config (connection);

	ip_ifindex = nm_device_get_ip_ifindex (self);
	if (!ip_ifindex)
	       return s_tc == NULL;

	if (s_tc) {
		nqdiscs = nm_setting_tc_config_get_num_qdiscs (s_tc);
		qdiscs = g_ptr_array_new_full (nqdiscs, (GDestroyNotify) nmp_object_unref);

		for (i = 0; i < nqdiscs; i++) {
			NMTCQdisc *s_qdisc = nm_setting_tc_config_get_qdisc (s_tc, i);
			NMPObject *q = nmp_object_new (NMP_OBJECT_TYPE_QDISC, NULL);
			NMPlatformQdisc *qdisc = NMP_OBJECT_CAST_QDISC (q);

			qdisc->ifindex = ip_ifindex;
			qdisc->kind = nm_tc_qdisc_get_kind (s_qdisc);
			qdisc->addr_family = AF_UNSPEC;
			qdisc->handle = nm_tc_qdisc_get_handle (s_qdisc);
			qdisc->parent = nm_tc_qdisc_get_parent (s_qdisc);
			qdisc->info = 0;

			g_ptr_array_add (qdiscs, q);
		}

		ntfilters = nm_setting_tc_config_get_num_tfilters (s_tc);
		tfilters = g_ptr_array_new_full (ntfilters, (GDestroyNotify) nmp_object_unref);

		for (i = 0; i < ntfilters; i++) {
			NMTCTfilter *s_tfilter = nm_setting_tc_config_get_tfilter (s_tc, i);
			NMTCAction *action;
			NMPObject *q = nmp_object_new (NMP_OBJECT_TYPE_TFILTER, NULL);
			NMPlatformTfilter *tfilter = NMP_OBJECT_CAST_TFILTER (q);

			tfilter->ifindex = ip_ifindex;
			tfilter->kind = nm_tc_tfilter_get_kind (s_tfilter);
			tfilter->addr_family = AF_UNSPEC;
			tfilter->handle = nm_tc_tfilter_get_handle (s_tfilter);
			tfilter->parent = nm_tc_tfilter_get_parent (s_tfilter);
			tfilter->info = TC_H_MAKE (0, htons (ETH_P_ALL));

			action = nm_tc_tfilter_get_action (s_tfilter);
			if (action) {
				tfilter->action.kind = nm_tc_action_get_kind (action);
				if (strcmp (tfilter->action.kind, "simple") == 0) {
					GVariant *sdata;

					sdata = nm_tc_action_get_attribute (action, "sdata");
					if (sdata && g_variant_is_of_type (sdata, G_VARIANT_TYPE_BYTESTRING)) {
						g_strlcpy (tfilter->action.simple.sdata,
						           g_variant_get_bytestring (sdata),
						           sizeof (tfilter->action.simple.sdata));
					}
				}
			}

			g_ptr_array_add (tfilters, q);
		}
	}

	if (!nm_platform_qdisc_sync (nm_device_get_platform (self), ip_ifindex, qdiscs))
		return FALSE;

	if (!nm_platform_tfilter_sync (nm_device_get_platform (self), ip_ifindex, tfilters))
		return FALSE;

	return TRUE;
}

/*
 * activate_stage2_device_config
 *
 * Determine device parameters and set those on the device, ie
 * for wireless devices, set SSID, keys, etc.
 *
 */
static void
activate_stage2_device_config (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActStageReturn ret;
	gboolean no_firmware = FALSE;
	CList *iter;

	nm_device_state_changed (self, NM_DEVICE_STATE_CONFIG, NM_DEVICE_STATE_REASON_NONE);

	/* Assumed connections were already set up outside NetworkManager */
	if (!nm_device_sys_iface_state_is_external_or_assume (self)) {
		NMDeviceStateReason failure_reason = NM_DEVICE_STATE_REASON_NONE;

		if (!tc_commit (self)) {
			_LOGW (LOGD_IP6, "failed applying traffic control rules");
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
		}

		if (!nm_device_bring_up (self, FALSE, &no_firmware)) {
			if (no_firmware)
				nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_FIRMWARE_MISSING);
			else
				nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
			return;
		}

		ret = NM_DEVICE_GET_CLASS (self)->act_stage2_config (self, &failure_reason);
		if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
			return;
		else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
			nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, failure_reason);
			return;
		}
		g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);
	}

	/* If we have slaves that aren't yet enslaved, do that now */
	c_list_for_each (iter, &priv->slaves) {
		SlaveInfo *info = c_list_entry (iter, SlaveInfo, lst_slave);
		NMDeviceState slave_state = nm_device_get_state (info->slave);

		if (slave_state == NM_DEVICE_STATE_IP_CONFIG)
			nm_device_master_enslave_slave (self, info->slave, nm_device_get_applied_connection (info->slave));
		else if (   priv->act_request
		         && nm_device_sys_iface_state_is_external (self)
		         && slave_state <= NM_DEVICE_STATE_DISCONNECTED)
			nm_device_queue_recheck_assume (info->slave);
	}

	lldp_init (self, TRUE);
	nm_device_activate_schedule_stage3_ip_config_start (self);
}


/*
 * nm_device_activate_schedule_stage2_device_config
 *
 * Schedule setup of the hardware device
 *
 */
void
nm_device_activate_schedule_stage2_device_config (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	if (!priv->master_ready_handled) {
		NMActiveConnection *active = NM_ACTIVE_CONNECTION (priv->act_request);
		NMActiveConnection *master;

		master = nm_active_connection_get_master (active);

		if (!master) {
			g_warn_if_fail (!priv->master_ready_id);
			priv->master_ready_handled = TRUE;
		} else {
			/* If the master connection is ready for slaves, attach ourselves */
			if (nm_active_connection_get_master_ready (active))
				master_ready (self, active);
			else if (nm_active_connection_get_state (master) >= NM_ACTIVE_CONNECTION_STATE_DEACTIVATING) {
				_LOGD (LOGD_DEVICE, "master connection is deactivating");
				nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED);
			} else {
				_LOGD (LOGD_DEVICE, "waiting for master connection to become ready");

				if (priv->master_ready_id == 0) {
					priv->master_ready_id = g_signal_connect (active,
					                                          "notify::" NM_ACTIVE_CONNECTION_INT_MASTER_READY,
					                                          (GCallback) master_ready_cb,
					                                          self);
				}
				/* Postpone */
				return;
			}
		}
	}

	activation_source_schedule (self, activate_stage2_device_config, AF_INET);
}

void
nm_device_ip_method_failed (NMDevice *self,
                            int addr_family,
                            NMDeviceStateReason reason)
{
	g_return_if_fail (NM_IS_DEVICE (self));
	g_return_if_fail (NM_IN_SET (addr_family, AF_INET, AF_INET6));

	_set_ip_state (self, addr_family, IP_FAIL);

	if (get_ip_config_may_fail (self, addr_family))
		check_ip_state (self, FALSE, (nm_device_get_state (self) == NM_DEVICE_STATE_IP_CONFIG));
	else
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, reason);
}

/*****************************************************************************/
/* IPv4 DAD stuff */

static guint
get_ipv4_dad_timeout (NMDevice *self)
{
	NMConnection *connection;
	NMSettingIPConfig *s_ip4 = NULL;
	gs_free char *value = NULL;
	gint ret = 0;

	connection = nm_device_get_applied_connection (self);
	if (connection)
		s_ip4 = nm_connection_get_setting_ip4_config (connection);

	if (s_ip4) {
		ret = nm_setting_ip_config_get_dad_timeout (s_ip4);

		if (ret < 0) {
			value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
			                                               "ipv4.dad-timeout", self);
			ret = _nm_utils_ascii_str_to_int64 (value, 10, -1,
			                                    NM_SETTING_IP_CONFIG_DAD_TIMEOUT_MAX,
			                                    -1);
			ret = ret < 0 ? 0 : ret;
		}
	}

	return ret;
}

static void
arping_data_destroy (gpointer ptr, GClosure *closure)
{
	ArpingData *data = ptr;
	int i;

	if (data) {
		for (i = 0; data->configs && data->configs[i]; i++)
			g_object_unref (data->configs[i]);
		g_free (data->configs);
		g_slice_free (ArpingData, data);
	}
}

static void
ipv4_manual_method_apply (NMDevice *self, NMIP4Config **configs, gboolean success)
{
	NMIP4Config *empty;

	if (success) {
		empty = _ip4_config_new (self);
		nm_device_activate_schedule_ip4_config_result (self, empty);
		g_object_unref (empty);
	} else {
		nm_device_ip_method_failed (self, AF_INET,
		                            NM_DEVICE_STATE_REASON_IP_ADDRESS_DUPLICATE);
	}
}

static void
arping_manager_probe_terminated (NMArpingManager *arping_manager, ArpingData *data)
{
	NMDevice *self;
	NMDevicePrivate *priv;
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP4Address *address;
	gboolean result, success = TRUE;
	int i;

	g_assert (data);
	self = data->device;
	priv = NM_DEVICE_GET_PRIVATE (self);

	for (i = 0; data->configs && data->configs[i]; i++) {
		nm_ip_config_iter_ip4_address_for_each (&ipconf_iter, data->configs[i], &address) {
			result = nm_arping_manager_check_address (arping_manager, address->address);
			success &= result;

			_NMLOG (result ? LOGL_DEBUG : LOGL_WARN,
			        LOGD_DEVICE,
			        "IPv4 DAD result: address %s is %s",
			        nm_utils_inet4_ntop (address->address, NULL),
			        result ? "unique" : "duplicate");
		}
	}

	data->callback (self, data->configs, success);

	priv->arping.dad_list = g_slist_remove (priv->arping.dad_list, arping_manager);
	nm_arping_manager_destroy (arping_manager);
}

/**
 * ipv4_dad_start:
 * @self: device instance
 * @configs: NULL-terminated array of IPv4 configurations
 * @cb: callback function
 *
 * Start IPv4 DAD on device @self, check addresses in @configs and call @cb
 * when the procedure ends. @cb will be called in any case, even if DAD can't
 * be started. @configs will be unreferenced after @cb has been called.
 */
static void
ipv4_dad_start (NMDevice *self, NMIP4Config **configs, ArpingCallback cb)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMArpingManager *arping_manager;
	const NMPlatformIP4Address *address;
	NMDedupMultiIter ipconf_iter;
	ArpingData *data;
	guint timeout;
	gboolean ret, addr_found;
	const guint8 *hwaddr_arr;
	GError *error = NULL;
	guint i;

	g_return_if_fail (NM_IS_DEVICE (self));
	g_return_if_fail (configs);
	g_return_if_fail (cb);

	for (i = 0, addr_found = FALSE; configs[i]; i++) {
		if (nm_ip4_config_get_num_addresses (configs[i]) > 0) {
			addr_found = TRUE;
			break;
		}
	}

	timeout = get_ipv4_dad_timeout (self);
	hwaddr_arr = nm_platform_link_get_address (nm_device_get_platform (self),
	                                           nm_device_get_ip_ifindex (self),
	                                           NULL);

	if (   !timeout
	    || !hwaddr_arr
	    || !addr_found
	    || nm_device_sys_iface_state_is_external_or_assume (self)) {

		/* DAD not needed, signal success */
		cb (self, configs, TRUE);

		for (i = 0; configs[i]; i++)
			g_object_unref (configs[i]);
		g_free (configs);

		return;
	}

	/* don't take additional references of @arping_manager that outlive @self.
	 * Otherwise, the callback can be invoked on a dangling pointer as we don't
	 * disconnect the handler. */
	arping_manager = nm_arping_manager_new (nm_device_get_ip_ifindex (self));
	priv->arping.dad_list = g_slist_append (priv->arping.dad_list, arping_manager);

	data = g_slice_new0 (ArpingData);
	data->configs = configs;
	data->callback = cb;
	data->device = self;

	for (i = 0; configs[i]; i++) {
		nm_ip_config_iter_ip4_address_for_each (&ipconf_iter, configs[i], &address)
			nm_arping_manager_add_address (arping_manager, address->address);
	}

	g_signal_connect_data (arping_manager, NM_ARPING_MANAGER_PROBE_TERMINATED,
	                       G_CALLBACK (arping_manager_probe_terminated), data,
	                       arping_data_destroy, 0);

	ret = nm_arping_manager_start_probe (arping_manager, timeout, &error);

	if (!ret) {
		_LOGW (LOGD_DEVICE, "arping probe failed: %s", error->message);

		/* DAD could not be started, signal success */
		cb (self, configs, TRUE);

		priv->arping.dad_list = g_slist_remove (priv->arping.dad_list, arping_manager);
		nm_arping_manager_destroy (arping_manager);
	}
}

/*****************************************************************************/
/* IPv4LL stuff */

static void
ipv4ll_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->ipv4ll) {
		sd_ipv4ll_set_callback (priv->ipv4ll, NULL, NULL);
		sd_ipv4ll_stop (priv->ipv4ll);
		priv->ipv4ll = sd_ipv4ll_unref (priv->ipv4ll);
	}

	nm_clear_g_source (&priv->ipv4ll_timeout);
}

static NMIP4Config *
ipv4ll_get_ip4_config (NMDevice *self, guint32 lla)
{
	NMIP4Config *config = NULL;
	NMPlatformIP4Address address;
	NMPlatformIP4Route route;

	config = _ip4_config_new (self);
	g_assert (config);

	memset (&address, 0, sizeof (address));
	nm_platform_ip4_address_set_addr (&address, lla, 16);
	address.addr_source = NM_IP_CONFIG_SOURCE_IP4LL;
	nm_ip4_config_add_address (config, &address);

	/* Add a multicast route for link-local connections: destination= 224.0.0.0, netmask=240.0.0.0 */
	memset (&route, 0, sizeof (route));
	route.network = htonl (0xE0000000L);
	route.plen = 4;
	route.rt_source = NM_IP_CONFIG_SOURCE_IP4LL;
	route.table_coerced = nm_platform_route_table_coerce (nm_device_get_route_table (self, AF_INET, TRUE));
	route.metric = nm_device_get_route_metric (self, AF_INET);
	nm_ip4_config_add_route (config, &route, NULL);

	return config;
}

#define IPV4LL_NETWORK (htonl (0xA9FE0000L))
#define IPV4LL_NETMASK (htonl (0xFFFF0000L))

static void
nm_device_handle_ipv4ll_event (sd_ipv4ll *ll, int event, void *data)
{
	NMDevice *self = data;
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection = NULL;
	const char *method;
	struct in_addr address;
	NMIP4Config *config;
	int r;

	if (priv->act_request == NULL)
		return;

	connection = nm_act_request_get_applied_connection (priv->act_request);
	g_assert (connection);

	/* Ignore if the connection isn't an AutoIP connection */
	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL) != 0)
		return;

	switch (event) {
	case SD_IPV4LL_EVENT_BIND:
		r = sd_ipv4ll_get_address (ll, &address);
		if (r < 0) {
			_LOGE (LOGD_AUTOIP4, "invalid IPv4 link-local address received, error %d.", r);
			nm_device_ip_method_failed (self, AF_INET, NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED);
			return;
		}

		if ((address.s_addr & IPV4LL_NETMASK) != IPV4LL_NETWORK) {
			_LOGE (LOGD_AUTOIP4, "invalid address %08x received (not link-local).", address.s_addr);
			nm_device_ip_method_failed (self, AF_INET, NM_DEVICE_STATE_REASON_AUTOIP_ERROR);
			return;
		}

		config = ipv4ll_get_ip4_config (self, address.s_addr);
		if (config == NULL) {
			_LOGE (LOGD_AUTOIP4, "failed to get IPv4LL config");
			nm_device_ip_method_failed (self, AF_INET, NM_DEVICE_STATE_REASON_AUTOIP_FAILED);
			return;
		}

		if (priv->ip4_state == IP_CONF) {
			nm_clear_g_source (&priv->ipv4ll_timeout);
			nm_device_activate_schedule_ip4_config_result (self, config);
		} else if (priv->ip4_state == IP_DONE) {
			applied_config_init (&priv->dev_ip4_config, config);
			if (!ip4_config_merge_and_apply (self, TRUE)) {
				_LOGE (LOGD_AUTOIP4, "failed to update IP4 config for autoip change.");
				nm_device_ip_method_failed (self, AF_INET, NM_DEVICE_STATE_REASON_AUTOIP_FAILED);
			}
		} else
			g_assert_not_reached ();

		g_object_unref (config);
		break;
	default:
		_LOGW (LOGD_AUTOIP4, "IPv4LL address no longer valid after event %d.", event);
		nm_device_ip_method_failed (self, AF_INET, NM_DEVICE_STATE_REASON_AUTOIP_FAILED);
	}
}

static gboolean
ipv4ll_timeout_cb (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->ipv4ll_timeout) {
		_LOGI (LOGD_AUTOIP4, "IPv4LL configuration timed out.");
		priv->ipv4ll_timeout = 0;
		ipv4ll_cleanup (self);

		if (priv->ip4_state == IP_CONF)
			nm_device_activate_schedule_ip4_config_timeout (self);
	}

	return FALSE;
}

static NMActStageReturn
ipv4ll_start (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const struct ether_addr *addr;
	int ifindex, r;
	size_t addr_len;

	ipv4ll_cleanup (self);

	r = sd_ipv4ll_new (&priv->ipv4ll);
	if (r < 0) {
		_LOGE (LOGD_AUTOIP4, "IPv4LL: new() failed with error %d", r);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	r = sd_ipv4ll_attach_event (priv->ipv4ll, NULL, 0);
	if (r < 0) {
		_LOGE (LOGD_AUTOIP4, "IPv4LL: attach_event() failed with error %d", r);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	ifindex = nm_device_get_ip_ifindex (self);
	addr = nm_platform_link_get_address (nm_device_get_platform (self), ifindex, &addr_len);
	if (!addr || addr_len != ETH_ALEN) {
		_LOGE (LOGD_AUTOIP4, "IPv4LL: can't retrieve hardware address");
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	r = sd_ipv4ll_set_mac (priv->ipv4ll, addr);
	if (r < 0) {
		_LOGE (LOGD_AUTOIP4, "IPv4LL: set_mac() failed with error %d", r);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	r = sd_ipv4ll_set_ifindex (priv->ipv4ll, ifindex);
	if (r < 0) {
		_LOGE (LOGD_AUTOIP4, "IPv4LL: set_ifindex() failed with error %d", r);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	r = sd_ipv4ll_set_callback (priv->ipv4ll, nm_device_handle_ipv4ll_event, self);
	if (r < 0) {
		_LOGE (LOGD_AUTOIP4, "IPv4LL: set_callback() failed with error %d", r);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	r = sd_ipv4ll_start (priv->ipv4ll);
	if (r < 0) {
		_LOGE (LOGD_AUTOIP4, "IPv4LL: start() failed with error %d", r);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	_LOGI (LOGD_DEVICE | LOGD_AUTOIP4, "IPv4LL: started");

	/* Start a timeout to bound the address attempt */
	priv->ipv4ll_timeout = g_timeout_add_seconds (20, ipv4ll_timeout_cb, self);
	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/

static void
ensure_con_ip4_config (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;

	if (priv->con_ip4_config)
		return;

	connection = nm_device_get_applied_connection (self);
	if (!connection)
		return;

	priv->con_ip4_config = _ip4_config_new (self);
	nm_ip4_config_merge_setting (priv->con_ip4_config,
	                             nm_connection_get_setting_ip4_config (connection),
	                             _get_mdns (self),
	                             nm_device_get_route_table (self, AF_INET, TRUE),
	                             nm_device_get_route_metric (self, AF_INET));

	if (nm_device_sys_iface_state_is_external_or_assume (self)) {
		/* For assumed connections ignore all addresses and routes. */
		nm_ip4_config_reset_addresses (priv->con_ip4_config);
		nm_ip4_config_reset_routes (priv->con_ip4_config);
	}
}

static void
ensure_con_ip6_config (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;

	if (priv->con_ip6_config)
		return;

	connection = nm_device_get_applied_connection (self);
	if (!connection)
		return;

	priv->con_ip6_config = _ip6_config_new (self);
	nm_ip6_config_merge_setting (priv->con_ip6_config,
	                             nm_connection_get_setting_ip6_config (connection),
	                             nm_device_get_route_table (self, AF_INET6, TRUE),
	                             nm_device_get_route_metric (self, AF_INET6));

	if (nm_device_sys_iface_state_is_external_or_assume (self)) {
		/* For assumed connections ignore all addresses and routes. */
		nm_ip6_config_reset_addresses (priv->con_ip6_config);
		nm_ip6_config_reset_routes (priv->con_ip6_config);
	}
}

/*****************************************************************************/
/* DHCPv4 stuff */

static void
dhcp4_cleanup (NMDevice *self, CleanupType cleanup_type, gboolean release)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	nm_clear_g_source (&priv->dhcp4.restart_id);
	g_clear_pointer (&priv->dhcp4.pac_url, g_free);

	if (priv->dhcp4.client) {
		/* Stop any ongoing DHCP transaction on this device */
		nm_clear_g_signal_handler (priv->dhcp4.client, &priv->dhcp4.state_sigid);

		nm_device_remove_pending_action (self, NM_PENDING_ACTION_DHCP4, FALSE);

		if (   cleanup_type == CLEANUP_TYPE_DECONFIGURE
		    || cleanup_type == CLEANUP_TYPE_REMOVED)
			nm_dhcp_client_stop (priv->dhcp4.client, release);

		g_clear_object (&priv->dhcp4.client);
	}

	if (priv->dhcp4.config) {
		nm_dbus_object_clear_and_unexport (&priv->dhcp4.config);
		_notify (self, PROP_DHCP4_CONFIG);
	}
}

static gboolean
ip4_config_merge_and_apply (NMDevice *self,
                            gboolean commit)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	gboolean success;
	NMIP4Config *composite, *config;
	gboolean ignore_auto_routes = FALSE;
	gboolean ignore_auto_dns = FALSE;
	gboolean ignore_default_routes = FALSE;
	GSList *iter;
	gs_unref_ptrarray GPtrArray *ip4_dev_route_blacklist = NULL;

	if (nm_device_sys_iface_state_is_external (self))
		commit = 0;

	/* Apply ignore-auto-routes and ignore-auto-dns settings */
	connection = nm_device_get_applied_connection (self);
	if (connection) {
		NMSettingIPConfig *s_ip4 = nm_connection_get_setting_ip4_config (connection);

		if (s_ip4) {
			ignore_auto_routes = nm_setting_ip_config_get_ignore_auto_routes (s_ip4);
			ignore_auto_dns = nm_setting_ip_config_get_ignore_auto_dns (s_ip4);

			/* if the connection has an explicit gateway, we also ignore
			 * the default routes from other sources. */
			ignore_default_routes =    nm_setting_ip_config_get_never_default (s_ip4)
			                        || nm_setting_ip_config_get_gateway (s_ip4);
		}
	}

	composite = _ip4_config_new (self);
	init_ip4_config_dns_priority (self, composite);

	if (commit) {
		if (priv->queued_ip4_config_id)
			update_ext_ip_config (self, AF_INET, FALSE, FALSE);
		ensure_con_ip4_config (self);
	}

	if (commit)
		priv->default_route_metric_penalty_ip4_has = default_route_metric_penalty_detect (self);

	config = (NMIP4Config *) applied_config_get_current (&priv->dev_ip4_config);
	if (config) {
		nm_ip4_config_merge (composite, config,
		                       (ignore_auto_routes ? NM_IP_CONFIG_MERGE_NO_ROUTES : 0)
		                     | (ignore_default_routes ? NM_IP_CONFIG_MERGE_NO_DEFAULT_ROUTES : 0)
		                     | (ignore_auto_dns ? NM_IP_CONFIG_MERGE_NO_DNS : 0),
		                     default_route_metric_penalty_get (self, AF_INET));
	}

	for (iter = priv->vpn4_configs; iter; iter = iter->next)
		nm_ip4_config_merge (composite, iter->data, NM_IP_CONFIG_MERGE_DEFAULT, 0);

	if (priv->ext_ip4_config)
		nm_ip4_config_merge (composite, priv->ext_ip4_config, NM_IP_CONFIG_MERGE_DEFAULT, 0);

	/* Merge WWAN config *last* to ensure modem-given settings overwrite
	 * any external stuff set by pppd or other scripts.
	 */
	config = (NMIP4Config *) applied_config_get_current (&priv->wwan_ip4_config);
	if (config) {
		nm_ip4_config_merge (composite, config,
		                       (ignore_auto_routes ? NM_IP_CONFIG_MERGE_NO_ROUTES : 0)
		                     | (ignore_default_routes ? NM_IP_CONFIG_MERGE_NO_DEFAULT_ROUTES : 0)
		                     | (ignore_auto_dns ? NM_IP_CONFIG_MERGE_NO_DNS : 0),
		                     default_route_metric_penalty_get (self, AF_INET));
	}

	/* Merge user overrides into the composite config. For assumed connections,
	 * con_ip4_config is empty. */
	if (priv->con_ip4_config) {
		nm_ip4_config_merge (composite, priv->con_ip4_config, NM_IP_CONFIG_MERGE_DEFAULT,
		                     default_route_metric_penalty_get (self, AF_INET));
	}

	if (commit) {
		nm_ip4_config_add_dependent_routes (composite,
		                                    nm_device_get_route_table (self, AF_INET, TRUE),
		                                    nm_device_get_route_metric (self, AF_INET),
		                                    &ip4_dev_route_blacklist);
	}

	if (commit) {
		if (NM_DEVICE_GET_CLASS (self)->ip4_config_pre_commit)
			NM_DEVICE_GET_CLASS (self)->ip4_config_pre_commit (self, composite);
	}

	success = nm_device_set_ip4_config (self, composite, commit, ip4_dev_route_blacklist);
	g_object_unref (composite);

	if (commit)
		priv->v4_commit_first_time = FALSE;
	return success;
}

static gboolean
dhcp4_lease_change (NMDevice *self, NMIP4Config *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_val_if_fail (config, FALSE);

	applied_config_init (&priv->dev_ip4_config, config);

	if (!ip4_config_merge_and_apply (self, TRUE)) {
		_LOGW (LOGD_DHCP4, "failed to update IPv4 config for DHCP change.");
		return FALSE;
	}

	nm_dispatcher_call_device (NM_DISPATCHER_ACTION_DHCP4_CHANGE,
	                           self,
	                           NULL,
	                           NULL, NULL, NULL);

	nm_device_remove_pending_action (self, NM_PENDING_ACTION_DHCP4, FALSE);

	return TRUE;
}

static gboolean
dhcp4_restart_cb (gpointer user_data)
{
	NMDevice *self = user_data;
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	priv->dhcp4.restart_id = 0;

	if (dhcp4_start (self) == NM_ACT_STAGE_RETURN_FAILURE)
		dhcp_schedule_restart (self, AF_INET, NULL);

	return FALSE;
}

static void
dhcp4_fail (NMDevice *self, gboolean timeout)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	_LOGD (LOGD_DHCP4, "DHCPv4 failed: timeout %d, num tries left %u",
	       timeout, priv->dhcp4.num_tries_left);

	dhcp4_cleanup (self, CLEANUP_TYPE_DECONFIGURE, FALSE);

	/* Don't fail if there are static addresses configured on
	 * the device, instead retry after some time.
	 */
	if (   priv->ip4_state == IP_DONE
	    && priv->con_ip4_config
	    && nm_ip4_config_get_num_addresses (priv->con_ip4_config) > 0) {
		dhcp_schedule_restart (self, AF_INET, "device has IP addresses");
		return;
	}

	if (   priv->dhcp4.num_tries_left == DHCP_NUM_TRIES_MAX
	    && (timeout || (priv->ip4_state == IP_CONF))
	    && !priv->dhcp4.was_active)
		nm_device_activate_schedule_ip4_config_timeout (self);
	else if (   priv->dhcp4.num_tries_left < DHCP_NUM_TRIES_MAX
	         || priv->ip4_state == IP_DONE
	         || priv->dhcp4.was_active) {
		/* Don't fail immediately when the lease expires but try to
		 * restart DHCP for a predefined number of times.
		 */
		if (priv->dhcp4.num_tries_left) {
			priv->dhcp4.num_tries_left--;
			dhcp_schedule_restart (self, AF_INET, "lease expired");
		} else {
			nm_device_ip_method_failed (self, AF_INET, NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED);
			/* We failed the ipv4 method but schedule again the retries if the ipv6 method is
			 * configured, keeping the connection up.
			 */
			if (nm_device_get_state (self) != NM_DEVICE_STATE_FAILED)
				dhcp_schedule_restart (self, AF_INET, "renewal failed");
		}
	} else
		g_warn_if_reached ();
}

static void
dhcp4_dad_cb (NMDevice *self, NMIP4Config **configs, gboolean success)
{
	if (success)
		nm_device_activate_schedule_ip4_config_result (self, configs[1]);
	else {
		nm_device_ip_method_failed (self, AF_INET,
		                            NM_DEVICE_STATE_REASON_IP_ADDRESS_DUPLICATE);
	}
}

static void
dhcp4_state_changed (NMDhcpClient *client,
                     NMDhcpState state,
                     NMIP4Config *ip4_config,
                     GHashTable *options,
                     const char *event_id,
                     gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMIP4Config *manual, **configs;
	NMConnection *connection;

	g_return_if_fail (nm_dhcp_client_get_addr_family (client) == AF_INET);
	g_return_if_fail (!ip4_config || NM_IS_IP4_CONFIG (ip4_config));

	_LOGD (LOGD_DHCP4, "new DHCPv4 client state %d", state);

	switch (state) {
	case NM_DHCP_STATE_BOUND:
		if (!ip4_config) {
			_LOGW (LOGD_DHCP4, "failed to get IPv4 config in response to DHCP event.");
			dhcp4_fail (self, FALSE);
			break;
		}

		/* After some failures, we have been able to renew the lease:
		 * update the ip state
		 */
		if (priv->ip4_state == IP_FAIL)
			_set_ip_state (self, AF_INET, IP_CONF);

		g_free (priv->dhcp4.pac_url);
		priv->dhcp4.pac_url = g_strdup (g_hash_table_lookup (options, "wpad"));
		nm_device_set_proxy_config (self, priv->dhcp4.pac_url);

		nm_dhcp4_config_set_options (priv->dhcp4.config, options);
		_notify (self, PROP_DHCP4_CONFIG);
		priv->dhcp4.num_tries_left = DHCP_NUM_TRIES_MAX;

		if (priv->ip4_state == IP_CONF) {
			connection = nm_device_get_applied_connection (self);
			g_assert (connection);

			manual = _ip4_config_new (self);
			nm_ip4_config_merge_setting (manual,
			                             nm_connection_get_setting_ip4_config (connection),
			                             NM_SETTING_CONNECTION_MDNS_DEFAULT,
			                             nm_device_get_route_table (self, AF_INET, TRUE),
			                             nm_device_get_route_metric (self, AF_INET));

			configs = g_new0 (NMIP4Config *, 3);
			configs[0] = manual;
			configs[1] = g_object_ref (ip4_config);

			ipv4_dad_start (self, configs, dhcp4_dad_cb);
		} else if (priv->ip4_state == IP_DONE) {
			if (dhcp4_lease_change (self, ip4_config))
				nm_device_update_metered (self);
			else
				dhcp4_fail (self, FALSE);
		}
		break;
	case NM_DHCP_STATE_TIMEOUT:
		dhcp4_fail (self, TRUE);
		break;
	case NM_DHCP_STATE_EXPIRE:
		/* Ignore expiry before we even have a lease (NAK, old lease, etc) */
		if (priv->ip4_state == IP_CONF)
			break;
		/* fall through */
	case NM_DHCP_STATE_DONE:
	case NM_DHCP_STATE_FAIL:
		dhcp4_fail (self, FALSE);
		break;
	default:
		break;
	}
}

static int
get_dhcp_timeout (NMDevice *self, int addr_family)
{
	NMDeviceClass *klass;
	NMConnection *connection;
	NMSettingIPConfig *s_ip;
	guint32 timeout;

	nm_assert (NM_IS_DEVICE (self));
	nm_assert_addr_family (addr_family);

	connection = nm_device_get_applied_connection (self);

	if (addr_family == AF_INET)
		s_ip = nm_connection_get_setting_ip4_config (connection);
	else
		s_ip = nm_connection_get_setting_ip6_config (connection);

	timeout = nm_setting_ip_config_get_dhcp_timeout (s_ip);
	if (timeout)
		return timeout;

	{
		gs_free char *value = NULL;

		value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
		                                               addr_family == AF_INET
		                                                 ? "ipv4.dhcp-timeout"
		                                                 : "ipv6.dhcp-timeout",
		                                               self);
		timeout = _nm_utils_ascii_str_to_int64 (value, 10,
		                                        0, G_MAXINT32, 0);
		if (timeout)
			return timeout;
	}

	klass = NM_DEVICE_GET_CLASS (self);
	if (klass->get_dhcp_timeout)
		timeout = klass->get_dhcp_timeout (self, addr_family);

	return timeout ?: NM_DHCP_TIMEOUT_DEFAULT;
}

static GBytes *
dhcp4_get_client_id (NMDevice *self, NMConnection *connection)
{
	NMSettingIPConfig *s_ip4;
	const char *client_id;
	gs_free char *client_id_default = NULL;
	guint8 *client_id_buf;
	gboolean is_mac;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	client_id = nm_setting_ip4_config_get_dhcp_client_id (NM_SETTING_IP4_CONFIG (s_ip4));

	if (!client_id) {
		client_id_default = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
		                                                           "ipv4.dhcp-client-id", self);
		if (client_id_default && client_id_default[0])
			client_id = client_id_default;
	}

	if (!client_id)
		return NULL;

	if (   (is_mac = nm_streq (client_id, "mac"))
	    || nm_streq (client_id, "perm-mac")) {
		const char *hwaddr;
		char addr_buf[NM_UTILS_HWADDR_LEN_MAX];
		gsize addr_len;
		guint8 addr_type;

		hwaddr = is_mac
		         ? nm_device_get_hw_address (self)
		         : nm_device_get_permanent_hw_address (self);
		if (!hwaddr)
			return NULL;

		if (!_nm_utils_hwaddr_aton (hwaddr, addr_buf, sizeof (addr_buf), &addr_len))
			g_return_val_if_reached (NULL);

		switch (addr_len) {
		case ETH_ALEN:
			addr_type = ARPHRD_ETHER;
			break;
		default:
			/* unsupported type. */
			return NULL;
		}

		client_id_buf = g_malloc (addr_len + 1);
		client_id_buf[0] = addr_type;
		memcpy (&client_id_buf[1], addr_buf, addr_len);
		return g_bytes_new_take (client_id_buf, addr_len + 1);
	}

	if (nm_streq (client_id, "stable")) {
		NMUtilsStableType stable_type;
		const char *stable_id;
		GChecksum *sum;
		guint8 buf[20];
		gsize buf_size;
		guint32 salted_header;

		stable_id = _get_stable_id (self, connection, &stable_type);
		if (!stable_id)
			g_return_val_if_reached (NULL);

		salted_header = htonl (2011610591 + stable_type);

		sum = g_checksum_new (G_CHECKSUM_SHA1);

		g_checksum_update (sum, (const guchar *) &salted_header, sizeof (salted_header));
		g_checksum_update (sum, (const guchar *) stable_id, strlen (stable_id));

		buf_size = sizeof (buf);
		g_checksum_get_digest (sum, buf, &buf_size);
		nm_assert (buf_size == sizeof (buf));

		g_checksum_free (sum);

		client_id_buf = g_malloc (1 + 15);
		client_id_buf[0] = 0;
		memcpy (&client_id_buf[0], buf, 15);
		return g_bytes_new_take (client_id_buf, 1 + 15);
	}

	return nm_dhcp_utils_client_id_string_to_bytes (client_id);
}

static NMActStageReturn
dhcp4_start (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMSettingIPConfig *s_ip4;
	gs_unref_bytes GBytes *hwaddr = NULL;
	gs_unref_bytes GBytes *client_id = NULL;
	NMConnection *connection;

	connection = nm_device_get_applied_connection (self);
	g_return_val_if_fail (connection, FALSE);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);

	/* Clear old exported DHCP options */
	nm_dbus_object_clear_and_unexport (&priv->dhcp4.config);
	priv->dhcp4.config = nm_dhcp4_config_new ();

	hwaddr = nm_platform_link_get_address_as_bytes (nm_device_get_platform (self),
	                                                nm_device_get_ip_ifindex (self));

	client_id = dhcp4_get_client_id (self, connection);

	g_warn_if_fail (priv->dhcp4.client == NULL);
	priv->dhcp4.client = nm_dhcp_manager_start_ip4 (nm_dhcp_manager_get (),
	                                                nm_netns_get_multi_idx (nm_device_get_netns (self)),
	                                                nm_device_get_ip_iface (self),
	                                                nm_device_get_ip_ifindex (self),
	                                                hwaddr,
	                                                nm_connection_get_uuid (connection),
	                                                nm_device_get_route_table (self, AF_INET, TRUE),
	                                                nm_device_get_route_metric (self, AF_INET),
	                                                nm_setting_ip_config_get_dhcp_send_hostname (s_ip4),
	                                                nm_setting_ip_config_get_dhcp_hostname (s_ip4),
	                                                nm_setting_ip4_config_get_dhcp_fqdn (NM_SETTING_IP4_CONFIG (s_ip4)),
	                                                client_id,
	                                                get_dhcp_timeout (self, AF_INET),
	                                                priv->dhcp_anycast_address,
	                                                NULL);

	if (!priv->dhcp4.client)
		return NM_ACT_STAGE_RETURN_FAILURE;

	priv->dhcp4.state_sigid = g_signal_connect (priv->dhcp4.client,
	                                            NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED,
	                                            G_CALLBACK (dhcp4_state_changed),
	                                            self);

	nm_device_add_pending_action (self, NM_PENDING_ACTION_DHCP4, TRUE);

	if (nm_device_sys_iface_state_is_external_or_assume (self))
		priv->dhcp4.was_active = TRUE;

	/* DHCP devices will be notified by the DHCP manager when stuff happens */
	return NM_ACT_STAGE_RETURN_POSTPONE;
}

gboolean
nm_device_dhcp4_renew (NMDevice *self, gboolean release)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_val_if_fail (priv->dhcp4.client != NULL, FALSE);

	_LOGI (LOGD_DHCP4, "DHCPv4 lease renewal requested");

	/* Terminate old DHCP instance and release the old lease */
	dhcp4_cleanup (self, CLEANUP_TYPE_DECONFIGURE, release);

	/* Start DHCP again on the interface */
	return dhcp4_start (self) != NM_ACT_STAGE_RETURN_FAILURE;
}

/*****************************************************************************/

static GHashTable *shared_ips = NULL;

static void
shared_ip_release (gpointer data)
{
	g_hash_table_remove (shared_ips, data);
	if (!g_hash_table_size (shared_ips))
		g_clear_pointer (&shared_ips, g_hash_table_unref);
}

static NMIP4Config *
shared4_new_config (NMDevice *self, NMConnection *connection)
{
	NMIP4Config *config = NULL;
	gboolean is_generated = FALSE;
	NMSettingIPConfig *s_ip4;
	NMPlatformIP4Address address = {
		.addr_source = NM_IP_CONFIG_SOURCE_SHARED,
	};

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (connection, NULL);

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (s_ip4 && nm_setting_ip_config_get_num_addresses (s_ip4)) {
		/* Use the first user-supplied address */
		NMIPAddress *user = nm_setting_ip_config_get_address (s_ip4, 0);
		in_addr_t a;

		nm_ip_address_get_address_binary (user, &a);
		nm_platform_ip4_address_set_addr (&address, a, nm_ip_address_get_prefix (user));
	} else {
		/* Find an unused address in the 10.42.x.x range */
		guint32 start = (guint32) ntohl (0x0a2a0001); /* 10.42.0.1 */
		guint32 count = 0;

		if (G_UNLIKELY (!shared_ips))
			shared_ips = g_hash_table_new (nm_direct_hash, NULL);
		else {
			while (g_hash_table_lookup (shared_ips, GUINT_TO_POINTER (start + count))) {
				count += ntohl (0x100);
				if (count > ntohl (0xFE00)) {
					_LOGE (LOGD_SHARING, "ran out of shared IP addresses!");
					return FALSE;
				}
			}
		}
		nm_platform_ip4_address_set_addr (&address, start + count, 24);
		g_hash_table_add (shared_ips, GUINT_TO_POINTER (address.address));
		is_generated = TRUE;
	}

	config = _ip4_config_new (self);
	nm_ip4_config_add_address (config, &address);
	if (is_generated) {
		/* Remove the address lock when the object gets disposed */
		g_object_set_qdata_full (G_OBJECT (config), NM_CACHED_QUARK ("shared-ip"),
		                         GUINT_TO_POINTER (address.address),
		                         shared_ip_release);
	}
	return config;
}

/*****************************************************************************/

static gboolean
connection_ip4_method_requires_carrier (NMConnection *connection,
                                        gboolean *out_ip4_enabled)
{
	const char *method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	static const char *ip4_carrier_methods[] = {
		NM_SETTING_IP4_CONFIG_METHOD_AUTO,
		NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL,
		NULL
	};

	if (out_ip4_enabled)
		*out_ip4_enabled = !!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED);
	return g_strv_contains (ip4_carrier_methods, method);
}

static gboolean
connection_ip6_method_requires_carrier (NMConnection *connection,
                                        gboolean *out_ip6_enabled)
{
	const char *method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
	static const char *ip6_carrier_methods[] = {
		NM_SETTING_IP6_CONFIG_METHOD_AUTO,
		NM_SETTING_IP6_CONFIG_METHOD_DHCP,
		NM_SETTING_IP6_CONFIG_METHOD_SHARED,
		NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
		NULL
	};

	if (out_ip6_enabled)
		*out_ip6_enabled = !!strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE);
	return g_strv_contains (ip6_carrier_methods, method);
}

static gboolean
connection_requires_carrier (NMConnection *connection)
{
	NMSettingIPConfig *s_ip4, *s_ip6;
	NMSettingConnection *s_con;
	gboolean ip4_carrier_wanted, ip6_carrier_wanted;
	gboolean ip4_used = FALSE, ip6_used = FALSE;

	/* We can progress to IP_CONFIG now, so that we're enslaved.
	 * That may actually cause carrier to go up and thus continue acivation. */
	s_con = nm_connection_get_setting_connection (connection);
	if (nm_setting_connection_get_master (s_con))
		return FALSE;

	ip4_carrier_wanted = connection_ip4_method_requires_carrier (connection, &ip4_used);
	if (ip4_carrier_wanted) {
		/* If IPv4 wants a carrier and cannot fail, the whole connection
		 * requires a carrier regardless of the IPv6 method.
		 */
		s_ip4 = nm_connection_get_setting_ip4_config (connection);
		if (s_ip4 && !nm_setting_ip_config_get_may_fail (s_ip4))
			return TRUE;
	}

	ip6_carrier_wanted = connection_ip6_method_requires_carrier (connection, &ip6_used);
	if (ip6_carrier_wanted) {
		/* If IPv6 wants a carrier and cannot fail, the whole connection
		 * requires a carrier regardless of the IPv4 method.
		 */
		s_ip6 = nm_connection_get_setting_ip6_config (connection);
		if (s_ip6 && !nm_setting_ip_config_get_may_fail (s_ip6))
			return TRUE;
	}

	/* If an IP version wants a carrier and the other IP version isn't
	 * used, the connection requires carrier since it will just fail without one.
	 */
	if (ip4_carrier_wanted && !ip6_used)
		return TRUE;
	if (ip6_carrier_wanted && !ip4_used)
		return TRUE;

	/* If both want a carrier, the whole connection wants a carrier */
	return ip4_carrier_wanted && ip6_carrier_wanted;
}

static gboolean
have_any_ready_slaves (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	SlaveInfo *info;
	CList *iter;

	/* Any enslaved slave is "ready" in the generic case as it's
	 * at least >= NM_DEVCIE_STATE_IP_CONFIG and has had Layer 2
	 * properties set up.
	 */
	c_list_for_each (iter, &priv->slaves) {
		info = c_list_entry (iter, SlaveInfo, lst_slave);
		if (NM_DEVICE_GET_PRIVATE (info->slave)->is_enslaved)
			return TRUE;
	}
	return FALSE;
}

static gboolean
ip4_requires_slaves (NMConnection *connection)
{
	const char *method;

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	return strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0;
}

static NMActStageReturn
act_stage3_ip4_config_start (NMDevice *self,
                             NMIP4Config **out_config,
                             NMDeviceStateReason *out_failure_reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	const char *method;

	connection = nm_device_get_applied_connection (self);
	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	if (   connection_ip4_method_requires_carrier (connection, NULL)
	    && nm_device_is_master (self)
	    && !priv->carrier) {
		_LOGI (LOGD_IP4 | LOGD_DEVICE,
		       "IPv4 config waiting until carrier is on");
		return NM_ACT_STAGE_RETURN_IP_WAIT;
	}

	if (nm_device_is_master (self) && ip4_requires_slaves (connection)) {
		/* If the master has no ready slaves, and depends on slaves for
		 * a successful IPv4 attempt, then postpone IPv4 addressing.
		 */
		if (!have_any_ready_slaves (self)) {
			_LOGI (LOGD_DEVICE | LOGD_IP4,
			       "IPv4 config waiting until slaves are ready");
			return NM_ACT_STAGE_RETURN_IP_WAIT;
		}
	}

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	priv->dhcp4.num_tries_left = DHCP_NUM_TRIES_MAX;

	/* Start IPv4 addressing based on the method requested */
	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0) {
		ret = dhcp4_start (self);
		if (ret == NM_ACT_STAGE_RETURN_FAILURE)
			NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_DHCP_START_FAILED);
	} else if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL) == 0) {
		ret = ipv4ll_start (self);
		if (ret == NM_ACT_STAGE_RETURN_FAILURE)
			NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_AUTOIP_START_FAILED);
	} else if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL) == 0) {
		NMIP4Config **configs, *config;

		config = _ip4_config_new (self);
		nm_ip4_config_merge_setting (config,
		                             nm_connection_get_setting_ip4_config (connection),
		                             NM_SETTING_CONNECTION_MDNS_DEFAULT,
		                             nm_device_get_route_table (self, AF_INET, TRUE),
		                             nm_device_get_route_metric (self, AF_INET));

		configs = g_new0 (NMIP4Config *, 2);
		configs[0] = config;
		ipv4_dad_start (self, configs, ipv4_manual_method_apply);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED) == 0) {
		if (out_config) {
			*out_config = shared4_new_config (self, connection);
			if (*out_config) {
				priv->dnsmasq_manager = nm_dnsmasq_manager_new (nm_device_get_ip_iface (self));
				ret = NM_ACT_STAGE_RETURN_SUCCESS;
			} else {
				NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
				ret = NM_ACT_STAGE_RETURN_FAILURE;
			}
		} else
			g_return_val_if_reached (NM_ACT_STAGE_RETURN_FAILURE);
	} else if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0)
		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	else
		_LOGW (LOGD_IP4, "unhandled IPv4 config method '%s'; will fail", method);

	return ret;
}

/*****************************************************************************/
/* DHCPv6 stuff */

static void
dhcp6_cleanup (NMDevice *self, CleanupType cleanup_type, gboolean release)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->dhcp6.mode = NM_NDISC_DHCP_LEVEL_NONE;
	applied_config_clear (&priv->dhcp6.ip6_config);
	g_clear_pointer (&priv->dhcp6.event_id, g_free);
	nm_clear_g_source (&priv->dhcp6.restart_id);

	if (priv->dhcp6.client) {
		nm_clear_g_signal_handler (priv->dhcp6.client, &priv->dhcp6.state_sigid);
		nm_clear_g_signal_handler (priv->dhcp6.client, &priv->dhcp6.prefix_sigid);

		if (   cleanup_type == CLEANUP_TYPE_DECONFIGURE
		    || cleanup_type == CLEANUP_TYPE_REMOVED)
			nm_dhcp_client_stop (priv->dhcp6.client, release);

		g_clear_object (&priv->dhcp6.client);
	}

	nm_device_remove_pending_action (self, NM_PENDING_ACTION_DHCP6, FALSE);

	if (priv->dhcp6.config) {
		nm_dbus_object_clear_and_unexport (&priv->dhcp6.config);
		_notify (self, PROP_DHCP6_CONFIG);
	}
}

static gboolean
ip6_config_merge_and_apply (NMDevice *self,
                            gboolean commit)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	gboolean success;
	NMIP6Config *composite, *config;
	gboolean ignore_auto_routes = FALSE;
	gboolean ignore_auto_dns = FALSE;
	gboolean ignore_default_routes = FALSE;
	const char *token = NULL;
	GSList *iter;

	if (nm_device_sys_iface_state_is_external (self))
		commit = 0;

	/* Apply ignore-auto-routes and ignore-auto-dns settings */
	connection = nm_device_get_applied_connection (self);
	if (connection) {
		NMSettingIPConfig *s_ip6 = nm_connection_get_setting_ip6_config (connection);

		if (s_ip6) {
			NMSettingIP6Config *ip6 = NM_SETTING_IP6_CONFIG (s_ip6);

			ignore_auto_routes = nm_setting_ip_config_get_ignore_auto_routes (s_ip6);
			ignore_auto_dns = nm_setting_ip_config_get_ignore_auto_dns (s_ip6);

			/* if the connection has an explicit gateway, we also ignore
			 * the default routes from other sources. */
			ignore_default_routes =    nm_setting_ip_config_get_never_default (s_ip6)
			                        || nm_setting_ip_config_get_gateway (s_ip6);

			if (nm_setting_ip6_config_get_addr_gen_mode (ip6) == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64)
				token = nm_setting_ip6_config_get_token (ip6);
		}
	}

	composite = _ip6_config_new (self);
	nm_ip6_config_set_privacy (composite,
	                           priv->ndisc ?
	                           priv->ndisc_use_tempaddr :
	                           NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);
	init_ip6_config_dns_priority (self, composite);

	if (commit) {
		if (priv->queued_ip6_config_id)
			update_ext_ip_config (self, AF_INET6, FALSE, FALSE);
		ensure_con_ip6_config (self);
	}

	if (commit)
		priv->default_route_metric_penalty_ip6_has = default_route_metric_penalty_detect (self);

	/* Merge all the IP configs into the composite config */
	config = (NMIP6Config *) applied_config_get_current (&priv->ac_ip6_config);
	if (config) {
		nm_ip6_config_merge (composite, config,
		                       (ignore_auto_routes ? NM_IP_CONFIG_MERGE_NO_ROUTES : 0)
		                     | (ignore_default_routes ? NM_IP_CONFIG_MERGE_NO_DEFAULT_ROUTES : 0)
		                     | (ignore_auto_dns ? NM_IP_CONFIG_MERGE_NO_DNS : 0),
		                     default_route_metric_penalty_get (self, AF_INET6));
	}

	config = (NMIP6Config *) applied_config_get_current (&priv->dhcp6.ip6_config);
	if (config) {
		nm_ip6_config_merge (composite, config,
		                       (ignore_auto_routes ? NM_IP_CONFIG_MERGE_NO_ROUTES : 0)
		                     | (ignore_default_routes ? NM_IP_CONFIG_MERGE_NO_DEFAULT_ROUTES : 0)
		                     | (ignore_auto_dns ? NM_IP_CONFIG_MERGE_NO_DNS : 0),
		                     default_route_metric_penalty_get (self, AF_INET6));
	}

	for (iter = priv->vpn6_configs; iter; iter = iter->next)
		nm_ip6_config_merge (composite, iter->data, NM_IP_CONFIG_MERGE_DEFAULT, 0);

	if (priv->ext_ip6_config)
		nm_ip6_config_merge (composite, priv->ext_ip6_config, NM_IP_CONFIG_MERGE_DEFAULT, 0);

	/* Merge WWAN config *last* to ensure modem-given settings overwrite
	 * any external stuff set by pppd or other scripts.
	 */
	config = (NMIP6Config *) applied_config_get_current (&priv->wwan_ip6_config);
	if (config) {
		nm_ip6_config_merge (composite, config,
		                       (ignore_auto_routes ? NM_IP_CONFIG_MERGE_NO_ROUTES : 0)
		                     | (ignore_default_routes ? NM_IP_CONFIG_MERGE_NO_DEFAULT_ROUTES : 0)
		                     | (ignore_auto_dns ? NM_IP_CONFIG_MERGE_NO_DNS : 0),
		                     default_route_metric_penalty_get (self, AF_INET6));
	}

	if (priv->rt6_temporary_not_available) {
		const NMPObject *o;
		GHashTableIter hiter;

		g_hash_table_iter_init (&hiter, priv->rt6_temporary_not_available);
		while (g_hash_table_iter_next (&hiter, (gpointer *) &o, NULL)) {
			nm_ip6_config_add_route (composite,
			                         NMP_OBJECT_CAST_IP6_ROUTE (o),
			                         NULL);
		}
	}

	/* Merge user overrides into the composite config. For assumed connections,
	 * con_ip6_config is empty. */
	if (priv->con_ip6_config) {
		nm_ip6_config_merge (composite, priv->con_ip6_config, NM_IP_CONFIG_MERGE_DEFAULT,
		                     default_route_metric_penalty_get (self, AF_INET6));
	}

	if (commit) {
		nm_ip6_config_add_dependent_routes (composite,
		                                    nm_device_get_route_table (self, AF_INET6, TRUE),
		                                    nm_device_get_route_metric (self, AF_INET6));
	}

	/* Allow setting MTU etc */
	if (commit) {
		NMUtilsIPv6IfaceId iid;

		if (token && nm_utils_ipv6_interface_identifier_get_from_token (&iid, token)) {
			nm_platform_link_set_ipv6_token (nm_device_get_platform (self),
			                                 nm_device_get_ip_ifindex (self),
			                                 iid);
		}
	}

	success = nm_device_set_ip6_config (self, composite, commit);
	g_object_unref (composite);
	if (commit)
		priv->v6_commit_first_time = FALSE;
	return success;
}

static gboolean
dhcp6_lease_change (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMSettingsConnection *settings_connection;

	if (!applied_config_get_current (&priv->dhcp6.ip6_config)) {
		_LOGW (LOGD_DHCP6, "failed to get DHCPv6 config for rebind");
		return FALSE;
	}

	g_assert (priv->dhcp6.client);  /* sanity check */

	settings_connection = nm_device_get_settings_connection (self);
	g_assert (settings_connection);

	/* Apply the updated config */
	if (!ip6_config_merge_and_apply (self, TRUE)) {
		_LOGW (LOGD_DHCP6, "failed to update IPv6 config in response to DHCP event");
		return FALSE;
	}

	nm_dispatcher_call_device (NM_DISPATCHER_ACTION_DHCP6_CHANGE,
	                           self,
	                           NULL,
	                           NULL, NULL, NULL);

	nm_device_remove_pending_action (self, NM_PENDING_ACTION_DHCP6, FALSE);

	return TRUE;
}

static gboolean
dhcp6_restart_cb (gpointer user_data)
{
	NMDevice *self = user_data;
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	priv->dhcp6.restart_id = 0;

	if (!dhcp6_start (self, FALSE))
		dhcp_schedule_restart (self, AF_INET6, NULL);

	return FALSE;
}

static void
dhcp_schedule_restart (NMDevice *self,
                       int addr_family,
                       const char *reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint tries_left;
	char tries_str[255];

	nm_assert_addr_family (addr_family);

	tries_left =   (addr_family == AF_INET)
	             ? priv->dhcp4.num_tries_left
	             : priv->dhcp6.num_tries_left;

	_LOGI ((addr_family == AF_INET) ? LOGD_DHCP4 : LOGD_DHCP6,
	       "scheduling DHCPv%c restart in %u seconds%s%s%s%s",
	       nm_utils_addr_family_to_char (addr_family),
	       DHCP_RESTART_TIMEOUT,
	       (tries_left != DHCP_NUM_TRIES_MAX)
	         ? nm_sprintf_buf (tries_str, ", %u tries left", tries_left + 1)
	         : "",
	       NM_PRINT_FMT_QUOTED (reason, " (reason: ", reason, ")", ""));

	if (addr_family == AF_INET) {
		priv->dhcp4.restart_id = g_timeout_add_seconds (DHCP_RESTART_TIMEOUT,
		                                                dhcp4_restart_cb, self);
	} else {
		priv->dhcp6.restart_id = g_timeout_add_seconds (DHCP_RESTART_TIMEOUT,
		                                                dhcp6_restart_cb, self);
	}
}

static void
dhcp6_fail (NMDevice *self, gboolean timeout)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean is_dhcp_managed;

	_LOGD (LOGD_DHCP6, "DHCPv6 failed: timeout %d, num tries left %u",
           timeout, priv->dhcp6.num_tries_left);

	is_dhcp_managed = (priv->dhcp6.mode == NM_NDISC_DHCP_LEVEL_MANAGED);
	dhcp6_cleanup (self, CLEANUP_TYPE_DECONFIGURE, FALSE);

	if (is_dhcp_managed || priv->dhcp6.num_tries_left < DHCP_NUM_TRIES_MAX) {
		/* Don't fail if there are static addresses configured on
		 * the device, instead retry after some time.
		 */
		if (   priv->ip6_state == IP_DONE
		    && priv->con_ip6_config
		    && nm_ip6_config_get_num_addresses (priv->con_ip6_config)) {
			dhcp_schedule_restart (self, AF_INET6, "device has IP addresses");
			return;
		}

		if (   priv->dhcp6.num_tries_left == DHCP_NUM_TRIES_MAX
		    && (timeout || (priv->ip6_state == IP_CONF))
		    && !priv->dhcp6.was_active)
			nm_device_activate_schedule_ip6_config_timeout (self);
		else if (   priv->dhcp6.num_tries_left < DHCP_NUM_TRIES_MAX
		         || priv->ip6_state == IP_DONE
		         || priv->dhcp6.was_active) {
			/* Don't fail immediately when the lease expires but try to
			 * restart DHCP for a predefined number of times.
			 */
			if (priv->dhcp6.num_tries_left) {
				priv->dhcp6.num_tries_left--;
				dhcp_schedule_restart (self, AF_INET6, "lease expired");
			} else {
				nm_device_ip_method_failed (self, AF_INET6, NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED);
				/* We failed the ipv6 method but schedule again the retries if the ipv4 method is
				 * configured, keeping the connection up.
				 */
				if (nm_device_get_state (self) != NM_DEVICE_STATE_FAILED)
					dhcp_schedule_restart (self, AF_INET6, "renewal failed");
			}
		} else
			g_warn_if_reached ();
	} else {
		/* not a hard failure; just live with the RA info */
		if (priv->ip6_state == IP_CONF)
			nm_device_activate_schedule_ip6_config_result (self);
	}
}

static void
dhcp6_timeout (NMDevice *self, NMDhcpClient *client)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->dhcp6.mode == NM_NDISC_DHCP_LEVEL_MANAGED)
		dhcp6_fail (self, TRUE);
	else {
		/* not a hard failure; just live with the RA info */
		dhcp6_cleanup (self, CLEANUP_TYPE_DECONFIGURE, FALSE);
		if (priv->ip6_state == IP_CONF)
			nm_device_activate_schedule_ip6_config_result (self);
	}
}

static void
dhcp6_state_changed (NMDhcpClient *client,
                     NMDhcpState state,
                     NMIP6Config *ip6_config,
                     GHashTable *options,
                     const char *event_id,
                     gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_if_fail (nm_dhcp_client_get_addr_family (client) == AF_INET6);
	g_return_if_fail (!ip6_config || NM_IS_IP6_CONFIG (ip6_config));

	_LOGD (LOGD_DHCP6, "new DHCPv6 client state %d", state);

	switch (state) {
	case NM_DHCP_STATE_BOUND:
		/* If the server sends multiple IPv6 addresses, we receive a state
		 * changed event for each of them. Use the event ID to merge IPv6
		 * addresses from the same transaction into a single configuration.
		 */
		if (   ip6_config
		    && event_id
		    && priv->dhcp6.event_id
		    && !strcmp (event_id, priv->dhcp6.event_id)) {
			NMDedupMultiIter ipconf_iter;
			const NMPlatformIP6Address *a;

			nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, ip6_config, &a)
				applied_config_add_address (&priv->dhcp6.ip6_config, NM_PLATFORM_IP_ADDRESS_CAST (a));
		} else {
			g_clear_pointer (&priv->dhcp6.event_id, g_free);
			if (ip6_config) {
				applied_config_init (&priv->dhcp6.ip6_config, ip6_config);
				priv->dhcp6.event_id = g_strdup (event_id);
				nm_dhcp6_config_set_options (priv->dhcp6.config, options);
				_notify (self, PROP_DHCP6_CONFIG);
			} else
				applied_config_clear (&priv->dhcp6.ip6_config);
		}

		/* After long time we have been able to renew the lease:
		 * update the ip state
		 */
		if (priv->ip6_state == IP_FAIL)
			_set_ip_state (self, AF_INET6, IP_CONF);

		priv->dhcp6.num_tries_left = DHCP_NUM_TRIES_MAX;

		if (priv->ip6_state == IP_CONF) {
			if (!applied_config_get_current (&priv->dhcp6.ip6_config)) {
				nm_device_ip_method_failed (self, AF_INET6, NM_DEVICE_STATE_REASON_DHCP_FAILED);
				break;
			}
			nm_device_activate_schedule_ip6_config_result (self);
		} else if (priv->ip6_state == IP_DONE)
			if (!dhcp6_lease_change (self))
				dhcp6_fail (self, FALSE);
		break;
	case NM_DHCP_STATE_TIMEOUT:
		dhcp6_timeout (self, client);
		break;
	case NM_DHCP_STATE_EXPIRE:
		/* Ignore expiry before we even have a lease (NAK, old lease, etc) */
		if (priv->ip6_state != IP_CONF)
			dhcp6_fail (self, FALSE);
		break;
	case NM_DHCP_STATE_DONE:
		/* In IPv6 info-only mode, the client doesn't handle leases so it
		 * may exit right after getting a response from the server.  That's
		 * normal.  In that case we just ignore the exit.
		 */
		if (priv->dhcp6.mode == NM_NDISC_DHCP_LEVEL_OTHERCONF)
			break;
		/* fall through */
	case NM_DHCP_STATE_FAIL:
		dhcp6_fail (self, FALSE);
		break;
	default:
		break;
	}
}

static void
dhcp6_prefix_delegated (NMDhcpClient *client,
                        NMPlatformIP6Address *prefix,
                        gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	/* Just re-emit. The device just contributes the prefix to the
	 * pool in NMPolicy, which decides about subnet allocation
	 * on the shared devices. */
	g_signal_emit (self, signals[IP6_PREFIX_DELEGATED], 0, prefix);
}

static gboolean
dhcp6_start_with_link_ready (NMDevice *self, NMConnection *connection)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMSettingIPConfig *s_ip6;
	gs_unref_bytes GBytes *hwaddr = NULL;
	const NMPlatformIP6Address *ll_addr = NULL;

	g_assert (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip6);

	if (priv->ext_ip6_config_captured)
		ll_addr = nm_ip6_config_get_address_first_nontentative (priv->ext_ip6_config_captured, TRUE);

	if (!ll_addr) {
		_LOGW (LOGD_DHCP6, "can't start DHCPv6: no link-local address");
		return FALSE;
	}

	hwaddr = nm_platform_link_get_address_as_bytes (nm_device_get_platform (self),
	                                                nm_device_get_ip_ifindex (self));

	priv->dhcp6.client = nm_dhcp_manager_start_ip6 (nm_dhcp_manager_get (),
	                                                nm_device_get_multi_index (self),
	                                                nm_device_get_ip_iface (self),
	                                                nm_device_get_ip_ifindex (self),
	                                                hwaddr,
	                                                &ll_addr->address,
	                                                nm_connection_get_uuid (connection),
	                                                nm_device_get_route_table (self, AF_INET6, TRUE),
	                                                nm_device_get_route_metric (self, AF_INET6),
	                                                nm_setting_ip_config_get_dhcp_send_hostname (s_ip6),
	                                                nm_setting_ip_config_get_dhcp_hostname (s_ip6),
	                                                get_dhcp_timeout (self, AF_INET6),
	                                                priv->dhcp_anycast_address,
	                                                (priv->dhcp6.mode == NM_NDISC_DHCP_LEVEL_OTHERCONF) ? TRUE : FALSE,
	                                                nm_setting_ip6_config_get_ip6_privacy (NM_SETTING_IP6_CONFIG (s_ip6)),
	                                                priv->dhcp6.needed_prefixes);

	if (priv->dhcp6.client) {
		priv->dhcp6.state_sigid = g_signal_connect (priv->dhcp6.client,
		                                            NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED,
		                                            G_CALLBACK (dhcp6_state_changed),
		                                            self);
		priv->dhcp6.prefix_sigid = g_signal_connect (priv->dhcp6.client,
		                                             NM_DHCP_CLIENT_SIGNAL_PREFIX_DELEGATED,
		                                             G_CALLBACK (dhcp6_prefix_delegated),
		                                             self);
	}

	if (nm_device_sys_iface_state_is_external_or_assume (self))
		priv->dhcp6.was_active = TRUE;

	return !!priv->dhcp6.client;
}

static gboolean
dhcp6_start (NMDevice *self, gboolean wait_for_ll)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	NMSettingIPConfig *s_ip6;

	nm_dbus_object_clear_and_unexport (&priv->dhcp6.config);
	priv->dhcp6.config = nm_dhcp6_config_new ();

	nm_assert (!applied_config_get_current (&priv->dhcp6.ip6_config));
	applied_config_clear (&priv->dhcp6.ip6_config);
	g_clear_pointer (&priv->dhcp6.event_id, g_free);

	connection = nm_device_get_applied_connection (self);
	g_assert (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (!nm_setting_ip_config_get_may_fail (s_ip6) ||
	    !strcmp (nm_setting_ip_config_get_method (s_ip6), NM_SETTING_IP6_CONFIG_METHOD_DHCP))
		nm_device_add_pending_action (self, NM_PENDING_ACTION_DHCP6, TRUE);

	if (wait_for_ll) {
		NMActStageReturn ret;

		/* ensure link local is ready... */
		ret = linklocal6_start (self);
		if (ret == NM_ACT_STAGE_RETURN_POSTPONE) {
			/* success; wait for the LL address to show up */
			return TRUE;
		}

		/* success; already have the LL address; kick off DHCP */
		g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);
	}

	if (!dhcp6_start_with_link_ready (self, connection))
		return FALSE;

	return TRUE;
}

gboolean
nm_device_dhcp6_renew (NMDevice *self, gboolean release)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_val_if_fail (priv->dhcp6.client != NULL, FALSE);

	_LOGI (LOGD_DHCP6, "DHCPv6 lease renewal requested");

	/* Terminate old DHCP instance and release the old lease */
	dhcp6_cleanup (self, CLEANUP_TYPE_DECONFIGURE, release);

	/* Start DHCP again on the interface */
	return dhcp6_start (self, FALSE);
}

/*****************************************************************************/

/*
 * Called on the requesting interface when a subnet can't be obtained
 * from known prefixes for a newly active shared connection.
 */
void
nm_device_request_ip6_prefixes (NMDevice *self, int needed_prefixes)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->dhcp6.needed_prefixes = needed_prefixes;

	if (priv->dhcp6.client) {
		_LOGD (LOGD_IP6, "ipv6-pd: asking DHCPv6 for %d prefixes", needed_prefixes);
		nm_device_dhcp6_renew (self, FALSE);
	} else {
		_LOGI (LOGD_IP6, "ipv6-pd: device doesn't use DHCPv6, can't request prefixes");
	}
}

gboolean
nm_device_needs_ip6_subnet (NMDevice *self)
{
	return NM_DEVICE_GET_PRIVATE (self)->needs_ip6_subnet;
}

/*
 * Called on the ipv6.method=shared interface when a new subnet is allocated
 * or the prefix from which it is allocated is renewed.
 */
void
nm_device_use_ip6_subnet (NMDevice *self, const NMPlatformIP6Address *subnet)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMPlatformIP6Address address = *subnet;

	if (!applied_config_get_current (&priv->ac_ip6_config))
		applied_config_init_new (&priv->ac_ip6_config, self, AF_INET6);

	/* Assign a ::1 address in the subnet for us. */
	address.address.s6_addr32[3] |= htonl (1);
	applied_config_add_address (&priv->ac_ip6_config, NM_PLATFORM_IP_ADDRESS_CAST (&address));

	_LOGD (LOGD_IP6, "ipv6-pd: using %s address (preferred for %u seconds)",
	       nm_utils_inet6_ntop (&address.address, NULL),
	       subnet->preferred);

	/* This also updates the ndisc if there are actual changes. */
	if (!ip6_config_merge_and_apply (self, TRUE))
		_LOGW (LOGD_IP6, "ipv6-pd: failed applying IP6 config for connection sharing");
}

/*
 * Called whenever the policy picks a default IPv6 device.
 * The ipv6.method=shared devices just reuse its DNS configuration.
 */
void
nm_device_copy_ip6_dns_config (NMDevice *self, NMDevice *from_device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMIP6Config *from_config = NULL;
	guint i, len;

	if (applied_config_get_current (&priv->ac_ip6_config)) {
		applied_config_reset_nameservers (&priv->ac_ip6_config);
		applied_config_reset_searches (&priv->ac_ip6_config);
	} else
		applied_config_init_new (&priv->ac_ip6_config, self, AF_INET6);

	if (from_device)
		from_config = nm_device_get_ip6_config (from_device);
	if (!from_config)
		return;

	len = nm_ip6_config_get_num_nameservers (from_config);
	for (i = 0; i < len; i++) {
		applied_config_add_nameserver (&priv->ac_ip6_config,
		                               (const NMIPAddr *) nm_ip6_config_get_nameserver (from_config, i));
	}

	len = nm_ip6_config_get_num_searches (from_config);
	for (i = 0; i < len; i++) {
		applied_config_add_search (&priv->ac_ip6_config,
		                           nm_ip6_config_get_search (from_config, i));
	}

	if (!ip6_config_merge_and_apply (self, TRUE))
		_LOGW (LOGD_IP6, "ipv6-pd: failed applying DNS config for connection sharing");
}

/*****************************************************************************/

static void
linklocal6_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	nm_clear_g_source (&priv->linklocal6_timeout_id);
}

static void
linklocal6_failed (NMDevice *self)
{
	linklocal6_cleanup (self);
	nm_device_activate_schedule_ip6_config_timeout (self);
}

static gboolean
linklocal6_timeout_cb (gpointer user_data)
{
	NMDevice *self = user_data;

	_LOGD (LOGD_DEVICE, "linklocal6: waiting for link-local addresses failed due to timeout");
	linklocal6_failed (self);
	return G_SOURCE_REMOVE;
}

static void
linklocal6_complete (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	const char *method;

	g_assert (priv->linklocal6_timeout_id);
	g_assert (priv->ext_ip6_config_captured);
	g_assert (nm_ip6_config_get_address_first_nontentative (priv->ext_ip6_config_captured, TRUE));

	linklocal6_cleanup (self);

	connection = nm_device_get_applied_connection (self);
	g_assert (connection);

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);

	_LOGD (LOGD_DEVICE, "linklocal6: waiting for link-local addresses successful, continue with method %s", method);

	if (   strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0
	    || strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_SHARED) == 0) {
		if (!addrconf6_start_with_link_ready (self)) {
			/* Time out IPv6 instead of failing the entire activation */
			nm_device_activate_schedule_ip6_config_timeout (self);
		}
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP) == 0) {
		if (!dhcp6_start_with_link_ready (self, connection)) {
			/* Time out IPv6 instead of failing the entire activation */
			nm_device_activate_schedule_ip6_config_timeout (self);
		}
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0)
		nm_device_activate_schedule_ip6_config_result (self);
	else
		g_return_if_fail (FALSE);
}

static void
check_and_add_ipv6ll_addr (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	int ip_ifindex = nm_device_get_ip_ifindex (self);
	struct in6_addr lladdr;
	NMConnection *connection;
	NMSettingIP6Config *s_ip6 = NULL;
	GError *error = NULL;

	if (priv->nm_ipv6ll == FALSE)
		return;

	if (priv->ext_ip6_config_captured) {
		NMDedupMultiIter ipconf_iter;
		const NMPlatformIP6Address *addr;

		nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, priv->ext_ip6_config_captured, &addr) {
			if (   IN6_IS_ADDR_LINKLOCAL (&addr->address)
			    && !(addr->n_ifa_flags & IFA_F_DADFAILED)) {
				/* Already have an LL address, nothing to do */
				return;
			}
		}
	}

	memset (&lladdr, 0, sizeof (lladdr));
	lladdr.s6_addr16[0] = htons (0xfe80);

	connection = nm_device_get_applied_connection (self);
	if (connection)
		s_ip6 = NM_SETTING_IP6_CONFIG (nm_connection_get_setting_ip6_config (connection));

	if (s_ip6 && nm_setting_ip6_config_get_addr_gen_mode (s_ip6) == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY) {
		NMUtilsStableType stable_type;
		const char *stable_id;

		stable_id = _get_stable_id (self, connection, &stable_type);
		if (   !stable_id
		    || !nm_utils_ipv6_addr_set_stable_privacy (stable_type,
		                                               &lladdr,
		                                               nm_device_get_iface (self),
		                                               stable_id,
		                                               priv->linklocal6_dad_counter++,
		                                               &error)) {
			_LOGW (LOGD_IP6, "linklocal6: failed to generate an address: %s", error->message);
			g_clear_error (&error);
			linklocal6_failed (self);
			return;
		}
		_LOGD (LOGD_IP6, "linklocal6: using IPv6 stable-privacy addressing");
	} else {
		NMUtilsIPv6IfaceId iid;

		if (priv->linklocal6_timeout_id) {
			/* We already started and attempt to add a LL address. For the EUI-64
			 * mode we can't pick a new one, we'll just fail. */
			_LOGW (LOGD_IP6, "linklocal6: DAD failed for an EUI-64 address");
			linklocal6_failed (self);
			return;
		}

		if (!nm_device_get_ip_iface_identifier (self, &iid, TRUE)) {
			_LOGW (LOGD_IP6, "linklocal6: failed to get interface identifier; IPv6 cannot continue");
			return;
		}
		_LOGD (LOGD_IP6, "linklocal6: using EUI-64 identifier to generate IPv6LL address");

		nm_utils_ipv6_addr_set_interface_identifier (&lladdr, iid);
	}

	_LOGD (LOGD_IP6, "linklocal6: adding IPv6LL address %s", nm_utils_inet6_ntop (&lladdr, NULL));
	if (!nm_platform_ip6_address_add (nm_device_get_platform (self),
	                                  ip_ifindex,
	                                  lladdr,
	                                  64,
	                                  in6addr_any,
	                                  NM_PLATFORM_LIFETIME_PERMANENT,
	                                  NM_PLATFORM_LIFETIME_PERMANENT,
	                                  0)) {
		_LOGW (LOGD_IP6, "failed to add IPv6 link-local address %s",
		       nm_utils_inet6_ntop (&lladdr, NULL));
	}
}

static NMActStageReturn
linklocal6_start (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	const char *method;

	linklocal6_cleanup (self);

	if (   priv->ext_ip6_config_captured
	    && nm_ip6_config_get_address_first_nontentative (priv->ext_ip6_config_captured, TRUE))
		return NM_ACT_STAGE_RETURN_SUCCESS;

	connection = nm_device_get_applied_connection (self);
	g_assert (connection);

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
	_LOGD (LOGD_DEVICE, "linklocal6: starting IPv6 with method '%s', but the device has no link-local addresses configured. Wait.", method);

	check_and_add_ipv6ll_addr (self);

	/* Depending on the network and what the 'dad_transmits' and 'retrans_time_ms'
	 * sysctl values are, DAD for the IPv6LL address may take quite a while.
	 * FIXME: use dad/retrans sysctl values if they are higher than a minimum time.
	 * (rh #1101809)
	 */
	priv->linklocal6_timeout_id = g_timeout_add_seconds (15, linklocal6_timeout_cb, self);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/

gint64
nm_device_get_configured_mtu_from_connection_default (NMDevice *self,
                                                      const char *property_name)
{
	gs_free char *str = NULL;

	str = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA, property_name, self);
	return _nm_utils_ascii_str_to_int64 (str, 10, 0, G_MAXUINT32, -1);
}

guint32
nm_device_get_configured_mtu_for_wired (NMDevice *self, gboolean *out_is_user_config)
{
	NMConnection *connection;
	NMSettingWired *setting;
	gint64 mtu_default;
	guint32 mtu;

	nm_assert (NM_IS_DEVICE (self));
	nm_assert (out_is_user_config);

	connection = nm_device_get_applied_connection (self);
	if (!connection)
		g_return_val_if_reached (0);

	setting = nm_connection_get_setting_wired (connection);

	if (setting) {
		mtu = nm_setting_wired_get_mtu (setting);
		if (mtu) {
			*out_is_user_config = TRUE;
			return mtu;
		}
	}

	mtu_default = nm_device_get_configured_mtu_from_connection_default (self, "ethernet.mtu");
	if (mtu_default >= 0) {
		*out_is_user_config = TRUE;
		return (guint32) mtu_default;
	}

	*out_is_user_config = FALSE;
	return 0;
}

/*****************************************************************************/

static void
_set_mtu (NMDevice *self, guint32 mtu)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->mtu == mtu)
		return;

	priv->mtu = mtu;
	_notify (self, PROP_MTU);

	if (priv->master) {
		/* changing the MTU of a slave, might require the master to reset
		 * it's MTU. Note that the master usually cannot set a MTU larger
		 * then the slave's. Hence, when the slave increases the MTU,
		 * master might want to retry setting the MTU. */
		nm_device_commit_mtu (priv->master);
	}
}

static void
_commit_mtu (NMDevice *self, const NMIP4Config *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint32 ip6_mtu, ip6_mtu_orig;
	guint32 mtu_desired, mtu_desired_orig;
	guint32 mtu_plat;
	struct {
		gboolean initialized;
		guint32 value;
	} ip6_mtu_sysctl = { 0, };
	int ifindex;
	char sbuf[64], sbuf1[64], sbuf2[64];

	ifindex = nm_device_get_ip_ifindex (self);
	if (ifindex <= 0)
		return;

	if (nm_device_sys_iface_state_is_external_or_assume (self)) {
		/* for assumed connections we don't tamper with the MTU. */
		return;
	}

	{
		gboolean mtu_is_user_config = FALSE;
		guint32 mtu = 0;

		/* preferably, get the MTU from explict user-configuration.
		 * Only if that fails, look at the current @config (which contains
		 * MTUs from DHCP/PPP) or maybe fallback to a device-specific MTU. */

		if (NM_DEVICE_GET_CLASS (self)->get_configured_mtu)
			mtu = NM_DEVICE_GET_CLASS (self)->get_configured_mtu (self, &mtu_is_user_config);

		if (mtu_is_user_config)
			mtu_desired = mtu;
		else {
			if (config)
				mtu_desired = nm_ip4_config_get_mtu (config);
			else
				mtu_desired = 0;
			if (!mtu_desired && !priv->mtu_initialized) {
				/* there is no MTU specified, and this is the first commit of the MTU.
				 * Reset a per-device MTU default, as returned from get_configured_mtu().
				 *
				 * The device might choose not to return a default MTU via get_configured_mtu()
				 * to suppress this behavior. */
				mtu_desired = mtu;
			}
		}
	}

	if (mtu_desired && mtu_desired < 1280) {
		NMSettingIPConfig *s_ip6;

		s_ip6 = (NMSettingIPConfig *) nm_device_get_applied_setting (self, NM_TYPE_SETTING_IP6_CONFIG);
		if (   s_ip6
		    && !NM_IN_STRSET (nm_setting_ip_config_get_method (s_ip6),
		                      NM_SETTING_IP6_CONFIG_METHOD_IGNORE)) {
			/* the interface has IPv6 enabled. The MTU with IPv6 cannot be smaller
			 * then 1280.
			 *
			 * For slave-devices (that don't have @s_ip6 we) don't do this fixup because
			 * it's anyway an unsolved problem when the slave configures a conflicting
			 * MTU. */
			mtu_desired = 1280;
		}
	}

	ip6_mtu = priv->ip6_mtu;
	if (!ip6_mtu && !priv->mtu_initialized) {
		/* initially, if the IPv6 MTU is not specified, grow it as large as the
		 * link MTU @mtu_desired. Only exception is, if @mtu_desired is so small
		 * to disable IPv6. */
		if (mtu_desired >= 1280)
			ip6_mtu = mtu_desired;
	}

	priv->mtu_initialized = TRUE;

	if (!ip6_mtu && !mtu_desired)
		return;

	mtu_desired_orig = mtu_desired;
	ip6_mtu_orig = ip6_mtu;

	mtu_plat = nm_platform_link_get_mtu (nm_device_get_platform (self), ifindex);

	if (ip6_mtu) {
		ip6_mtu = NM_MAX (1280, ip6_mtu);

		if (!mtu_desired)
			mtu_desired = mtu_plat;

		if (mtu_desired) {
			mtu_desired = NM_MAX (1280, mtu_desired);

			if (mtu_desired < ip6_mtu)
				ip6_mtu = mtu_desired;
		}
	}

	_LOGT (LOGD_DEVICE, "mtu: device-mtu: %u%s, ipv6-mtu: %u%s, ifindex: %d",
	       (guint) mtu_desired,
	       mtu_desired == mtu_desired_orig ? "" : nm_sprintf_buf (sbuf1, " (was %u)", (guint) mtu_desired_orig),
	       (guint) ip6_mtu,
	       ip6_mtu == ip6_mtu_orig ? "" : nm_sprintf_buf (sbuf2, " (was %u)", (guint) ip6_mtu_orig),
	       ifindex);

#define _IP6_MTU_SYS() \
	({ \
		if (!ip6_mtu_sysctl.initialized) { \
			ip6_mtu_sysctl.value = nm_device_ipv6_sysctl_get_uint32 (self, "mtu", 0); \
			ip6_mtu_sysctl.initialized = TRUE; \
		} \
		ip6_mtu_sysctl.value; \
	})
	if (   (mtu_desired && mtu_desired != mtu_plat)
	    || (ip6_mtu && ip6_mtu != _IP6_MTU_SYS ())) {
		gboolean anticipated_failure = FALSE;

		if (!priv->mtu_initial && !priv->ip6_mtu_initial) {
			/* before touching any of the MTU parameters, record the
			 * original setting to restore on deactivation. */
			priv->mtu_initial = mtu_plat;
			priv->ip6_mtu_initial = _IP6_MTU_SYS ();
		}

		if (mtu_desired && mtu_desired != mtu_plat) {
			if (nm_platform_link_set_mtu (nm_device_get_platform (self), ifindex, mtu_desired) == NM_PLATFORM_ERROR_CANT_SET_MTU) {
				anticipated_failure = TRUE;
				_LOGW (LOGD_DEVICE, "mtu: failure to set MTU. %s",
				       NM_IS_DEVICE_VLAN (self)
				         ? "Is the parent's MTU size large enough?"
				         : (!c_list_is_empty (&priv->slaves)
				              ? "Are the MTU sizes of the slaves large enough?"
				              : "Did you configure the MTU correctly?"));
			}
			priv->carrier_wait_until_ms = nm_utils_get_monotonic_timestamp_ms () + CARRIER_WAIT_TIME_AFTER_MTU_MS;
		}

		if (ip6_mtu && ip6_mtu != _IP6_MTU_SYS ()) {
			if (!nm_device_ipv6_sysctl_set (self, "mtu",
			                                nm_sprintf_buf (sbuf, "%u", (unsigned) ip6_mtu))) {
				int errsv = errno;

				_NMLOG (anticipated_failure && errsv == EINVAL ? LOGL_DEBUG : LOGL_WARN,
				        LOGD_DEVICE,
				        "mtu: failure to set IPv6 MTU%s",
				        anticipated_failure && errsv == EINVAL
				           ? ": Is the underlying MTU value successfully set?"
				           : "");
			}
			priv->carrier_wait_until_ms = nm_utils_get_monotonic_timestamp_ms () + CARRIER_WAIT_TIME_AFTER_MTU_MS;
		}
	}
#undef _IP6_MTU_SYS
}

void
nm_device_commit_mtu (NMDevice *self)
{
	NMDeviceState state;

	g_return_if_fail (NM_IS_DEVICE (self));

	state = nm_device_get_state (self);
	if (   state >= NM_DEVICE_STATE_CONFIG
	    && state < NM_DEVICE_STATE_DEACTIVATING) {
		_LOGT (LOGD_DEVICE, "mtu: commit-mtu...");
		_commit_mtu (self, NM_DEVICE_GET_PRIVATE (self)->ip4_config);
	} else
		_LOGT (LOGD_DEVICE, "mtu: commit-mtu... skip due to state %s", nm_device_state_to_str (state));
}

static void
ndisc_config_changed (NMNDisc *ndisc, const NMNDiscData *rdata, guint changed_int, NMDevice *self)
{
	NMNDiscConfigMap changed = changed_int;
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint i;

	g_return_if_fail (priv->act_request);

	if (!applied_config_get_current (&priv->ac_ip6_config))
		applied_config_init_new (&priv->ac_ip6_config, self, AF_INET6);

	if (changed & NM_NDISC_CONFIG_ADDRESSES) {
		guint8 plen;
		guint32 ifa_flags;

		/* Check, whether kernel is recent enough to help user space handling RA.
		 * If it's not supported, we have no ipv6-privacy and must add autoconf
		 * addresses as /128. The reason for the /128 is to prevent the kernel
		 * from adding a prefix route for this address. */
		ifa_flags = 0;
		if (nm_platform_check_kernel_support (nm_device_get_platform (self),
		                                      NM_PLATFORM_KERNEL_SUPPORT_EXTENDED_IFA_FLAGS)) {
			ifa_flags |= IFA_F_NOPREFIXROUTE;
			if (NM_IN_SET (priv->ndisc_use_tempaddr, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR,
			                                         NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR))
				ifa_flags |= IFA_F_MANAGETEMPADDR;
			plen = 64;
		} else
			plen = 128;

		nm_ip6_config_reset_addresses_ndisc ((NMIP6Config *) priv->ac_ip6_config.orig,
		                                     rdata->addresses,
		                                     rdata->addresses_n,
		                                     plen,
		                                     ifa_flags);
		if (priv->ac_ip6_config.current) {
			nm_ip6_config_reset_addresses_ndisc ((NMIP6Config *) priv->ac_ip6_config.current,
			                                     rdata->addresses,
			                                     rdata->addresses_n,
			                                     plen,
			                                     ifa_flags);
		}
	}

	if (NM_FLAGS_ANY (changed,   NM_NDISC_CONFIG_ROUTES
	                           | NM_NDISC_CONFIG_GATEWAYS)) {
		nm_ip6_config_reset_routes_ndisc ((NMIP6Config *) priv->ac_ip6_config.orig,
		                                  rdata->gateways,
		                                  rdata->gateways_n,
		                                  rdata->routes,
		                                  rdata->routes_n,
		                                  nm_device_get_route_table (self, AF_INET6, TRUE),
		                                  nm_device_get_route_metric (self, AF_INET6),
		                                  nm_platform_check_kernel_support (nm_device_get_platform (self),
		                                                                    NM_PLATFORM_KERNEL_SUPPORT_RTA_PREF));
		if (priv->ac_ip6_config.current) {
			nm_ip6_config_reset_routes_ndisc ((NMIP6Config *) priv->ac_ip6_config.current,
			                                  rdata->gateways,
			                                  rdata->gateways_n,
			                                  rdata->routes,
			                                  rdata->routes_n,
			                                  nm_device_get_route_table (self, AF_INET6, TRUE),
			                                  nm_device_get_route_metric (self, AF_INET6),
			                                  nm_platform_check_kernel_support (nm_device_get_platform (self),
			                                                                    NM_PLATFORM_KERNEL_SUPPORT_RTA_PREF));
		}

	}

	if (changed & NM_NDISC_CONFIG_DNS_SERVERS) {
		/* Rebuild DNS server list from neighbor discovery cache. */
		applied_config_reset_nameservers (&priv->ac_ip6_config);

		for (i = 0; i < rdata->dns_servers_n; i++)
			applied_config_add_nameserver (&priv->ac_ip6_config, (const NMIPAddr *) &rdata->dns_servers[i].address);
	}

	if (changed & NM_NDISC_CONFIG_DNS_DOMAINS) {
		/* Rebuild domain list from neighbor discovery cache. */
		applied_config_reset_searches (&priv->ac_ip6_config);

		for (i = 0; i < rdata->dns_domains_n; i++)
			applied_config_add_search (&priv->ac_ip6_config, rdata->dns_domains[i].domain);
	}

	if (changed & NM_NDISC_CONFIG_DHCP_LEVEL) {
		dhcp6_cleanup (self, CLEANUP_TYPE_DECONFIGURE, TRUE);

		priv->dhcp6.mode = rdata->dhcp_level;
		if (priv->dhcp6.mode != NM_NDISC_DHCP_LEVEL_NONE) {
			_LOGD (LOGD_DEVICE | LOGD_DHCP6,
			       "Activation: Stage 3 of 5 (IP Configure Start) starting DHCPv6"
			       " as requested by IPv6 router...");
			if (!dhcp6_start (self, FALSE)) {
				if (priv->dhcp6.mode == NM_NDISC_DHCP_LEVEL_MANAGED) {
					nm_device_state_changed (self, NM_DEVICE_STATE_FAILED,
					                         NM_DEVICE_STATE_REASON_DHCP_START_FAILED);
					return;
				}
			}
		}
	}

	if (changed & NM_NDISC_CONFIG_HOP_LIMIT)
		nm_platform_sysctl_set_ip6_hop_limit_safe (nm_device_get_platform (self), nm_device_get_ip_iface (self), rdata->hop_limit);

	if (changed & NM_NDISC_CONFIG_MTU) {
		if (priv->ip6_mtu != rdata->mtu) {
			_LOGD (LOGD_DEVICE, "mtu: set IPv6 MTU to %u", (guint) rdata->mtu);
			priv->ip6_mtu = rdata->mtu;
		}
	}

	nm_device_activate_schedule_ip6_config_result (self);
}

static void
ndisc_ra_timeout (NMNDisc *ndisc, NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	/* We don't want to stop listening for router advertisements completely,
	 * but instead let device activation continue activating.  If an RA
	 * shows up later, we'll use it as long as the device is not disconnected.
	 */

	_LOGD (LOGD_IP6, "timed out waiting for IPv6 router advertisement");
	if (priv->ip6_state == IP_CONF) {
		/* If RA is our only source of addressing information and we don't
		 * ever receive one, then time out IPv6.  But if there is other
		 * IPv6 configuration, like manual IPv6 addresses or external IPv6
		 * config, consider that sufficient for IPv6 success.
		 */
		if (   priv->ip6_config
		    && nm_ip6_config_get_address_first_nontentative (priv->ip6_config, FALSE))
			nm_device_activate_schedule_ip6_config_result (self);
		else
			nm_device_activate_schedule_ip6_config_timeout (self);
	}
}

static gboolean
addrconf6_start_with_link_ready (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMUtilsIPv6IfaceId iid;

	g_assert (priv->ndisc);

	if (nm_device_get_ip_iface_identifier (self, &iid, FALSE)) {
		_LOGD (LOGD_IP6, "addrconf6: using the device EUI-64 identifier");
		nm_ndisc_set_iid (priv->ndisc, iid);
	} else {
		/* Don't abort the addrconf at this point -- if ndisc needs the iid
		 * it will notice this itself. */
		_LOGI (LOGD_IP6, "addrconf6: no interface identifier; IPv6 adddress creation may fail");
	}

	/* Apply any manual configuration before starting RA */
	if (!ip6_config_merge_and_apply (self, TRUE)) {
		_LOGW (LOGD_IP6, "failed to apply manual IPv6 configuration");
		g_clear_object (&priv->con_ip6_config);
	}

	/* FIXME: These sysctls would probably be better set by the lndp ndisc itself. */
	switch (nm_ndisc_get_node_type (priv->ndisc)) {
	case NM_NDISC_NODE_TYPE_HOST:
		/* Accepting prefixes from discovered routers. */
		nm_device_ipv6_sysctl_set (self, "accept_ra", "1");
		nm_device_ipv6_sysctl_set (self, "accept_ra_defrtr", "0");
		nm_device_ipv6_sysctl_set (self, "accept_ra_pinfo", "0");
		nm_device_ipv6_sysctl_set (self, "accept_ra_rtr_pref", "0");
		break;
	case NM_NDISC_NODE_TYPE_ROUTER:
		/* We're the router. */
		nm_device_ipv6_sysctl_set (self, "forwarding", "1");
		nm_device_activate_schedule_ip6_config_result (self);
		priv->needs_ip6_subnet = TRUE;
		g_signal_emit (self, signals[IP6_SUBNET_NEEDED], 0);
		break;
	default:
		g_assert_not_reached ();
	}

	priv->ndisc_changed_id = g_signal_connect (priv->ndisc,
	                                           NM_NDISC_CONFIG_RECEIVED,
	                                           G_CALLBACK (ndisc_config_changed),
	                                           self);
	priv->ndisc_timeout_id = g_signal_connect (priv->ndisc,
	                                           NM_NDISC_RA_TIMEOUT,
	                                           G_CALLBACK (ndisc_ra_timeout),
	                                           self);

	ndisc_set_router_config (priv->ndisc, self);
	nm_ndisc_start (priv->ndisc);
	return TRUE;
}

static NMNDiscNodeType
ndisc_node_type (NMDevice *self)
{
	NMConnection *connection;

	connection = nm_device_get_applied_connection (self);
	g_assert (connection);

	if (strcmp (nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG),
	            NM_SETTING_IP4_CONFIG_METHOD_SHARED) == 0)
		return NM_NDISC_NODE_TYPE_ROUTER;
	else
		return NM_NDISC_NODE_TYPE_HOST;
}

static gboolean
addrconf6_start (NMDevice *self, NMSettingIP6ConfigPrivacy use_tempaddr)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	NMActStageReturn ret;
	NMSettingIP6Config *s_ip6 = NULL;
	GError *error = NULL;
	NMUtilsStableType stable_type;
	const char *stable_id;

	connection = nm_device_get_applied_connection (self);
	g_assert (connection);

	nm_assert (!applied_config_get_current (&priv->ac_ip6_config));
	applied_config_clear (&priv->ac_ip6_config);

	g_clear_pointer (&priv->rt6_temporary_not_available, g_hash_table_unref);
	nm_clear_g_source (&priv->rt6_temporary_not_available_id);

	s_ip6 = NM_SETTING_IP6_CONFIG (nm_connection_get_setting_ip6_config (connection));
	g_assert (s_ip6);

	stable_id = _get_stable_id (self, connection, &stable_type);
	g_assert (stable_id);
	priv->ndisc = nm_lndp_ndisc_new (nm_device_get_platform (self),
	                                 nm_device_get_ip_ifindex (self),
	                                 nm_device_get_ip_iface (self),
	                                 stable_type,
	                                 stable_id,
	                                 nm_setting_ip6_config_get_addr_gen_mode (s_ip6),
	                                 ndisc_node_type (self),
	                                 &error);
	if (!priv->ndisc) {
		_LOGE (LOGD_IP6, "addrconf6: failed to start neighbor discovery: %s", error->message);
		g_error_free (error);
		return FALSE;
	}

	priv->ndisc_use_tempaddr = use_tempaddr;

	if (   NM_IN_SET (use_tempaddr, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR)
	    && !nm_platform_check_kernel_support (nm_device_get_platform (self),
	                                          NM_PLATFORM_KERNEL_SUPPORT_EXTENDED_IFA_FLAGS)) {
		_LOGW (LOGD_IP6, "The kernel does not support extended IFA_FLAGS needed by NM for "
		                 "IPv6 private addresses. This feature is not available");
	}

	if (!nm_setting_ip_config_get_may_fail (nm_connection_get_setting_ip6_config (connection)))
		nm_device_add_pending_action (self, NM_PENDING_ACTION_AUTOCONF6, TRUE);

	/* ensure link local is ready... */
	ret = linklocal6_start (self);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE) {
		/* success; wait for the LL address to show up */
		return TRUE;
	}

	/* success; already have the LL address; kick off neighbor discovery */
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);
	return addrconf6_start_with_link_ready (self);
}

static void
addrconf6_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	nm_clear_g_signal_handler (priv->ndisc, &priv->ndisc_changed_id);
	nm_clear_g_signal_handler (priv->ndisc, &priv->ndisc_timeout_id);

	nm_device_remove_pending_action (self, NM_PENDING_ACTION_AUTOCONF6, FALSE);

	applied_config_clear (&priv->ac_ip6_config);
	g_clear_pointer (&priv->rt6_temporary_not_available, g_hash_table_unref);
	nm_clear_g_source (&priv->rt6_temporary_not_available_id);
	g_clear_object (&priv->ndisc);
}

/*****************************************************************************/

static const char *ip6_properties_to_save[] = {
	"accept_ra",
	"accept_ra_defrtr",
	"accept_ra_pinfo",
	"accept_ra_rtr_pref",
	"forwarding",
	"disable_ipv6",
	"hop_limit",
	"use_tempaddr",
};

static void
save_ip6_properties (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const char *ifname = nm_device_get_ip_iface (self);
	char *value;
	int i;

	g_hash_table_remove_all (priv->ip6_saved_properties);

	if (!nm_device_get_ip_ifindex (self))
		return;

	for (i = 0; i < G_N_ELEMENTS (ip6_properties_to_save); i++) {
		char buf[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];

		value = nm_platform_sysctl_get (nm_device_get_platform (self), NMP_SYSCTL_PATHID_ABSOLUTE (nm_utils_sysctl_ip_conf_path (AF_INET6, buf, ifname, ip6_properties_to_save[i])));
		if (value) {
			g_hash_table_insert (priv->ip6_saved_properties,
			                     (char *) ip6_properties_to_save[i],
			                     value);
		}
	}
}

static void
restore_ip6_properties (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init (&iter, priv->ip6_saved_properties);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		/* Don't touch "disable_ipv6" if we're doing userland IPv6LL */
		if (priv->nm_ipv6ll && strcmp (key, "disable_ipv6") == 0)
			continue;
		nm_device_ipv6_sysctl_set (self, key, value);
	}
}

static inline void
set_disable_ipv6 (NMDevice *self, const char *value)
{
	/* We only touch disable_ipv6 when NM is not managing the IPv6LL address */
	if (NM_DEVICE_GET_PRIVATE (self)->nm_ipv6ll == FALSE)
		nm_device_ipv6_sysctl_set (self, "disable_ipv6", value);
}

static inline void
set_nm_ipv6ll (NMDevice *self, gboolean enable)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	int ifindex = nm_device_get_ip_ifindex (self);
	char *value;

	if (!nm_platform_check_kernel_support (nm_device_get_platform (self),
	                                       NM_PLATFORM_KERNEL_SUPPORT_USER_IPV6LL))
		return;

	priv->nm_ipv6ll = enable;
	if (ifindex > 0) {
		NMPlatformError plerr;
		const char *detail = enable ? "enable" : "disable";

		_LOGD (LOGD_IP6, "will %s userland IPv6LL", detail);
		plerr = nm_platform_link_set_user_ipv6ll_enabled (nm_device_get_platform (self), ifindex, enable);
		if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
			_NMLOG (plerr == NM_PLATFORM_ERROR_NOT_FOUND ? LOGL_DEBUG : LOGL_WARN,
			        LOGD_IP6,
			        "failed to %s userspace IPv6LL address handling (%s)",
			        detail,
			        nm_platform_error_to_string_a (plerr));
		}

		if (enable) {
			char buf[NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE];

			/* Bounce IPv6 to ensure the kernel stops IPv6LL address generation */
			value = nm_platform_sysctl_get (nm_device_get_platform (self),
			                                NMP_SYSCTL_PATHID_ABSOLUTE (nm_utils_sysctl_ip_conf_path (AF_INET6, buf, nm_device_get_ip_iface (self), "disable_ipv6")));
			if (g_strcmp0 (value, "0") == 0)
				nm_device_ipv6_sysctl_set (self, "disable_ipv6", "1");
			g_free (value);

			/* Ensure IPv6 is enabled */
			nm_device_ipv6_sysctl_set (self, "disable_ipv6", "0");
		}

	}
}

/*****************************************************************************/

static NMSettingIP6ConfigPrivacy
_ip6_privacy_clamp (NMSettingIP6ConfigPrivacy use_tempaddr)
{
	switch (use_tempaddr) {
	case NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED:
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR:
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR:
		return use_tempaddr;
	default:
		return NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;
	}
}

static NMSettingIP6ConfigPrivacy
_ip6_privacy_get (NMDevice *self)
{
	NMSettingIP6ConfigPrivacy ip6_privacy;
	gs_free char *value = NULL;
	NMConnection *connection;

	g_return_val_if_fail (self, NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);

	/* 1.) First look at the per-connection setting. If it is not -1 (unknown),
	 * use it. */
	connection = nm_device_get_applied_connection (self);
	if (connection) {
		NMSettingIPConfig *s_ip6 = nm_connection_get_setting_ip6_config (connection);

		if (s_ip6) {
			ip6_privacy = nm_setting_ip6_config_get_ip6_privacy (NM_SETTING_IP6_CONFIG (s_ip6));
			ip6_privacy = _ip6_privacy_clamp (ip6_privacy);
			if (ip6_privacy != NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN)
				return ip6_privacy;
		}
	}

	value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
	                                               "ipv6.ip6-privacy", self);

	/* 2.) use the default value from the configuration. */
	ip6_privacy = _nm_utils_ascii_str_to_int64 (value, 10,
	                                            NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN,
	                                            NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR,
	                                            NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);
	if (ip6_privacy != NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN)
		return ip6_privacy;

	if (!nm_device_get_ip_ifindex (self))
		return NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;;

	/* 3.) No valid default-value configured. Fallback to reading sysctl.
	 *
	 * Instead of reading static config files in /etc, just read the current sysctl value.
	 * This works as NM only writes to "/proc/sys/net/ipv6/conf/IFNAME/use_tempaddr", but leaves
	 * the "default" entry untouched. */
	ip6_privacy = nm_platform_sysctl_get_int32 (nm_device_get_platform (self), NMP_SYSCTL_PATHID_ABSOLUTE ("/proc/sys/net/ipv6/conf/default/use_tempaddr"), NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);
	return _ip6_privacy_clamp (ip6_privacy);
}

/*****************************************************************************/

static gboolean
ip6_requires_slaves (NMConnection *connection)
{
	const char *method;

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);

	/* SLAAC, DHCP, and Link-Local depend on connectivity (and thus slaves)
	 * to complete addressing.  SLAAC and DHCP need a peer to provide a prefix.
	 */
	return    strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0
	       || strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP) == 0;
}

static NMActStageReturn
act_stage3_ip6_config_start (NMDevice *self,
                             NMIP6Config **out_config,
                             NMDeviceStateReason *out_failure_reason)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMConnection *connection;
	const char *method;
	NMSettingIP6ConfigPrivacy ip6_privacy = NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;
	const char *ip6_privacy_str = "0";

	connection = nm_device_get_applied_connection (self);
	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	if (   connection_ip6_method_requires_carrier (connection, NULL)
	    && nm_device_is_master (self)
	    && !priv->carrier) {
		_LOGI (LOGD_IP6 | LOGD_DEVICE,
		       "IPv6 config waiting until carrier is on");
		return NM_ACT_STAGE_RETURN_IP_WAIT;
	}

	if (nm_device_is_master (self) && ip6_requires_slaves (connection)) {
		/* If the master has no ready slaves, and depends on slaves for
		 * a successful IPv6 attempt, then postpone IPv6 addressing.
		 */
		if (!have_any_ready_slaves (self)) {
			_LOGI (LOGD_DEVICE | LOGD_IP6,
			       "IPv6 config waiting until slaves are ready");
			return NM_ACT_STAGE_RETURN_IP_WAIT;
		}
	}

	priv->dhcp6.mode = NM_NDISC_DHCP_LEVEL_NONE;
	priv->dhcp6.num_tries_left = DHCP_NUM_TRIES_MAX;

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);

	if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) == 0) {
		if (   !priv->master
		    && !nm_device_sys_iface_state_is_external (self)) {
			gboolean old_nm_ipv6ll = priv->nm_ipv6ll;

			/* When activating an IPv6 'ignore' connection we need to revert back
			 * to kernel IPv6LL, but the kernel won't actually assign an address
			 * to the interface until disable_ipv6 is bounced.
			 */
			set_nm_ipv6ll (self, FALSE);
			if (old_nm_ipv6ll == TRUE)
				nm_device_ipv6_sysctl_set (self, "disable_ipv6", "1");
			restore_ip6_properties (self);
		}
		return NM_ACT_STAGE_RETURN_IP_DONE;
	}

	/* Ensure the MTU makes sense. If it was below 1280 the kernel would not
	 * expose any ipv6 sysctls or allow presence of any addresses on the interface,
	 * including LL, which * would make it impossible to autoconfigure MTU to a
	 * correct value. */
	_commit_mtu (self, priv->ip4_config);

	/* Any method past this point requires an IPv6LL address. Use NM-controlled
	 * IPv6LL if this is not an assumed connection, since assumed connections
	 * will already have IPv6 set up.
	 */
	if (!nm_device_sys_iface_state_is_external_or_assume (self))
		set_nm_ipv6ll (self, TRUE);

	/* Re-enable IPv6 on the interface */
	set_disable_ipv6 (self, "0");

	/* Synchronize external IPv6 configuration with kernel, since
	 * linklocal6_start() uses the information there to determine if we can
	 * proceed with the selected method (SLAAC, DHCP, link-local).
	 */
	nm_platform_process_events (nm_device_get_platform (self));
	g_clear_object (&priv->ext_ip6_config_captured);
	priv->ext_ip6_config_captured = nm_ip6_config_capture (nm_device_get_multi_index (self),
	                                                       nm_device_get_platform (self),
	                                                       nm_device_get_ip_ifindex (self),
	                                                       FALSE,
	                                                       NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);

	ip6_privacy = _ip6_privacy_get (self);

	if (   strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0
	    || strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_SHARED) == 0) {
		if (!addrconf6_start (self, ip6_privacy)) {
			/* IPv6 might be disabled; allow IPv4 to proceed */
			ret = NM_ACT_STAGE_RETURN_IP_FAIL;
		} else
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL) == 0) {
		ret = linklocal6_start (self);
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP) == 0) {
		priv->dhcp6.mode = NM_NDISC_DHCP_LEVEL_MANAGED;
		if (!dhcp6_start (self, TRUE)) {
			/* IPv6 might be disabled; allow IPv4 to proceed */
			ret = NM_ACT_STAGE_RETURN_IP_FAIL;
		} else
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_MANUAL) == 0) {
		ret = NM_ACT_STAGE_RETURN_SUCCESS;
	} else
		_LOGW (LOGD_IP6, "unhandled IPv6 config method '%s'; will fail", method);

	if (   ret != NM_ACT_STAGE_RETURN_FAILURE
	    && !nm_device_sys_iface_state_is_external_or_assume (self)) {
		switch (ip6_privacy) {
		case NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN:
		case NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED:
			ip6_privacy_str = "0";
			break;
		case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR:
			ip6_privacy_str = "1";
			break;
		case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR:
			ip6_privacy_str = "2";
			break;
		}
		nm_device_ipv6_sysctl_set (self, "use_tempaddr", ip6_privacy_str);
	}

	return ret;
}

/**
 * nm_device_activate_stage3_ip4_start:
 * @self: the device
 *
 * Try starting IPv4 configuration.
 */
gboolean
nm_device_activate_stage3_ip4_start (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActStageReturn ret;
	NMDeviceStateReason failure_reason = NM_DEVICE_STATE_REASON_NONE;
	NMIP4Config *ip4_config = NULL;

	g_assert (priv->ip4_state == IP_WAIT);

	if (nm_device_sys_iface_state_is_external (self)) {
		_set_ip_state (self, AF_INET, IP_DONE);
		check_ip_state (self, FALSE, TRUE);
		return TRUE;
	}

	_set_ip_state (self, AF_INET, IP_CONF);
	ret = NM_DEVICE_GET_CLASS (self)->act_stage3_ip4_config_start (self, &ip4_config, &failure_reason);
	if (ret == NM_ACT_STAGE_RETURN_SUCCESS) {
		if (!ip4_config)
			ip4_config = _ip4_config_new (self);
		nm_device_activate_schedule_ip4_config_result (self, ip4_config);
		g_object_unref (ip4_config);
	} else if (ret == NM_ACT_STAGE_RETURN_IP_DONE) {
		_set_ip_state (self, AF_INET, IP_DONE);
		check_ip_state (self, FALSE, TRUE);
	} else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, failure_reason);
		return FALSE;
	} else if (ret == NM_ACT_STAGE_RETURN_IP_FAIL) {
		/* Activation not wanted */
		_set_ip_state (self, AF_INET, IP_FAIL);
	} else if (ret == NM_ACT_STAGE_RETURN_IP_WAIT) {
		/* Wait for something to try IP config again */
		_set_ip_state (self, AF_INET, IP_WAIT);
	} else
		g_assert (ret == NM_ACT_STAGE_RETURN_POSTPONE);

	return TRUE;
}

/**
 * nm_device_activate_stage3_ip6_start:
 * @self: the device
 *
 * Try starting IPv6 configuration.
 */
gboolean
nm_device_activate_stage3_ip6_start (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActStageReturn ret;
	NMDeviceStateReason failure_reason = NM_DEVICE_STATE_REASON_NONE;
	NMIP6Config *ip6_config = NULL;

	g_assert (priv->ip6_state == IP_WAIT);

	if (nm_device_sys_iface_state_is_external (self)) {
		_set_ip_state (self, AF_INET6, IP_DONE);
		check_ip_state (self, FALSE, TRUE);
		return TRUE;
	}

	_set_ip_state (self, AF_INET6, IP_CONF);
	ret = NM_DEVICE_GET_CLASS (self)->act_stage3_ip6_config_start (self, &ip6_config, &failure_reason);
	if (ret == NM_ACT_STAGE_RETURN_SUCCESS) {
		if (!ip6_config)
			ip6_config = _ip6_config_new (self);
		/* Here we get a static IPv6 config, like for Shared where it's
		 * autogenerated or from modems where it comes from ModemManager.
		 */
		nm_assert (!applied_config_get_current (&priv->ac_ip6_config));
		applied_config_init (&priv->ac_ip6_config, ip6_config);
		nm_device_activate_schedule_ip6_config_result (self);
	} else if (ret == NM_ACT_STAGE_RETURN_IP_DONE) {
		_set_ip_state (self, AF_INET6, IP_DONE);
		check_ip_state (self, FALSE, TRUE);
	} else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, failure_reason);
		return FALSE;
	} else if (ret == NM_ACT_STAGE_RETURN_IP_FAIL) {
		/* Activation not wanted */
		_set_ip_state (self, AF_INET6, IP_FAIL);
	} else if (ret == NM_ACT_STAGE_RETURN_IP_WAIT) {
		/* Wait for something to try IP config again */
		_set_ip_state (self, AF_INET6, IP_WAIT);
	} else
		g_assert (ret == NM_ACT_STAGE_RETURN_POSTPONE);

	return TRUE;
}

/*
 * activate_stage3_ip_config_start
 *
 * Begin automatic/manual IP configuration
 *
 */
static void
activate_stage3_ip_config_start (NMDevice *self)
{
	_set_ip_state (self, AF_INET, IP_WAIT);
	_set_ip_state (self, AF_INET6, IP_WAIT);

	_active_connection_set_state_flags (self,
	                                    NM_ACTIVATION_STATE_FLAG_LAYER2_READY);

	nm_device_state_changed (self, NM_DEVICE_STATE_IP_CONFIG, NM_DEVICE_STATE_REASON_NONE);

	/* Device should be up before we can do anything with it */
	if (!nm_platform_link_is_up (nm_device_get_platform (self), nm_device_get_ip_ifindex (self)))
		_LOGW (LOGD_DEVICE, "interface %s not up for IP configuration", nm_device_get_ip_iface (self));

	/* IPv4 */
	if (   nm_device_activate_ip4_state_in_wait (self)
	    && !nm_device_activate_stage3_ip4_start (self))
		return;

	/* IPv6 */
	if (   nm_device_activate_ip6_state_in_wait (self)
	    && !nm_device_activate_stage3_ip6_start (self))
		return;

	/* Proxy */
	nm_device_set_proxy_config (self, NULL);

	check_ip_state (self, TRUE, TRUE);
}

static void
fw_change_zone_cb (NMFirewallManager *firewall_manager,
                   NMFirewallManagerCallId call_id,
                   GError *error,
                   gpointer user_data)
{
	NMDevice *self = user_data;
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->fw_call != call_id)
		g_return_if_reached ();
	priv->fw_call = NULL;

	if (nm_utils_error_is_cancelled (error, FALSE))
		return;

	switch (priv->fw_state) {
	case FIREWALL_STATE_WAIT_STAGE_3:
		priv->fw_state = FIREWALL_STATE_INITIALIZED;
		nm_device_activate_schedule_stage3_ip_config_start (self);
		break;
	case FIREWALL_STATE_WAIT_IP_CONFIG:
		priv->fw_state = FIREWALL_STATE_INITIALIZED;
		if (priv->ip4_state == IP_DONE || priv->ip6_state == IP_DONE)
			nm_device_start_ip_check (self);
		break;
	case FIREWALL_STATE_INITIALIZED:
		break;
	default:
		g_return_if_reached ();
	}
}

static void
fw_change_zone (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *applied_connection;
	NMSettingConnection *s_con;

	nm_assert (priv->fw_state >= FIREWALL_STATE_INITIALIZED);

	applied_connection = nm_device_get_applied_connection (self);
	nm_assert (applied_connection);

	s_con = nm_connection_get_setting_connection (applied_connection);
	nm_assert (s_con);

	if (priv->fw_call) {
		nm_firewall_manager_cancel_call (priv->fw_call);
		nm_assert (!priv->fw_call);
	}

	if (G_UNLIKELY (!priv->fw_mgr))
		priv->fw_mgr = g_object_ref (nm_firewall_manager_get ());

	priv->fw_call = nm_firewall_manager_add_or_change_zone (priv->fw_mgr,
	                                                        nm_device_get_ip_iface (self),
	                                                        nm_setting_connection_get_zone (s_con),
	                                                        FALSE, /* change zone */
	                                                        fw_change_zone_cb,
	                                                        self);
}

/*
 * nm_device_activate_schedule_stage3_ip_config_start
 *
 * Schedule IP configuration start
 */
void
nm_device_activate_schedule_stage3_ip_config_start (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	/* Add the interface to the specified firewall zone */
	if (priv->fw_state == FIREWALL_STATE_UNMANAGED) {
		if (!nm_device_sys_iface_state_is_external (self)) {
			priv->fw_state = FIREWALL_STATE_WAIT_STAGE_3;
			fw_change_zone (self);
			return;
		}

		/* fake success. */
		priv->fw_state = FIREWALL_STATE_INITIALIZED;
	} else if (priv->fw_state == FIREWALL_STATE_WAIT_STAGE_3) {
		/* a firewall call for stage3 is pending. Return and wait. */
		return;
	}

	nm_assert (priv->fw_state == FIREWALL_STATE_INITIALIZED);

	activation_source_schedule (self, activate_stage3_ip_config_start, AF_INET);
}

static NMActStageReturn
act_stage4_ip4_config_timeout (NMDevice *self, NMDeviceStateReason *out_failure_reason)
{
	if (!get_ip_config_may_fail (self, AF_INET)) {
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

/*
 * nm_device_activate_stage4_ip4_config_timeout
 *
 * Time out on retrieving the IPv4 config.
 *
 */
static void
activate_stage4_ip4_config_timeout (NMDevice *self)
{
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMDeviceStateReason failure_reason = NM_DEVICE_STATE_REASON_NONE;

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_ip4_config_timeout (self, &failure_reason);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		return;
	else if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, failure_reason);
		return;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);

	_set_ip_state (self, AF_INET, IP_FAIL);

	check_ip_state (self, FALSE, TRUE);
}

/*
 * nm_device_activate_schedule_ip4_config_timeout
 *
 * Deal with a timeout of the IPv4 configuration
 *
 */
void
nm_device_activate_schedule_ip4_config_timeout (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	activation_source_schedule (self, activate_stage4_ip4_config_timeout, AF_INET);
}

static NMActStageReturn
act_stage4_ip6_config_timeout (NMDevice *self, NMDeviceStateReason *out_failure_reason)
{
	if (!get_ip_config_may_fail (self, AF_INET6)) {
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

/*
 * activate_stage4_ip6_config_timeout
 *
 * Time out on retrieving the IPv6 config.
 *
 */
static void
activate_stage4_ip6_config_timeout (NMDevice *self)
{
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	NMDeviceStateReason failure_reason = NM_DEVICE_STATE_REASON_NONE;

	ret = NM_DEVICE_GET_CLASS (self)->act_stage4_ip6_config_timeout (self, &failure_reason);
	if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
		return;
	if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
		nm_device_state_changed (self, NM_DEVICE_STATE_FAILED, failure_reason);
		return;
	}
	g_assert (ret == NM_ACT_STAGE_RETURN_SUCCESS);

	_set_ip_state (self, AF_INET6, IP_FAIL);

	check_ip_state (self, FALSE, TRUE);
}

/*
 * nm_device_activate_schedule_ip6_config_timeout
 *
 * Deal with a timeout of the IPv6 configuration
 *
 */
void
nm_device_activate_schedule_ip6_config_timeout (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	g_return_if_fail (priv->act_request);

	activation_source_schedule (self, activate_stage4_ip6_config_timeout, AF_INET6);
}

static gboolean
share_init (NMDevice *self, GError **error)
{
	char *modules[] = { "ip_tables", "iptable_nat", "nf_nat_ftp", "nf_nat_irc",
	                    "nf_nat_sip", "nf_nat_tftp", "nf_nat_pptp", "nf_nat_h323",
	                    NULL };
	char **iter;
	int errsv;

	if (nm_platform_sysctl_get_int32 (nm_device_get_platform (self), NMP_SYSCTL_PATHID_ABSOLUTE ("/proc/sys/net/ipv4/ip_forward"), -1) == 1) {
		/* nothing to do. */
	} else if (!nm_platform_sysctl_set (nm_device_get_platform (self), NMP_SYSCTL_PATHID_ABSOLUTE ("/proc/sys/net/ipv4/ip_forward"), "1")) {
		errsv = errno;
		_LOGD (LOGD_SHARING, "share: error enabling IPv4 forwarding: (%d) %s",
		       errsv, g_strerror (errsv));
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "cannot set ipv4/ip_forward: %s", g_strerror (errsv));
		return FALSE;
	}

	if (nm_platform_sysctl_get_int32 (nm_device_get_platform (self), NMP_SYSCTL_PATHID_ABSOLUTE ("/proc/sys/net/ipv4/ip_dynaddr"), -1) == 1) {
		/* nothing to do. */
	} else if (!nm_platform_sysctl_set (nm_device_get_platform (self), NMP_SYSCTL_PATHID_ABSOLUTE ("/proc/sys/net/ipv4/ip_dynaddr"), "1")) {
		errsv = errno;
		_LOGD (LOGD_SHARING, "share: error enabling dynamic addresses: (%d) %s",
		       errsv, strerror (errsv));
	}

	for (iter = modules; *iter; iter++)
		nm_utils_modprobe (NULL, FALSE, *iter, NULL);

	return TRUE;
}

#define add_share_rule(req, table, ...) \
	G_STMT_START { \
		char *_cmd = g_strdup_printf (__VA_ARGS__); \
		nm_act_request_add_share_rule (req, table, _cmd); \
		g_free (_cmd); \
	} G_STMT_END

static gboolean
start_sharing (NMDevice *self, NMIP4Config *config, GError **error)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActRequest *req;
	char str_addr[INET_ADDRSTRLEN];
	char str_mask[INET_ADDRSTRLEN];
	guint32 netmask, network;
	const NMPlatformIP4Address *ip4_addr = NULL;
	const char *ip_iface;
	GError *local = NULL;

	g_return_val_if_fail (config, FALSE);

	ip_iface = nm_device_get_ip_iface (self);
	if (!ip_iface) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "device has no ip interface");
		return FALSE;
	}

	ip4_addr = nm_ip4_config_get_first_address (config);
	if (!ip4_addr || !ip4_addr->address) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "could not determine IPv4 address");
		return FALSE;
	}

	if (!share_init (self, error))
		return FALSE;

	req = nm_device_get_act_request (self);
	g_assert (req);

	netmask = _nm_utils_ip4_prefix_to_netmask (ip4_addr->plen);
	nm_utils_inet4_ntop (netmask, str_mask);

	network = ip4_addr->address & netmask;
	nm_utils_inet4_ntop (network, str_addr);

	add_share_rule (req, "nat", "POSTROUTING --source %s/%s ! --destination %s/%s --jump MASQUERADE", str_addr, str_mask, str_addr, str_mask);
	add_share_rule (req, "filter", "FORWARD --destination %s/%s --out-interface %s --match state --state ESTABLISHED,RELATED --jump ACCEPT", str_addr, str_mask, ip_iface);
	add_share_rule (req, "filter", "FORWARD --source %s/%s --in-interface %s --jump ACCEPT", str_addr, str_mask, ip_iface);
	add_share_rule (req, "filter", "FORWARD --in-interface %s --out-interface %s --jump ACCEPT", ip_iface, ip_iface);
	add_share_rule (req, "filter", "FORWARD --out-interface %s --jump REJECT", ip_iface);
	add_share_rule (req, "filter", "FORWARD --in-interface %s --jump REJECT", ip_iface);
	add_share_rule (req, "filter", "INPUT --in-interface %s --protocol udp --destination-port 67 --jump ACCEPT", ip_iface);
	add_share_rule (req, "filter", "INPUT --in-interface %s --protocol tcp --destination-port 67 --jump ACCEPT", ip_iface);
	add_share_rule (req, "filter", "INPUT --in-interface %s --protocol udp --destination-port 53 --jump ACCEPT", ip_iface);
	add_share_rule (req, "filter", "INPUT --in-interface %s --protocol tcp --destination-port 53 --jump ACCEPT", ip_iface);

	nm_act_request_set_shared (req, TRUE);

	if (!nm_dnsmasq_manager_start (priv->dnsmasq_manager, config, &local)) {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "could not start dnsmasq due to %s", local->message);
		g_error_free (local);
		nm_act_request_set_shared (req, FALSE);
		return FALSE;
	}

	priv->dnsmasq_state_id = g_signal_connect (priv->dnsmasq_manager, NM_DNS_MASQ_MANAGER_STATE_CHANGED,
	                                           G_CALLBACK (dnsmasq_state_changed_cb),
	                                           self);
	return TRUE;
}

static void
arp_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->arping.announcing) {
		nm_arping_manager_destroy (priv->arping.announcing);
		priv->arping.announcing = NULL;
	}
}

static void
arp_announce (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	NMSettingIPConfig *s_ip4;
	guint num, i;
	const guint8 *hw_addr;
	size_t hw_addr_len = 0;

	arp_cleanup (self);

	hw_addr = nm_platform_link_get_address (nm_device_get_platform (self),
	                                        nm_device_get_ip_ifindex (self),
	                                        &hw_addr_len);

	if (!hw_addr_len || !hw_addr)
		return;

	/* We only care about manually-configured addresses; DHCP- and autoip-configured
	 * ones should already have been seen on the network at this point.
	 */
	connection = nm_device_get_applied_connection (self);
	if (!connection)
		return;
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4)
		return;
	num = nm_setting_ip_config_get_num_addresses (s_ip4);
	if (num == 0)
		return;

	priv->arping.announcing = nm_arping_manager_new (nm_device_get_ip_ifindex (self));

	for (i = 0; i < num; i++) {
		NMIPAddress *ip = nm_setting_ip_config_get_address (s_ip4, i);
		in_addr_t addr;

		if (inet_pton (AF_INET, nm_ip_address_get_address (ip), &addr) == 1)
			nm_arping_manager_add_address (priv->arping.announcing, addr);
		else
			g_warn_if_reached ();
	}

	nm_arping_manager_announce_addresses (priv->arping.announcing);
}

static void
activate_stage5_ip4_config_result (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActRequest *req;
	const char *method;
	NMConnection *connection;
	int ip_ifindex;

	req = nm_device_get_act_request (self);
	g_assert (req);
	connection = nm_act_request_get_applied_connection (req);
	g_assert (connection);

	/* Interface must be IFF_UP before IP config can be applied */
	ip_ifindex = nm_device_get_ip_ifindex (self);
	if (!nm_platform_link_is_up (nm_device_get_platform (self), ip_ifindex) && !nm_device_sys_iface_state_is_external_or_assume (self)) {
		nm_platform_link_set_up (nm_device_get_platform (self), ip_ifindex, NULL);
		if (!nm_platform_link_is_up (nm_device_get_platform (self), ip_ifindex))
			_LOGW (LOGD_DEVICE, "interface %s not up for IP configuration", nm_device_get_ip_iface (self));
	}

	if (!ip4_config_merge_and_apply (self, TRUE)) {
		_LOGD (LOGD_DEVICE | LOGD_IP4, "Activation: Stage 5 of 5 (IPv4 Commit) failed");
		nm_device_ip_method_failed (self, AF_INET, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
		return;
	}

	/* Start IPv4 sharing if we need it */
	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);

	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED) == 0) {
		gs_free_error GError *error = NULL;

		if (!start_sharing (self, priv->ip4_config, &error)) {
			_LOGW (LOGD_SHARING, "Activation: Stage 5 of 5 (IPv4 Commit) start sharing failed: %s", error->message);
			nm_device_ip_method_failed (self, AF_INET, NM_DEVICE_STATE_REASON_SHARED_START_FAILED);
			return;
		}
	}

	/* If IPv4 wasn't the first to complete, and DHCP was used, then ensure
	 * dispatcher scripts get the DHCP lease information.
	 */
	if (   priv->dhcp4.client
	    && nm_device_activate_ip4_state_in_conf (self)
	    && (nm_device_get_state (self) > NM_DEVICE_STATE_IP_CONFIG)) {
		nm_dispatcher_call_device (NM_DISPATCHER_ACTION_DHCP4_CHANGE,
		                           self,
		                           NULL,
		                           NULL, NULL, NULL);
	}

	arp_announce (self);

	nm_device_remove_pending_action (self, NM_PENDING_ACTION_DHCP4, FALSE);

	/* Enter the IP_CHECK state if this is the first method to complete */
	_set_ip_state (self, AF_INET, IP_DONE);
	check_ip_state (self, FALSE, TRUE);
}

void
nm_device_activate_schedule_ip4_config_result (NMDevice *self, NMIP4Config *config)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));
	priv = NM_DEVICE_GET_PRIVATE (self);

	applied_config_init (&priv->dev_ip4_config, config);
	activation_source_schedule (self, activate_stage5_ip4_config_result, AF_INET);
}

gboolean
nm_device_activate_ip4_state_in_conf (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);
	return NM_DEVICE_GET_PRIVATE (self)->ip4_state == IP_CONF;
}

gboolean
nm_device_activate_ip4_state_in_wait (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);
	return NM_DEVICE_GET_PRIVATE (self)->ip4_state == IP_WAIT;
}

gboolean
nm_device_activate_ip4_state_done (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);
	return NM_DEVICE_GET_PRIVATE (self)->ip4_state == IP_DONE;
}

/*
 * Returns a NMIP6Config containing NM-configured addresses which
 * have the tentative flag, or NULL if none is present.
 */
static NMIP6Config *
dad6_get_pending_addresses (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMIP6Config *confs[] = { (NMIP6Config *) applied_config_get_current (&priv->ac_ip6_config),
	                         (NMIP6Config *) applied_config_get_current (&priv->dhcp6.ip6_config),
	                         priv->con_ip6_config,
	                         (NMIP6Config *) applied_config_get_current (&priv->wwan_ip6_config) };
	const NMPlatformIP6Address *addr, *pl_addr;
	NMIP6Config *dad6_config = NULL;
	NMDedupMultiIter ipconf_iter;
	guint i;
	int ifindex;

	ifindex = nm_device_get_ip_ifindex (self);
	g_return_val_if_fail (ifindex > 0, NULL);

	/* We are interested only in addresses that we have explicitly configured,
	 * not in externally added ones.
	 */
	for (i = 0; i < G_N_ELEMENTS (confs); i++) {
		if (confs[i]) {

			nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, confs[i], &addr) {
				pl_addr = nm_platform_ip6_address_get (nm_device_get_platform (self),
				                                       ifindex,
				                                       addr->address);
				if (   pl_addr
				    && NM_FLAGS_HAS (pl_addr->n_ifa_flags, IFA_F_TENTATIVE)
				    && !NM_FLAGS_HAS (pl_addr->n_ifa_flags, IFA_F_DADFAILED)
				    && !NM_FLAGS_HAS (pl_addr->n_ifa_flags, IFA_F_OPTIMISTIC)) {
					_LOGt (LOGD_DEVICE, "IPv6 DAD: pending address %s",
					       nm_platform_ip6_address_to_string (pl_addr, NULL, 0));

					if (!dad6_config)
						dad6_config = _ip6_config_new (self);

					nm_ip6_config_add_address (dad6_config, pl_addr);
				}
			}
		}
	}

	return dad6_config;
}

static void
activate_stage5_ip6_config_commit (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMActRequest *req;
	const char *method;
	NMConnection *connection;
	int ip_ifindex;
	int errsv;

	req = nm_device_get_act_request (self);
	g_assert (req);
	connection = nm_act_request_get_applied_connection (req);
	g_assert (connection);

	/* Interface must be IFF_UP before IP config can be applied */
	ip_ifindex = nm_device_get_ip_ifindex (self);
	g_return_if_fail (ip_ifindex);

	if (!nm_platform_link_is_up (nm_device_get_platform (self), ip_ifindex) && !nm_device_sys_iface_state_is_external_or_assume (self)) {
		nm_platform_link_set_up (nm_device_get_platform (self), ip_ifindex, NULL);
		if (!nm_platform_link_is_up (nm_device_get_platform (self), ip_ifindex))
			_LOGW (LOGD_DEVICE, "interface %s not up for IP configuration", nm_device_get_ip_iface (self));
	}

	if (ip6_config_merge_and_apply (self, TRUE)) {
		if (   priv->dhcp6.mode != NM_NDISC_DHCP_LEVEL_NONE
		    && priv->ip6_state == IP_CONF) {
			if (applied_config_get_current (&priv->dhcp6.ip6_config)) {
				/* If IPv6 wasn't the first IP to complete, and DHCP was used,
				 * then ensure dispatcher scripts get the DHCP lease information.
				 */
				nm_dispatcher_call_device (NM_DISPATCHER_ACTION_DHCP6_CHANGE,
				                           self,
				                           NULL,
				                           NULL, NULL, NULL);
			} else {
				/* still waiting for first dhcp6 lease. */
				return;
			}
		}
		nm_device_remove_pending_action (self, NM_PENDING_ACTION_DHCP6, FALSE);
		nm_device_remove_pending_action (self, NM_PENDING_ACTION_AUTOCONF6, FALSE);

		/* Start IPv6 forwarding if we need it */
		method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);

		if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_SHARED) == 0) {
			if (!nm_platform_sysctl_set (nm_device_get_platform (self), NMP_SYSCTL_PATHID_ABSOLUTE ("/proc/sys/net/ipv6/conf/all/forwarding"), "1")) {
				errsv = errno;
				_LOGE (LOGD_SHARING, "share: error enabling IPv6 forwarding: (%d) %s", errsv, strerror (errsv));
				nm_device_ip_method_failed (self, AF_INET6, NM_DEVICE_STATE_REASON_SHARED_START_FAILED);
			}
		}

		/* Check if we have to wait for DAD */
		if (priv->ip6_state == IP_CONF && !priv->dad6_ip6_config) {
			if (!priv->carrier && priv->ignore_carrier && get_ip_config_may_fail (self, AF_INET6))
				_LOGI (LOGD_DEVICE | LOGD_IP6, "IPv6 DAD: carrier missing and ignored, not delaying activation");
			else
				priv->dad6_ip6_config = dad6_get_pending_addresses (self);

			if (priv->dad6_ip6_config) {
				_LOGD (LOGD_DEVICE | LOGD_IP6, "IPv6 DAD: awaiting termination");
			} else {
				_set_ip_state (self, AF_INET6, IP_DONE);
				check_ip_state (self, FALSE, TRUE);
			}
		}
	} else {
		_LOGW (LOGD_DEVICE | LOGD_IP6, "Activation: Stage 5 of 5 (IPv6 Commit) failed");
		nm_device_ip_method_failed (self, AF_INET6, NM_DEVICE_STATE_REASON_CONFIG_FAILED);
	}
}

void
nm_device_activate_schedule_ip6_config_result (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_if_fail (NM_IS_DEVICE (self));

	/* If IP had previously failed, move it back to IP_CONF since we
	 * clearly now have configuration.
	 */
	if (priv->ip6_state == IP_FAIL)
		_set_ip_state (self, AF_INET6, IP_CONF);

	activation_source_schedule (self, activate_stage5_ip6_config_commit, AF_INET6);
}

gboolean
nm_device_activate_ip6_state_in_conf (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);
	return NM_DEVICE_GET_PRIVATE (self)->ip6_state == IP_CONF;
}

gboolean
nm_device_activate_ip6_state_in_wait (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);
	return NM_DEVICE_GET_PRIVATE (self)->ip6_state == IP_WAIT;
}

gboolean
nm_device_activate_ip6_state_done (NMDevice *self)
{
	g_return_val_if_fail (self != NULL, FALSE);
	return NM_DEVICE_GET_PRIVATE (self)->ip6_state == IP_DONE;
}

/*****************************************************************************/

static void
act_request_set_cb (NMActRequest *act_request,
                    GParamSpec *pspec,
                    NMDevice *self)
{
	_notify (self, PROP_ACTIVE_CONNECTION);
}

static void
act_request_set (NMDevice *self, NMActRequest *act_request)
{
	NMDevicePrivate *priv;
	gs_unref_object NMActRequest *old_act_requst = NULL;

	nm_assert (NM_IS_DEVICE (self));
	nm_assert (!act_request || NM_IS_ACT_REQUEST (act_request));

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (   !priv->act_request_public
	    && priv->act_request == act_request)
		return;

	/* always clear the public flag. The few callers that set a new @act_request
	 * don't want that the property is public yet.  */
	priv->act_request_public = FALSE;

	nm_clear_g_signal_handler (priv->act_request, &priv->act_request_id);

	old_act_requst = priv->act_request;
	priv->act_request = nm_g_object_ref (act_request);

	if (act_request) {
		priv->act_request_id = g_signal_connect (act_request,
		                                         "notify::"NM_DBUS_OBJECT_PATH,
		                                         G_CALLBACK (act_request_set_cb),
		                                         self);

		switch (nm_active_connection_get_activation_type (NM_ACTIVE_CONNECTION (act_request))) {
		case NM_ACTIVATION_TYPE_EXTERNAL:
			break;
		case NM_ACTIVATION_TYPE_ASSUME:
			if (priv->sys_iface_state == NM_DEVICE_SYS_IFACE_STATE_EXTERNAL)
				nm_device_sys_iface_state_set (self, NM_DEVICE_SYS_IFACE_STATE_ASSUME);
			break;
		case NM_ACTIVATION_TYPE_MANAGED:
			if (NM_IN_SET_TYPED (NMDeviceSysIfaceState,
			                     priv->sys_iface_state,
			                     NM_DEVICE_SYS_IFACE_STATE_EXTERNAL,
			                     NM_DEVICE_SYS_IFACE_STATE_ASSUME))
				nm_device_sys_iface_state_set (self, NM_DEVICE_SYS_IFACE_STATE_MANAGED);
			break;
		}
	}

	_notify (self, PROP_ACTIVE_CONNECTION);
}

static void
dnsmasq_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (!priv->dnsmasq_manager)
		return;

	nm_clear_g_signal_handler (priv->dnsmasq_manager, &priv->dnsmasq_state_id);

	nm_dnsmasq_manager_stop (priv->dnsmasq_manager);
	g_object_unref (priv->dnsmasq_manager);
	priv->dnsmasq_manager = NULL;
}

static void
_update_ip4_address (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const NMPlatformIP4Address *address;

	g_return_if_fail (NM_IS_DEVICE (self));

	if (   priv->ip4_config
	    && ip_config_valid (priv->state)
	    && (address = nm_ip4_config_get_first_address (priv->ip4_config))) {
		if (address->address != priv->ip4_address) {
			priv->ip4_address = address->address;
			_notify (self, PROP_IP4_ADDRESS);
		}
	}
}

gboolean
nm_device_is_nm_owned (NMDevice *self)
{
	return NM_DEVICE_GET_PRIVATE (self)->nm_owned;
}

/*
 * delete_on_deactivate_link_delete
 *
 * Function will be queued with g_idle_add to call
 * nm_platform_link_delete for the underlying resources
 * of the device.
 */
static gboolean
delete_on_deactivate_link_delete (gpointer user_data)
{
	DeleteOnDeactivateData *data = user_data;
	NMDevice *self = data->device;

	_LOGD (LOGD_DEVICE, "delete_on_deactivate: cleanup and delete virtual link #%d (id=%u)",
	       data->ifindex, data->idle_add_id);

	if (data->device) {
		NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (data->device);
		gs_free_error GError *error = NULL;

		g_object_remove_weak_pointer (G_OBJECT (data->device), (void **) &data->device);
		priv->delete_on_deactivate_data = NULL;

		if (!nm_device_unrealize (data->device, TRUE, &error))
			_LOGD (LOGD_DEVICE, "delete_on_deactivate: unrealizing %d failed (%s)", data->ifindex, error->message);
	} else if (data->ifindex > 0)
		nm_platform_link_delete (nm_device_get_platform (self), data->ifindex);

	g_free (data);
	return FALSE;
}

static void
delete_on_deactivate_unschedule (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->delete_on_deactivate_data) {
		DeleteOnDeactivateData *data = priv->delete_on_deactivate_data;

		priv->delete_on_deactivate_data = NULL;

		g_source_remove (data->idle_add_id);
		g_object_remove_weak_pointer (G_OBJECT (self), (void **) &data->device);
		_LOGD (LOGD_DEVICE, "delete_on_deactivate: cancel cleanup and delete virtual link #%d (id=%u)",
		       data->ifindex, data->idle_add_id);
		g_free (data);
	}
}

static void
delete_on_deactivate_check_and_schedule (NMDevice *self, int ifindex)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	DeleteOnDeactivateData *data;

	if (!priv->nm_owned)
		return;
	if (priv->queued_act_request)
		return;
	if (!nm_device_is_software (self) || !nm_device_is_real (self))
		return;
	if (nm_device_get_state (self) == NM_DEVICE_STATE_UNMANAGED)
		return;
	if (nm_device_get_state (self) == NM_DEVICE_STATE_UNAVAILABLE)
		return;
	delete_on_deactivate_unschedule (self); /* always cancel and reschedule */

	data = g_new (DeleteOnDeactivateData, 1);
	g_object_add_weak_pointer (G_OBJECT (self), (void **) &data->device);
	data->device = self;
	data->ifindex = ifindex;
	data->idle_add_id = g_idle_add (delete_on_deactivate_link_delete, data);
	priv->delete_on_deactivate_data = data;

	_LOGD (LOGD_DEVICE, "delete_on_deactivate: schedule cleanup and delete virtual link #%d (id=%u)",
	       ifindex, data->idle_add_id);
}

static void
_cleanup_ip4_pre (NMDevice *self, CleanupType cleanup_type)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	_set_ip_state (self, AF_INET, IP_NONE);

	if (nm_clear_g_source (&priv->queued_ip4_config_id))
		_LOGD (LOGD_DEVICE, "clearing queued IP4 config change");
	priv->queued_ip4_config_pending = FALSE;

	dhcp4_cleanup (self, cleanup_type, FALSE);
	arp_cleanup (self);
	dnsmasq_cleanup (self);
	ipv4ll_cleanup (self);
}

static void
_cleanup_ip6_pre (NMDevice *self, CleanupType cleanup_type)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	_set_ip_state (self, AF_INET6, IP_NONE);

	if (nm_clear_g_source (&priv->queued_ip6_config_id))
		_LOGD (LOGD_DEVICE, "clearing queued IP6 config change");
	priv->queued_ip6_config_pending = FALSE;

	g_clear_object (&priv->dad6_ip6_config);
	dhcp6_cleanup (self, cleanup_type, FALSE);
	linklocal6_cleanup (self);
	addrconf6_cleanup (self);
}

gboolean
_nm_device_hash_check_invalid_keys (GHashTable *hash, const char *setting_name,
                                    GError **error, const char **argv)
{
	guint found_keys = 0;
	guint i;

	nm_assert (hash && g_hash_table_size (hash) > 0);
	nm_assert (argv && argv[0]);

#if NM_MORE_ASSERTS > 10
	/* Assert that the keys are unique. */
	{
		gs_unref_hashtable GHashTable *check_dups = g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, NULL);

		for (i = 0; argv[i]; i++) {
			if (!g_hash_table_add (check_dups, (char *) argv[i]))
				nm_assert (FALSE);
		}
		nm_assert (g_hash_table_size (check_dups) > 0);
	}
#endif

	for (i = 0; argv[i]; i++) {
		if (g_hash_table_contains (hash, argv[i]))
			found_keys++;
	}

	if (found_keys != g_hash_table_size (hash)) {
		GHashTableIter iter;
		const char *k = NULL;
		const char *first_invalid_key = NULL;

		if (!error)
			return FALSE;

		g_hash_table_iter_init (&iter, hash);
		while (g_hash_table_iter_next (&iter, (gpointer *) &k, NULL)) {
			if (nm_utils_strv_find_first ((char **) argv, -1, k) < 0) {
				first_invalid_key = k;
				break;
			}
		}
		if (setting_name) {
			g_set_error (error,
			             NM_DEVICE_ERROR,
			             NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			             "Can't reapply changes to '%s.%s' setting",
			             setting_name,
			             first_invalid_key);
		} else {
			g_set_error (error,
			             NM_DEVICE_ERROR,
			             NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			             "Can't reapply any changes to '%s' setting",
			             first_invalid_key);
		}
		g_return_val_if_fail (first_invalid_key, FALSE);
		return FALSE;
	}

	return TRUE;
}

void
nm_device_reactivate_ip4_config (NMDevice *self,
                                 NMSettingIPConfig *s_ip4_old,
                                 NMSettingIPConfig *s_ip4_new)
{
	NMDevicePrivate *priv;
	const char *method_old, *method_new;

	g_return_if_fail (NM_IS_DEVICE (self));
	priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->ip4_state != IP_NONE) {
		g_clear_object (&priv->con_ip4_config);
		g_clear_object (&priv->ext_ip4_config);
		g_clear_object (&priv->dev_ip4_config.current);
		g_clear_object (&priv->wwan_ip4_config.current);
		priv->con_ip4_config = _ip4_config_new (self);
		nm_ip4_config_merge_setting (priv->con_ip4_config,
		                             s_ip4_new,
		                             _get_mdns (self),
		                             nm_device_get_route_table (self, AF_INET, TRUE),
		                             nm_device_get_route_metric (self, AF_INET));

		method_old = s_ip4_old
		             ? nm_setting_ip_config_get_method (s_ip4_old)
		             : NM_SETTING_IP4_CONFIG_METHOD_DISABLED;
		method_new = s_ip4_new
		             ? nm_setting_ip_config_get_method (s_ip4_new)
		             : NM_SETTING_IP4_CONFIG_METHOD_DISABLED;

		if (!nm_streq0 (method_old, method_new)) {
			_cleanup_ip4_pre (self, CLEANUP_TYPE_DECONFIGURE);
			_set_ip_state (self, AF_INET, IP_WAIT);
			if (!nm_device_activate_stage3_ip4_start (self))
				_LOGW (LOGD_IP4, "Failed to apply IPv4 configuration");
		} else {
			if (!ip4_config_merge_and_apply (self, TRUE))
				_LOGW (LOGD_IP4, "Failed to reapply IPv4 configuration");
		}
	}
}

void
nm_device_reactivate_ip6_config (NMDevice *self,
                                 NMSettingIPConfig *s_ip6_old,
                                 NMSettingIPConfig *s_ip6_new)
{
	NMDevicePrivate *priv;
	const char *method_old, *method_new;

	g_return_if_fail (NM_IS_DEVICE (self));
	priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->ip6_state != IP_NONE) {
		g_clear_object (&priv->con_ip6_config);
		g_clear_object (&priv->ext_ip6_config);
		g_clear_object (&priv->ac_ip6_config.current);
		g_clear_object (&priv->dhcp6.ip6_config.current);
		g_clear_object (&priv->wwan_ip6_config.current);
		priv->con_ip6_config = _ip6_config_new (self);
		nm_ip6_config_merge_setting (priv->con_ip6_config,
		                             s_ip6_new,
		                             nm_device_get_route_table (self, AF_INET6, TRUE),
		                             nm_device_get_route_metric (self, AF_INET6));

		method_old = s_ip6_old
		             ? nm_setting_ip_config_get_method (s_ip6_old)
		             : NM_SETTING_IP6_CONFIG_METHOD_IGNORE;
		method_new = s_ip6_new
		             ? nm_setting_ip_config_get_method (s_ip6_new)
		             : NM_SETTING_IP6_CONFIG_METHOD_IGNORE;

		if (!nm_streq0 (method_old, method_new)) {
			_cleanup_ip6_pre (self, CLEANUP_TYPE_DECONFIGURE);
			_set_ip_state (self, AF_INET6, IP_WAIT);
			if (!nm_device_activate_stage3_ip6_start (self))
				_LOGW (LOGD_IP6, "Failed to apply IPv6 configuration");
		} else {
			if (!ip6_config_merge_and_apply (self, TRUE))
				_LOGW (LOGD_IP4, "Failed to reapply IPv6 configuration");
		}
	}
}

static void
_pacrunner_manager_send (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	nm_pacrunner_manager_remove_clear (priv->pacrunner_manager,
	                                   &priv->pacrunner_call_id);

	if (!priv->pacrunner_manager)
		priv->pacrunner_manager = g_object_ref (nm_pacrunner_manager_get ());

	priv->pacrunner_call_id = nm_pacrunner_manager_send (priv->pacrunner_manager,
	                                                     nm_device_get_ip_iface (self),
	                                                     priv->proxy_config,
	                                                     NULL,
	                                                     NULL);
}

static void
reactivate_proxy_config (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (!priv->pacrunner_call_id)
		return;
	nm_device_set_proxy_config (self, priv->dhcp4.pac_url);
	_pacrunner_manager_send (self);
}

static gboolean
can_reapply_change (NMDevice *self, const char *setting_name,
                    NMSetting *s_old, NMSetting *s_new,
                    GHashTable *diffs, GError **error)
{
	if (nm_streq (setting_name, NM_SETTING_CONNECTION_SETTING_NAME)) {
		/* Whitelist allowed properties from "connection" setting which are
		 * allowed to differ.
		 *
		 * This includes UUID, there is no principal problem with reapplying a
		 * connection and changing it's UUID. In fact, disallowing it makes it
		 * cumbersome for the user to reapply any connection but the original
		 * settings-connection. */
		return nm_device_hash_check_invalid_keys (diffs,
		                                          NM_SETTING_CONNECTION_SETTING_NAME,
		                                          error,
		                                          NM_SETTING_CONNECTION_ID,
		                                          NM_SETTING_CONNECTION_UUID,
		                                          NM_SETTING_CONNECTION_STABLE_ID,
		                                          NM_SETTING_CONNECTION_AUTOCONNECT,
		                                          NM_SETTING_CONNECTION_ZONE,
		                                          NM_SETTING_CONNECTION_METERED,
		                                          NM_SETTING_CONNECTION_LLDP);
	} else if (NM_IN_STRSET (setting_name,
	                         NM_SETTING_IP4_CONFIG_SETTING_NAME,
	                         NM_SETTING_IP6_CONFIG_SETTING_NAME,
	                         NM_SETTING_PROXY_SETTING_NAME)) {
		if (g_hash_table_contains (diffs, NM_SETTING_IP_CONFIG_ROUTE_TABLE)) {
			/* changing the route-table setting is complicated, because it affects
			 * how we sync the routes. Don't support changing it without full
			 * re-activation.
			 *
			 * The problem is really that changing the setting also affects the sync
			 * mode. So, switching from NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN to
			 * NM_IP_ROUTE_TABLE_SYNC_MODE_FULL would somehow require us to get rid
			 * of additional routes, but we don't know which routes were added by NM
			 * and which should be removed.
			 *
			 * Note how nm_device_get_route_table() caches the value for the duration of the
			 * activation. */
			g_set_error (error,
			             NM_DEVICE_ERROR,
			             NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			             "Can't reapply changes to '%s.%s' setting",
			             setting_name,
			             NM_SETTING_IP_CONFIG_ROUTE_TABLE);
			return FALSE;
		}
		return TRUE;
	} else {
		g_set_error (error,
		             NM_DEVICE_ERROR,
		             NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		             "Can't reapply any changes to '%s' setting",
		             setting_name);
		return FALSE;
	}
}

static void
reapply_connection (NMDevice *self, NMConnection *con_old, NMConnection *con_new)
{

}

/* check_and_reapply_connection:
 * @connection: the new connection settings to be applied or %NULL to reapply
 *   the current settings connection
 * @version_id: either zero, or the current version id for the applied
 *   connection.
 * @audit_args: on return, a string representing the changes
 * @error: the error if %FALSE is returned
 *
 * Change configuration of an already configured device if possible.
 * Updates the device's applied connection upon success.
 *
 * Return: %FALSE if the new configuration can not be reapplied.
 */
static gboolean
check_and_reapply_connection (NMDevice *self,
                              NMConnection *connection,
                              guint64 version_id,
                              char **audit_args,
                              GError **error)
{
	NMDeviceClass *klass = NM_DEVICE_GET_CLASS (self);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *applied = nm_device_get_applied_connection (self);
	gs_unref_object NMConnection *applied_clone = NULL;
	gs_unref_hashtable GHashTable *diffs = NULL;
	NMConnection *con_old, *con_new;
	NMSettingIPConfig *s_ip4_old, *s_ip4_new;
	NMSettingIPConfig *s_ip6_old, *s_ip6_new;
	GHashTableIter iter;

	if (priv->state != NM_DEVICE_STATE_ACTIVATED) {
		g_set_error_literal (error,
		                     NM_DEVICE_ERROR,
		                     NM_DEVICE_ERROR_NOT_ACTIVE,
		                     "Device is not activated");
		return FALSE;
	}

	nm_connection_diff (connection,
	                    applied,
	                    NM_SETTING_COMPARE_FLAG_IGNORE_TIMESTAMP |
	                    NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS,
	                    &diffs);

	if (audit_args) {
		if (diffs && nm_audit_manager_audit_enabled (nm_audit_manager_get ()))
			*audit_args = nm_utils_format_con_diff_for_audit (diffs);
		else
			*audit_args = NULL;
	}

	/**************************************************************************
	 * check for unsupported changes and reject to reapply
	 *************************************************************************/
	if (diffs) {
		char *setting_name;
		GHashTable *setting_diff;

		g_hash_table_iter_init (&iter, diffs);
		while (g_hash_table_iter_next (&iter, (gpointer *) &setting_name, (gpointer *) &setting_diff)) {
			if (!klass->can_reapply_change (self,
			                                setting_name,
			                                nm_connection_get_setting_by_name (applied, setting_name),
			                                nm_connection_get_setting_by_name (connection, setting_name),
			                                setting_diff,
			                                error))
				return FALSE;
		}
	}

	if (   version_id != 0
	    && version_id != nm_active_connection_version_id_get ((NMActiveConnection *) priv->act_request)) {
		g_set_error_literal (error,
		                     NM_DEVICE_ERROR,
		                     NM_DEVICE_ERROR_VERSION_ID_MISMATCH,
		                     "Reapply failed because device changed in the meantime and the version-id mismatches");
		return FALSE;
	}

	/**************************************************************************
	 * Update applied connection
	 *************************************************************************/

	if (diffs)
		nm_active_connection_version_id_bump ((NMActiveConnection *) priv->act_request);

	_LOGD (LOGD_DEVICE, "reapply (version-id %llu%s)",
	       (unsigned long long) nm_active_connection_version_id_get (((NMActiveConnection *) priv->act_request)),
	       diffs ? "" : " (unmodified)");

	if (diffs) {
		NMConnection *connection_clean = connection;
		gs_free NMConnection *connection_clean_free = NULL;

		{
			NMSettingConnection *s_con_a, *s_con_n;

			/* we allow re-applying a connection with differing ID, UUID, STABLE_ID and AUTOCONNECT.
			 * This is for convenience but these values are not actually changeable. So, check
			 * if they changed, and if the did revert to the original values. */
			s_con_a = nm_connection_get_setting_connection (applied);
			s_con_n = nm_connection_get_setting_connection (connection);

			if (   !nm_streq (nm_setting_connection_get_id (s_con_a), nm_setting_connection_get_id (s_con_n))
			    || !nm_streq (nm_setting_connection_get_uuid (s_con_a), nm_setting_connection_get_uuid (s_con_n))
			    || nm_setting_connection_get_autoconnect (s_con_a) != nm_setting_connection_get_autoconnect (s_con_n)
			    || !nm_streq0 (nm_setting_connection_get_stable_id (s_con_a), nm_setting_connection_get_stable_id (s_con_n))) {
				connection_clean_free = nm_simple_connection_new_clone (connection);
				connection_clean = connection_clean_free;
				s_con_n = nm_connection_get_setting_connection (connection);
				g_object_set (s_con_n,
				              NM_SETTING_CONNECTION_ID, nm_setting_connection_get_id (s_con_a),
				              NM_SETTING_CONNECTION_UUID, nm_setting_connection_get_uuid (s_con_a),
				              NM_SETTING_CONNECTION_AUTOCONNECT, nm_setting_connection_get_autoconnect (s_con_a),
				              NM_SETTING_CONNECTION_STABLE_ID, nm_setting_connection_get_stable_id (s_con_a),
				              NULL);
			}
		}

		con_old = applied_clone  = nm_simple_connection_new_clone (applied);
		con_new = applied;
		nm_connection_replace_settings_from_connection (applied, connection_clean);
		nm_connection_clear_secrets (applied);
	} else
		con_old = con_new = applied;

	priv->v4_commit_first_time = TRUE;
	priv->v6_commit_first_time = TRUE;

	/**************************************************************************
	 * Reapply changes
	 *************************************************************************/
	klass->reapply_connection (self, con_old, con_new);

	nm_device_update_firewall_zone (self);
	nm_device_update_metered (self);
	lldp_init (self, FALSE);

	s_ip4_old = nm_connection_get_setting_ip4_config (con_old);
	s_ip4_new = nm_connection_get_setting_ip4_config (con_new);
	s_ip6_old = nm_connection_get_setting_ip6_config (con_old);
	s_ip6_new = nm_connection_get_setting_ip6_config (con_new);

	nm_device_reactivate_ip4_config (self, s_ip4_old, s_ip4_new);
	nm_device_reactivate_ip6_config (self, s_ip6_old, s_ip6_new);

	reactivate_proxy_config (self);

	return TRUE;
}

gboolean
nm_device_reapply (NMDevice *self,
                   NMConnection *connection,
                   GError **error)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	return check_and_reapply_connection (self,
	                                     connection,
	                                     0,
	                                     NULL,
	                                     error);
}

typedef struct {
	NMConnection *connection;
	guint64 version_id;
} ReapplyData;

static void
reapply_cb (NMDevice *self,
            GDBusMethodInvocation *context,
            NMAuthSubject *subject,
            GError *error,
            gpointer user_data)
{
	ReapplyData *reapply_data = user_data;
	guint64 version_id = 0;
	gs_unref_object NMConnection *connection = NULL;
	GError *local = NULL;
	gs_free char *audit_args = NULL;

	if (reapply_data) {
		connection = reapply_data->connection;
		version_id = reapply_data->version_id;
		g_slice_free (ReapplyData, reapply_data);
	}

	if (error) {
		nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_REAPPLY, self, FALSE, NULL, subject, error->message);
		g_dbus_method_invocation_return_gerror (context, error);
		return;
	}

	if (nm_device_sys_iface_state_is_external (self))
		nm_device_sys_iface_state_set (self, NM_DEVICE_SYS_IFACE_STATE_MANAGED);

	if (!check_and_reapply_connection (self,
	                                   connection ? : (NMConnection *) nm_device_get_settings_connection (self),
	                                   version_id,
	                                   &audit_args,
	                                   &local)) {
		nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_REAPPLY, self, FALSE, audit_args, subject, local->message);
		g_dbus_method_invocation_take_error (context, local);
		local = NULL;
	} else {
		nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_REAPPLY, self, TRUE, audit_args, subject, NULL);
		g_dbus_method_invocation_return_value (context, NULL);
	}
}

static void
impl_device_reapply (NMDBusObject *obj,
                     const NMDBusInterfaceInfoExtended *interface_info,
                     const NMDBusMethodInfoExtended *method_info,
                     GDBusConnection *dbus_connection,
                     const char *sender,
                     GDBusMethodInvocation *invocation,
                     GVariant *parameters)
{
	NMDevice *self = NM_DEVICE (obj);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMSettingsConnection *settings_connection;
	NMConnection *connection = NULL;
	GError *error = NULL;
	ReapplyData *reapply_data;
	gs_unref_variant GVariant *settings = NULL;
	guint64 version_id;
	guint32 flags;

	g_variant_get (parameters, "(@a{sa{sv}}tu)", &settings, &version_id, &flags);

	/* No flags supported as of now. */
	if (flags != 0) {
		error = g_error_new_literal (NM_DEVICE_ERROR,
		                             NM_DEVICE_ERROR_FAILED,
		                             "Invalid flags specified");
		nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_REAPPLY, self, FALSE, NULL, invocation, error->message);
		g_dbus_method_invocation_take_error (invocation, error);
		return;
	}

	if (priv->state != NM_DEVICE_STATE_ACTIVATED) {
		error = g_error_new_literal (NM_DEVICE_ERROR,
		                             NM_DEVICE_ERROR_NOT_ACTIVE,
		                             "Device is not activated");
		nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_REAPPLY, self, FALSE, NULL, invocation, error->message);
		g_dbus_method_invocation_take_error (invocation, error);
		return;
	}

	settings_connection = nm_device_get_settings_connection (self);
	g_return_if_fail (settings_connection);

	if (settings && g_variant_n_children (settings)) {
		/* New settings specified inline. */
		connection = _nm_simple_connection_new_from_dbus (settings,
		                                                    NM_SETTING_PARSE_FLAGS_STRICT
		                                                  | NM_SETTING_PARSE_FLAGS_NORMALIZE,
		                                                  &error);
		if (!connection) {
			g_prefix_error (&error, "The settings specified are invalid: ");
			nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_REAPPLY, self, FALSE, NULL, invocation, error->message);
			g_dbus_method_invocation_take_error (invocation, error);
			return;
		}
		nm_connection_clear_secrets (connection);
	}

	if (connection || version_id) {
		reapply_data = g_slice_new (ReapplyData);
		reapply_data->connection = connection;
		reapply_data->version_id = version_id;
	} else
		reapply_data = NULL;

	g_signal_emit (self, signals[AUTH_REQUEST], 0,
	               invocation,
	               nm_device_get_applied_connection (self),
	               NM_AUTH_PERMISSION_NETWORK_CONTROL,
	               TRUE,
	               reapply_cb,
	               reapply_data);
}

/*****************************************************************************/

static void
get_applied_connection_cb (NMDevice *self,
                           GDBusMethodInvocation *context,
                           NMAuthSubject *subject,
                           GError *error,
                           gpointer user_data /* possibly dangling pointer */)
{
	NMDevicePrivate *priv;
	NMConnection *applied_connection;
	GVariant *settings;

	g_return_if_fail (NM_IS_DEVICE (self));

	if (error) {
		g_dbus_method_invocation_return_gerror (context, error);
		return;
	}

	priv = NM_DEVICE_GET_PRIVATE (self);

	applied_connection = nm_device_get_applied_connection (self);

	if (!applied_connection) {
		error = g_error_new_literal (NM_DEVICE_ERROR,
		                             NM_DEVICE_ERROR_NOT_ACTIVE,
		                             "Device is not activated");
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	if (applied_connection != user_data) {
		/* The applied connection changed due to a race. Reauthenticate. */
		g_signal_emit (self, signals[AUTH_REQUEST], 0,
		               context,
		               applied_connection,
		               NM_AUTH_PERMISSION_NETWORK_CONTROL,
		               TRUE,
		               get_applied_connection_cb,
		               applied_connection /* no need take a ref. We will not dereference this pointer. */);
		return;
	}

	settings = nm_connection_to_dbus (applied_connection, NM_CONNECTION_SERIALIZE_NO_SECRETS);
	if (!settings)
		settings = g_variant_new_array (G_VARIANT_TYPE ("{sa{sv}}"), NULL, 0);

	g_dbus_method_invocation_return_value (context,
	                                       g_variant_new ("(@a{sa{sv}}t)",
	                                                      settings,
	                                                      nm_active_connection_version_id_get ((NMActiveConnection *) priv->act_request)));
}

static void
impl_device_get_applied_connection (NMDBusObject *obj,
                                    const NMDBusInterfaceInfoExtended *interface_info,
                                    const NMDBusMethodInfoExtended *method_info,
                                    GDBusConnection *connection,
                                    const char *sender,
                                    GDBusMethodInvocation *invocation,
                                    GVariant *parameters)
{
	NMDevice *self = NM_DEVICE (obj);
	NMConnection *applied_connection;
	guint32 flags;

	g_variant_get (parameters, "(u)", &flags);

	/* No flags supported as of now. */
	if (flags != 0) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_FAILED,
		                                               "Invalid flags specified");
		return;
	}

	applied_connection = nm_device_get_applied_connection (self);
	if (!applied_connection) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_NOT_ACTIVE,
		                                               "Device is not activated");
		return;
	}

	g_signal_emit (self, signals[AUTH_REQUEST], 0,
	               invocation,
	               applied_connection,
	               NM_AUTH_PERMISSION_NETWORK_CONTROL,
	               TRUE,
	               get_applied_connection_cb,
	               applied_connection /* no need take a ref. We will not dereference this pointer. */);
}

/*****************************************************************************/

typedef struct {
	gint64 timestamp_ms;
	bool dirty;
} IP6RoutesTemporaryNotAvailableData;

static gboolean
_rt6_temporary_not_available_timeout (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->rt6_temporary_not_available_id = 0;
	nm_device_activate_schedule_ip6_config_result (self);

	return G_SOURCE_REMOVE;
}

static gboolean
_rt6_temporary_not_available_set (NMDevice *self,
                                  GPtrArray *temporary_not_available)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	IP6RoutesTemporaryNotAvailableData *data;
	GHashTableIter iter;
	gint64 now_ms, oldest_ms;
	const gint64 MAX_AGE_MS = 20000;
	guint i;
	gboolean success = TRUE;

	if (   !temporary_not_available
	    || !temporary_not_available->len) {
		/* nothing outstanding. Clear tracking the routes. */
		g_clear_pointer (&priv->rt6_temporary_not_available, g_hash_table_unref);
		nm_clear_g_source (&priv->rt6_temporary_not_available_id);
		return success;
	}

	if (priv->rt6_temporary_not_available) {
		g_hash_table_iter_init (&iter, priv->rt6_temporary_not_available);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &data))
			data->dirty = TRUE;
	} else {
		priv->rt6_temporary_not_available = g_hash_table_new_full ((GHashFunc) nmp_object_id_hash,
		                                                           (GEqualFunc) nmp_object_id_equal,
		                                                           (GDestroyNotify) nmp_object_unref,
		                                                           nm_g_slice_free_fcn (IP6RoutesTemporaryNotAvailableData));
	}

	now_ms = nm_utils_get_monotonic_timestamp_ms ();
	oldest_ms = now_ms;

	for (i = 0; i < temporary_not_available->len; i++) {
		const NMPObject *o = temporary_not_available->pdata[i];

		data = g_hash_table_lookup (priv->rt6_temporary_not_available, o);
		if (data) {
			if (!data->dirty)
				continue;
			data->dirty = FALSE;
			nm_assert (data->timestamp_ms > 0 && data->timestamp_ms <= now_ms);
			if (now_ms > data->timestamp_ms + MAX_AGE_MS) {
				/* timeout. Could not add this address. */
				_LOGW (LOGD_DEVICE, "failure to add IPv6 route: %s",
				       nmp_object_to_string (o, NMP_OBJECT_TO_STRING_PUBLIC, NULL, 0));
				success = FALSE;
			} else
				oldest_ms = MIN (data->timestamp_ms, oldest_ms);
			continue;
		}

		data = g_slice_new0 (IP6RoutesTemporaryNotAvailableData);
		data->timestamp_ms = now_ms;
		g_hash_table_insert (priv->rt6_temporary_not_available, (gpointer) nmp_object_ref (o), data);
	}

	g_hash_table_iter_init (&iter, priv->rt6_temporary_not_available);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &data)) {
		if (data->dirty)
			g_hash_table_iter_remove (&iter);
	}

	nm_clear_g_source (&priv->rt6_temporary_not_available_id);
	priv->rt6_temporary_not_available_id = g_timeout_add (oldest_ms + MAX_AGE_MS - now_ms,
	                                                      _rt6_temporary_not_available_timeout,
	                                                      self);

	return success;
}

/*****************************************************************************/

static void
disconnect_cb (NMDevice *self,
               GDBusMethodInvocation *context,
               NMAuthSubject *subject,
               GError *error,
               gpointer user_data)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	GError *local = NULL;

	if (error) {
		g_dbus_method_invocation_return_gerror (context, error);
		nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_DISCONNECT, self, FALSE, NULL, subject, error->message);
		return;
	}

	/* Authorized */
	if (priv->state <= NM_DEVICE_STATE_DISCONNECTED) {
		local = g_error_new_literal (NM_DEVICE_ERROR,
		                             NM_DEVICE_ERROR_NOT_ACTIVE,
		                             "Device is not active");
		nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_DISCONNECT, self, FALSE, NULL, subject, local->message);
		g_dbus_method_invocation_take_error (context, local);
	} else {
		nm_device_autoconnect_blocked_set (self, NM_DEVICE_AUTOCONNECT_BLOCKED_MANUAL_DISCONNECT);

		nm_device_state_changed (self,
		                         NM_DEVICE_STATE_DEACTIVATING,
		                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
		g_dbus_method_invocation_return_value (context, NULL);
		nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_DISCONNECT, self, TRUE, NULL, subject, NULL);
	}
}

static void
_clear_queued_act_request (NMDevicePrivate *priv)
{
	if (priv->queued_act_request) {
		gs_unref_object NMActRequest *ac = NULL;

		ac = g_steal_pointer (&priv->queued_act_request);
		nm_active_connection_set_state_fail ((NMActiveConnection *) ac,
		                                     NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED,
		                                     NULL);
	}
}

static void
impl_device_disconnect (NMDBusObject *obj,
                        const NMDBusInterfaceInfoExtended *interface_info,
                        const NMDBusMethodInfoExtended *method_info,
                        GDBusConnection *dbus_connection,
                        const char *sender,
                        GDBusMethodInvocation *invocation,
                        GVariant *parameters)
{
	NMDevice *self = NM_DEVICE (obj);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;

	if (!priv->act_request) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_NOT_ACTIVE,
		                                               "This device is not active");
		return;
	}

	connection = nm_device_get_applied_connection (self);
	nm_assert (connection);

	g_signal_emit (self, signals[AUTH_REQUEST], 0,
	               invocation,
	               connection,
	               NM_AUTH_PERMISSION_NETWORK_CONTROL,
	               TRUE,
	               disconnect_cb,
	               NULL);
}

static void
delete_cb (NMDevice *self,
           GDBusMethodInvocation *context,
           NMAuthSubject *subject,
           GError *error,
           gpointer user_data)
{
	GError *local = NULL;

	if (error) {
		g_dbus_method_invocation_return_gerror (context, error);
		nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_DELETE, self, FALSE, NULL, subject, error->message);
		return;
	}

	/* Authorized */
	nm_audit_log_device_op (NM_AUDIT_OP_DEVICE_DELETE, self, TRUE, NULL, subject, NULL);
	if (nm_device_unrealize (self, TRUE, &local))
		g_dbus_method_invocation_return_value (context, NULL);
	else
		g_dbus_method_invocation_take_error (context, local);
}

static void
impl_device_delete (NMDBusObject *obj,
                    const NMDBusInterfaceInfoExtended *interface_info,
                    const NMDBusMethodInfoExtended *method_info,
                    GDBusConnection *connection,
                    const char *sender,
                    GDBusMethodInvocation *invocation,
                    GVariant *parameters)
{
	NMDevice *self = NM_DEVICE (obj);

	if (   !nm_device_is_software (self)
	    || !nm_device_is_real (self)) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_DEVICE_ERROR,
		                                               NM_DEVICE_ERROR_NOT_SOFTWARE,
		                                               "This device is not a software device or is not realized");
		return;
	}

	g_signal_emit (self, signals[AUTH_REQUEST], 0,
	               invocation,
	               NULL,
	               NM_AUTH_PERMISSION_NETWORK_CONTROL,
	               TRUE,
	               delete_cb,
	               NULL);
}

static void
_device_activate (NMDevice *self, NMActRequest *req)
{
	NMConnection *connection;

	g_return_if_fail (NM_IS_DEVICE (self));
	g_return_if_fail (NM_IS_ACT_REQUEST (req));
	nm_assert (nm_device_is_real (self));

	/* Ensure the activation request is still valid; the master may have
	 * already failed in which case activation of this device should not proceed.
	 */
	if (nm_active_connection_get_state (NM_ACTIVE_CONNECTION (req)) >= NM_ACTIVE_CONNECTION_STATE_DEACTIVATING)
		return;

	if (!nm_device_get_managed (self, FALSE)) {
		/* It's unclear why the device would be unmanaged at this point.
		 * Just to be sure, handle it and error out. */
		_LOGE (LOGD_DEVICE, "Activation: failed activating connection '%s' because device is still unmanaged",
		       nm_active_connection_get_settings_connection_id ((NMActiveConnection *) req));
		nm_active_connection_set_state_fail ((NMActiveConnection *) req,
		                                     NM_ACTIVE_CONNECTION_STATE_REASON_UNKNOWN,
		                                     NULL);
		return;
	}

	connection = nm_act_request_get_applied_connection (req);
	nm_assert (connection);

	_LOGI (LOGD_DEVICE, "Activation: starting connection '%s' (%s)",
	       nm_connection_get_id (connection),
	       nm_connection_get_uuid (connection));

	delete_on_deactivate_unschedule (self);

	act_request_set (self, req);

	nm_device_activate_schedule_stage1_device_prepare (self);
}

static void
_carrier_wait_check_queued_act_request (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (   !priv->queued_act_request
	    || !priv->queued_act_request_is_waiting_for_carrier)
		return;

	priv->queued_act_request_is_waiting_for_carrier = FALSE;
	if (!priv->carrier) {
		_LOGD (LOGD_DEVICE, "Cancel queued activation request as we have no carrier after timeout");
		_clear_queued_act_request (priv);
	} else {
		gs_unref_object NMActRequest *queued_req = NULL;

		_LOGD (LOGD_DEVICE, "Activate queued activation request as we now have carrier");
		queued_req = g_steal_pointer (&priv->queued_act_request);
		_device_activate (self, queued_req);
	}
}

static gboolean
_carrier_wait_check_act_request_must_queue (NMDevice *self, NMActRequest *req)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;

	/* If we have carrier or if we are not waiting for it, the activation
	 * request is not blocked waiting for carrier. */
	if (priv->carrier)
		return FALSE;
	if (priv->carrier_wait_id == 0)
		return FALSE;

	connection = nm_act_request_get_applied_connection (req);
	if (!connection_requires_carrier (connection))
		return FALSE;

	if (!nm_device_check_connection_available (self, connection, NM_DEVICE_CHECK_CON_AVAILABLE_ALL, NULL)) {
		/* We passed all @flags we have, and no @specific_object.
		 * This equals maximal availability, if a connection is not available
		 * in this case, it is not waiting for carrier.
		 *
		 * Actually, why are we even trying to activate it? Strange, but whatever
		 * the reason, don't wait for carrier.
		 */
		return FALSE;
	}

	if (nm_device_check_connection_available (self, connection, NM_DEVICE_CHECK_CON_AVAILABLE_ALL & ~_NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_WAITING_CARRIER, NULL)) {
		/* The connection was available with flags ALL, and it is still available
		 * if we pretend not to wait for carrier. That means that the
		 * connection is available now, and does not wait for carrier.
		 *
		 * Since the flags increase the availability of a connection, when checking
		 * ALL&~WAITING_CARRIER, it means that we certainly would wait for carrier. */
		return FALSE;
	}

	/* The activation request must wait for carrier. */
	return TRUE;
}

void
nm_device_steal_connection (NMDevice *self, NMSettingsConnection *connection)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	_LOGI (LOGD_DEVICE, "disconnecting connection '%s' for new activation request",
	       nm_settings_connection_get_id (connection));

	if (   priv->queued_act_request
	    && connection == nm_active_connection_get_settings_connection (NM_ACTIVE_CONNECTION (priv->queued_act_request)))
		_clear_queued_act_request (priv);

	if (   priv->act_request
	    && connection == nm_active_connection_get_settings_connection (NM_ACTIVE_CONNECTION (priv->act_request))
	    && priv->state < NM_DEVICE_STATE_DEACTIVATING) {
		nm_device_state_changed (self,
		                         NM_DEVICE_STATE_DEACTIVATING,
		                         NM_DEVICE_STATE_REASON_NEW_ACTIVATION);
	}
}

void
nm_device_queue_activation (NMDevice *self, NMActRequest *req)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean must_queue;

	must_queue = _carrier_wait_check_act_request_must_queue (self, req);

	if (   !priv->act_request
	    && !must_queue
	    && nm_device_is_real (self)) {
		_device_activate (self, req);
		return;
	}

	/* supercede any already-queued request */
	_clear_queued_act_request (priv);
	priv->queued_act_request = g_object_ref (req);
	priv->queued_act_request_is_waiting_for_carrier = must_queue;

	_LOGD (LOGD_DEVICE, "queue activation request waiting for %s", must_queue ? "carrier" : "currently active connection to disconnect");

	/* Deactivate existing activation request first */
	if (priv->act_request) {
		_LOGI (LOGD_DEVICE, "disconnecting for new activation request.");
		nm_device_state_changed (self,
		                         NM_DEVICE_STATE_DEACTIVATING,
		                         NM_DEVICE_STATE_REASON_NEW_ACTIVATION);
	}
}

/*
 * nm_device_is_activating
 *
 * Return whether or not the device is currently activating itself.
 *
 */
gboolean
nm_device_is_activating (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceState state;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	state = nm_device_get_state (self);
	if (state >= NM_DEVICE_STATE_PREPARE && state <= NM_DEVICE_STATE_SECONDARIES)
		return TRUE;

	/* There's a small race between the time when stage 1 is scheduled
	 * and when the device actually sets STATE_PREPARE when the activation
	 * handler is actually run.  If there's an activation handler scheduled
	 * we're activating anyway.
	 */
	return priv->act_handle4.id ? TRUE : FALSE;
}

NMProxyConfig *
nm_device_get_proxy_config (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->proxy_config;
}

static void
nm_device_set_proxy_config (NMDevice *self, const char *pac_url)
{
	NMDevicePrivate *priv;
	NMConnection *connection;
	NMSettingProxy *s_proxy = NULL;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);

	g_clear_object (&priv->proxy_config);
	priv->proxy_config = nm_proxy_config_new ();

	if (pac_url) {
		nm_proxy_config_set_method (priv->proxy_config, NM_PROXY_CONFIG_METHOD_AUTO);
		nm_proxy_config_set_pac_url (priv->proxy_config, pac_url);
		_LOGD (LOGD_PROXY, "proxy: PAC url \"%s\"", pac_url);
	} else
		nm_proxy_config_set_method (priv->proxy_config, NM_PROXY_CONFIG_METHOD_NONE);

	connection = nm_device_get_applied_connection (self);
	if (connection)
		s_proxy = nm_connection_get_setting_proxy (connection);

	if (s_proxy)
		nm_proxy_config_merge_setting (priv->proxy_config, s_proxy);
}

/* IP Configuration stuff */
NMDhcp4Config *
nm_device_get_dhcp4_config (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->dhcp4.config;
}

NMIP4Config *
nm_device_get_ip4_config (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->ip4_config;
}


static gboolean
nm_device_set_ip4_config (NMDevice *self,
                          NMIP4Config *new_config,
                          gboolean commit,
                          GPtrArray *ip4_dev_route_blacklist)
{
	NMDevicePrivate *priv;
	NMIP4Config *old_config = NULL;
	gboolean has_changes = FALSE;
	gboolean success = TRUE;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	_LOGD (LOGD_IP4, "ip4-config: update (commit=%d, new-config=%p)",
	       commit, new_config);

	nm_assert (   !new_config
	           || (   new_config
	               && ({
	                    int ip_ifindex = nm_device_get_ip_ifindex (self);

	                    (   ip_ifindex > 0
	                     && ip_ifindex == nm_ip4_config_get_ifindex (new_config));
	                  })));

	priv = NM_DEVICE_GET_PRIVATE (self);

	old_config = priv->ip4_config;

	/* Always commit to nm-platform to update lifetimes */
	if (commit && new_config) {
		_commit_mtu (self, new_config);
		success = nm_ip4_config_commit (new_config,
		                                nm_device_get_platform (self),
		                                nm_device_get_route_table (self, AF_INET, FALSE)
		                                  ? NM_IP_ROUTE_TABLE_SYNC_MODE_FULL
		                                  : NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN);
		nm_platform_ip4_dev_route_blacklist_set (nm_device_get_platform (self),
		                                         nm_ip4_config_get_ifindex (new_config),
		                                         ip4_dev_route_blacklist);
	}

	if (new_config) {
		if (old_config) {
			/* has_changes is set only on relevant changes, because when the configuration changes,
			 * this causes a re-read and reset. This should only happen for relevant changes */
			nm_ip4_config_replace (old_config, new_config, &has_changes);
			if (has_changes) {
				_LOGD (LOGD_IP4, "ip4-config: update IP4Config instance (%s)",
				       nm_dbus_object_get_path (NM_DBUS_OBJECT (old_config)));
			}
		} else {
			has_changes = TRUE;
			priv->ip4_config = g_object_ref (new_config);

			if (success && !nm_dbus_object_is_exported (NM_DBUS_OBJECT (new_config)))
				nm_dbus_object_export (NM_DBUS_OBJECT (new_config));

			_LOGD (LOGD_IP4, "ip4-config: set IP4Config instance (%s)",
			       nm_dbus_object_get_path (NM_DBUS_OBJECT (new_config)));
		}
	} else if (old_config) {
		has_changes = TRUE;
		priv->ip4_config = NULL;
		_LOGD (LOGD_IP4, "ip4-config: clear IP4Config instance (%s)",
		       nm_dbus_object_get_path (NM_DBUS_OBJECT (old_config)));
		/* Device config is invalid if combined config is invalid */
		applied_config_clear (&priv->dev_ip4_config);
	}

	concheck_periodic_update (self);

	if (!nm_device_sys_iface_state_is_external_or_assume (self))
		ip4_rp_filter_update (self);

	if (has_changes) {
		NMSettingsConnection *settings_connection;

		_update_ip4_address (self);

		if (old_config != priv->ip4_config)
			_notify (self, PROP_IP4_CONFIG);
		g_signal_emit (self, signals[IP4_CONFIG_CHANGED], 0, priv->ip4_config, old_config);

		if (old_config != priv->ip4_config)
			nm_dbus_object_clear_and_unexport (&old_config);

		if (   nm_device_sys_iface_state_is_external (self)
		    && (settings_connection = nm_device_get_settings_connection (self))
		    && NM_FLAGS_HAS (nm_settings_connection_get_flags (settings_connection),
		                     NM_SETTINGS_CONNECTION_FLAGS_NM_GENERATED)
		    && nm_active_connection_get_activation_type (NM_ACTIVE_CONNECTION (priv->act_request)) == NM_ACTIVATION_TYPE_EXTERNAL) {
			NMSetting *s_ip4;

			g_object_freeze_notify (G_OBJECT (settings_connection));

			nm_connection_remove_setting (NM_CONNECTION (settings_connection), NM_TYPE_SETTING_IP4_CONFIG);
			s_ip4 = nm_ip4_config_create_setting (priv->ip4_config);
			nm_connection_add_setting (NM_CONNECTION (settings_connection), s_ip4);

			g_object_thaw_notify (G_OBJECT (settings_connection));
		}

		nm_device_queue_recheck_assume (self);
	}

	return success;
}

static gboolean
_replace_vpn_config_in_list (GSList **plist, GObject *old, GObject *new)
{
	GSList *old_link;

	/* Below, assert that @new is not yet tracked, but still behave
	 * correctly in any case. Don't complain for missing @old since
	 * it could have been removed when the parent device became
	 * unmanaged. */

	if (   old
	    && (old_link = g_slist_find (*plist, old))) {
		if (old != new) {
			if (new)
				old_link->data = g_object_ref (new);
			else
				*plist = g_slist_delete_link (*plist, old_link);
			g_object_unref (old);
		}
		return TRUE;
	}

	if (new) {
		if (!g_slist_find (*plist, new))
			*plist = g_slist_append (*plist, g_object_ref (new));
		else
			g_return_val_if_reached (TRUE);
		return TRUE;
	}

	return FALSE;
}

void
nm_device_replace_vpn4_config (NMDevice *self, NMIP4Config *old, NMIP4Config *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	nm_assert (!old || NM_IS_IP4_CONFIG (old));
	nm_assert (!config || NM_IS_IP4_CONFIG (config));
	nm_assert (!old || nm_ip4_config_get_ifindex (old) == nm_device_get_ip_ifindex (self));
	nm_assert (!config || nm_ip4_config_get_ifindex (config) == nm_device_get_ip_ifindex (self));

	if (!_replace_vpn_config_in_list (&priv->vpn4_configs, (GObject *) old, (GObject *) config))
		return;

	/* NULL to use existing configs */
	if (!ip4_config_merge_and_apply (self, TRUE))
		_LOGW (LOGD_IP4, "failed to set VPN routes for device");
}

void
nm_device_set_wwan_ip4_config (NMDevice *self, NMIP4Config *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	applied_config_init (&priv->wwan_ip4_config, config);
	if (!ip4_config_merge_and_apply (self, TRUE))
		_LOGW (LOGD_IP4, "failed to set WWAN IPv4 configuration");
}

static gboolean
nm_device_set_ip6_config (NMDevice *self,
                          NMIP6Config *new_config,
                          gboolean commit)
{
	NMDevicePrivate *priv;
	NMIP6Config *old_config = NULL;
	gboolean has_changes = FALSE;
	gboolean success = TRUE;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	_LOGD (LOGD_IP6, "ip6-config: update (commit=%d, new-config=%p)",
	       commit, new_config);

	nm_assert (   !new_config
	           || (   new_config
	               && ({
	                    int ip_ifindex = nm_device_get_ip_ifindex (self);

	                    (   ip_ifindex > 0
	                     && ip_ifindex == nm_ip6_config_get_ifindex (new_config));
	                  })));

	priv = NM_DEVICE_GET_PRIVATE (self);

	old_config = priv->ip6_config;

	/* Always commit to nm-platform to update lifetimes */
	if (commit && new_config) {
		gs_unref_ptrarray GPtrArray *temporary_not_available = NULL;

		_commit_mtu (self, priv->ip4_config);

		success = nm_ip6_config_commit (new_config,
		                                nm_device_get_platform (self),
		                                nm_device_get_route_table (self, AF_INET6, FALSE)
		                                  ? NM_IP_ROUTE_TABLE_SYNC_MODE_FULL
		                                  : NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN,
		                                &temporary_not_available);

		if (!_rt6_temporary_not_available_set (self, temporary_not_available))
			success = FALSE;
	}

	if (new_config) {
		if (old_config) {
			/* has_changes is set only on relevant changes, because when the configuration changes,
			 * this causes a re-read and reset. This should only happen for relevant changes */
			nm_ip6_config_replace (old_config, new_config, &has_changes);
			if (has_changes) {
				_LOGD (LOGD_IP6, "ip6-config: update IP6Config instance (%s)",
				       nm_dbus_object_get_path (NM_DBUS_OBJECT (old_config)));
			}
		} else {
			has_changes = TRUE;
			priv->ip6_config = g_object_ref (new_config);

			if (success && !nm_dbus_object_is_exported (NM_DBUS_OBJECT (new_config)))
				nm_dbus_object_export (NM_DBUS_OBJECT (new_config));

			_LOGD (LOGD_IP6, "ip6-config: set IP6Config instance (%s)",
			       nm_dbus_object_get_path (NM_DBUS_OBJECT (new_config)));
		}
	} else if (old_config) {
		has_changes = TRUE;
		priv->ip6_config = NULL;
		priv->needs_ip6_subnet = FALSE;
		_LOGD (LOGD_IP6, "ip6-config: clear IP6Config instance (%s)",
		       nm_dbus_object_get_path (NM_DBUS_OBJECT (old_config)));
	}

	if (has_changes) {
		NMSettingsConnection *settings_connection;

		if (old_config != priv->ip6_config)
			_notify (self, PROP_IP6_CONFIG);
		g_signal_emit (self, signals[IP6_CONFIG_CHANGED], 0, priv->ip6_config, old_config);

		if (old_config != priv->ip6_config)
			nm_dbus_object_clear_and_unexport (&old_config);

		if (   nm_device_sys_iface_state_is_external (self)
		    && (settings_connection = nm_device_get_settings_connection (self))
		    && NM_FLAGS_HAS (nm_settings_connection_get_flags (settings_connection),
		                     NM_SETTINGS_CONNECTION_FLAGS_NM_GENERATED)
		    && nm_active_connection_get_activation_type (NM_ACTIVE_CONNECTION (priv->act_request)) == NM_ACTIVATION_TYPE_EXTERNAL) {
			NMSetting *s_ip6;

			g_object_freeze_notify (G_OBJECT (settings_connection));

			nm_connection_remove_setting (NM_CONNECTION (settings_connection), NM_TYPE_SETTING_IP6_CONFIG);
			s_ip6 = nm_ip6_config_create_setting (priv->ip6_config);
			nm_connection_add_setting (NM_CONNECTION (settings_connection), s_ip6);

			g_object_thaw_notify (G_OBJECT (settings_connection));
		}

		nm_device_queue_recheck_assume (self);

		if (priv->ndisc)
			ndisc_set_router_config (priv->ndisc, self);
	}

	return success;
}

void
nm_device_replace_vpn6_config (NMDevice *self, NMIP6Config *old, NMIP6Config *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	nm_assert (!old || NM_IS_IP6_CONFIG (old));
	nm_assert (!config || NM_IS_IP6_CONFIG (config));
	nm_assert (!old || nm_ip6_config_get_ifindex (old) == nm_device_get_ip_ifindex (self));
	nm_assert (!config || nm_ip6_config_get_ifindex (config) == nm_device_get_ip_ifindex (self));

	if (!_replace_vpn_config_in_list (&priv->vpn6_configs, (GObject *) old, (GObject *) config))
		return;

	/* NULL to use existing configs */
	if (!ip6_config_merge_and_apply (self, TRUE))
		_LOGW (LOGD_IP6, "failed to set VPN routes for device");
}

void
nm_device_set_wwan_ip6_config (NMDevice *self, NMIP6Config *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	applied_config_init (&priv->wwan_ip6_config, config);
	if (!ip6_config_merge_and_apply (self, TRUE))
		_LOGW (LOGD_IP6, "failed to set WWAN IPv6 configuration");
}

NMDhcp6Config *
nm_device_get_dhcp6_config (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->dhcp6.config;
}

NMIP6Config *
nm_device_get_ip6_config (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->ip6_config;
}

/*****************************************************************************/

static void
dispatcher_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->dispatcher.call_id) {
		nm_dispatcher_call_cancel (priv->dispatcher.call_id);
		priv->dispatcher.call_id = 0;
		priv->dispatcher.post_state = NM_DEVICE_STATE_UNKNOWN;
		priv->dispatcher.post_state_reason = NM_DEVICE_STATE_REASON_NONE;
	}
}

static void
dispatcher_complete_proceed_state (guint call_id, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_if_fail (call_id == priv->dispatcher.call_id);

	priv->dispatcher.call_id = 0;
	nm_device_queue_state (self, priv->dispatcher.post_state,
	                       priv->dispatcher.post_state_reason);
	priv->dispatcher.post_state = NM_DEVICE_STATE_UNKNOWN;
	priv->dispatcher.post_state_reason = NM_DEVICE_STATE_REASON_NONE;
}

/*****************************************************************************/

static void
ip_check_pre_up (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->dispatcher.call_id != 0) {
		g_warn_if_reached ();
		dispatcher_cleanup (self);
	}

	priv->dispatcher.post_state = NM_DEVICE_STATE_SECONDARIES;
	priv->dispatcher.post_state_reason = NM_DEVICE_STATE_REASON_NONE;
	if (!nm_dispatcher_call_device (NM_DISPATCHER_ACTION_PRE_UP,
	                                self,
	                                NULL,
	                                dispatcher_complete_proceed_state,
	                                self,
	                                &priv->dispatcher.call_id)) {
		/* Just proceed on errors */
		dispatcher_complete_proceed_state (0, self);
	}
}

static void
ip_check_gw_ping_cleanup (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	nm_clear_g_source (&priv->gw_ping.watch);
	nm_clear_g_source (&priv->gw_ping.timeout);

	if (priv->gw_ping.pid) {
		nm_utils_kill_child_async (priv->gw_ping.pid, SIGTERM, priv->gw_ping.log_domain, "ping", 1000, NULL, NULL);
		priv->gw_ping.pid = 0;
	}

	g_clear_pointer (&priv->gw_ping.binary, g_free);
	g_clear_pointer (&priv->gw_ping.address, g_free);
}

static gboolean
spawn_ping (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gs_free char *str_timeout = NULL;
	gs_free char *tmp_str = NULL;
	const char *args[] = { priv->gw_ping.binary, "-I", nm_device_get_ip_iface (self),
	                       "-c", "1", "-w", NULL, priv->gw_ping.address, NULL };
	gs_free_error GError *error = NULL;
	gboolean ret;

	args[6] = str_timeout = g_strdup_printf ("%u", priv->gw_ping.deadline);
	tmp_str = g_strjoinv (" ", (gchar **) args);
	_LOGD (priv->gw_ping.log_domain, "ping: running '%s'", tmp_str);

	ret = g_spawn_async ("/",
	                     (gchar **) args,
	                      NULL,
	                      G_SPAWN_DO_NOT_REAP_CHILD,
	                      NULL,
	                      NULL,
	                      &priv->gw_ping.pid,
	                      &error);

	if (!ret) {
		_LOGW (priv->gw_ping.log_domain, "ping: could not spawn %s: %s",
		       priv->gw_ping.binary, error->message);
	}

	return ret;
}

static gboolean
respawn_ping_cb (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->gw_ping.watch = 0;

	if (spawn_ping (self)) {
		priv->gw_ping.watch = g_child_watch_add (priv->gw_ping.pid,
		                                         ip_check_ping_watch_cb, self);
	} else {
		ip_check_gw_ping_cleanup (self);
		ip_check_pre_up (self);
	}

	return FALSE;
}

static void
ip_check_ping_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMLogDomain log_domain = priv->gw_ping.log_domain;
	gboolean success = FALSE;

	if (!priv->gw_ping.watch)
		return;
	priv->gw_ping.watch = 0;
	priv->gw_ping.pid = 0;

	if (WIFEXITED (status)) {
		if (WEXITSTATUS (status) == 0) {
			_LOGD (log_domain, "ping: gateway ping succeeded");
			success = TRUE;
		} else {
			_LOGW (log_domain, "ping: gateway ping failed with error code %d",
			       WEXITSTATUS (status));
		}
	} else
		_LOGW (log_domain, "ping: stopped unexpectedly with status %d", status);

	if (success) {
		/* We've got connectivity, proceed to pre_up */
		ip_check_gw_ping_cleanup (self);
		ip_check_pre_up (self);
	} else {
		/* If ping exited with an error it may have returned early,
		 * wait 1 second and restart it */
		priv->gw_ping.watch = g_timeout_add_seconds (1, respawn_ping_cb, self);
	}
}

static gboolean
ip_check_ping_timeout_cb (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->gw_ping.timeout = 0;

	_LOGW (priv->gw_ping.log_domain, "ping: gateway ping timed out");

	ip_check_gw_ping_cleanup (self);
	ip_check_pre_up (self);
	return FALSE;
}

static gboolean
start_ping (NMDevice *self,
            NMLogDomain log_domain,
            const char *binary,
            const char *address,
            guint timeout)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_return_val_if_fail (priv->gw_ping.watch == 0, FALSE);
	g_return_val_if_fail (priv->gw_ping.timeout == 0, FALSE);

	priv->gw_ping.log_domain = log_domain;
	priv->gw_ping.address = g_strdup (address);
	priv->gw_ping.binary = g_strdup (binary);
	priv->gw_ping.deadline = timeout + 10; /* the proper termination is enforced by a timer */

	if (spawn_ping (self)) {
		priv->gw_ping.watch = g_child_watch_add (priv->gw_ping.pid, ip_check_ping_watch_cb, self);
		priv->gw_ping.timeout = g_timeout_add_seconds (timeout, ip_check_ping_timeout_cb, self);
		return TRUE;
	}

	ip_check_gw_ping_cleanup (self);
	return FALSE;
}

static void
nm_device_start_ip_check (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMConnection *connection;
	NMSettingConnection *s_con;
	guint timeout = 0;
	const char *ping_binary = NULL;
	char buf[NM_UTILS_INET_ADDRSTRLEN];
	NMLogDomain log_domain = LOGD_IP4;

	/* Shouldn't be any active ping here, since IP_CHECK happens after the
	 * first IP method completes.  Any subsequently completing IP method doesn't
	 * get checked.
	 */
	g_return_if_fail (!priv->gw_ping.watch);
	g_return_if_fail (!priv->gw_ping.timeout);
	g_return_if_fail (!priv->gw_ping.pid);
	g_return_if_fail (priv->ip4_state == IP_DONE || priv->ip6_state == IP_DONE);

	connection = nm_device_get_applied_connection (self);
	g_assert (connection);

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	timeout = nm_setting_connection_get_gateway_ping_timeout (s_con);

	buf[0] = '\0';
	if (timeout) {
		const NMPObject *gw;

		if (priv->ip4_config && priv->ip4_state == IP_DONE) {
			gw = nm_ip4_config_best_default_route_get (priv->ip4_config);
			if (gw) {
				nm_utils_inet4_ntop (NMP_OBJECT_CAST_IP4_ROUTE (gw)->gateway, buf);
				ping_binary = nm_utils_find_helper ("ping", "/usr/bin/ping", NULL);
				log_domain = LOGD_IP4;
			}
		} else if (priv->ip6_config && priv->ip6_state == IP_DONE) {
			gw = nm_ip6_config_best_default_route_get (priv->ip6_config);
			if (gw) {
				nm_utils_inet6_ntop (&NMP_OBJECT_CAST_IP6_ROUTE (gw)->gateway, buf);
				ping_binary = nm_utils_find_helper ("ping6", "/usr/bin/ping6", NULL);
				log_domain = LOGD_IP6;
			}
		}
	}

	if (buf[0])
		start_ping (self, log_domain, ping_binary, buf, timeout);

	/* If no ping was started, just advance to pre_up */
	if (!priv->gw_ping.pid)
		ip_check_pre_up (self);
}

/*****************************************************************************/

static gboolean
carrier_wait_timeout (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->carrier_wait_id = 0;
	nm_device_remove_pending_action (self, NM_PENDING_ACTION_CARRIER_WAIT, FALSE);
	if (!priv->carrier)
		_carrier_wait_check_queued_act_request (self);
	return G_SOURCE_REMOVE;
}

static gboolean
nm_device_is_up (NMDevice *self)
{
	int ifindex;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	ifindex = nm_device_get_ip_ifindex (self);
	return ifindex > 0 ? nm_platform_link_is_up (nm_device_get_platform (self), ifindex) : TRUE;
}

static gint64
_get_carrier_wait_ms (NMDevice *self)
{
	gs_free char *value = NULL;

	value = nm_config_data_get_device_config (NM_CONFIG_GET_DATA,
	                                          NM_CONFIG_KEYFILE_KEY_DEVICE_CARRIER_WAIT_TIMEOUT,
	                                          self,
	                                          NULL);
	return _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXINT32, CARRIER_WAIT_TIME_MS);
}

gboolean
nm_device_bring_up (NMDevice *self, gboolean block, gboolean *no_firmware)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean device_is_up = FALSE;
	NMDeviceCapabilities capabilities;
	int ifindex;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	NM_SET_OUT (no_firmware, FALSE);

	if (!nm_device_get_enabled (self)) {
		_LOGD (LOGD_PLATFORM, "bringing up device ignored due to disabled");
		return FALSE;
	}

	ifindex = nm_device_get_ip_ifindex (self);
	_LOGD (LOGD_PLATFORM, "bringing up device %d", ifindex);
	if (ifindex <= 0) {
		/* assume success. */
	} else {
		if (!nm_platform_link_set_up (nm_device_get_platform (self), ifindex, no_firmware))
			return FALSE;
	}

	/* Store carrier immediately. */
	nm_device_set_carrier_from_platform (self);

	device_is_up = nm_device_is_up (self);
	if (block && !device_is_up) {
		gint64 wait_until = nm_utils_get_monotonic_timestamp_us () + 10000 /* microseconds */;

		do {
			g_usleep (200);
			if (!nm_platform_link_refresh (nm_device_get_platform (self), ifindex))
				return FALSE;
			device_is_up = nm_device_is_up (self);
		} while (!device_is_up && nm_utils_get_monotonic_timestamp_us () < wait_until);
	}

	if (!device_is_up) {
		if (block)
			_LOGW (LOGD_PLATFORM, "device not up after timeout!");
		else
			_LOGD (LOGD_PLATFORM, "device not up immediately");
		return FALSE;
	}

	/* some ethernet devices fail to report capabilities unless the device
	 * is up. Re-read the capabilities. */
	capabilities = 0;
	if (NM_DEVICE_GET_CLASS (self)->get_generic_capabilities)
		capabilities |= NM_DEVICE_GET_CLASS (self)->get_generic_capabilities (self);
	_add_capabilities (self, capabilities);

	/* Devices that support carrier detect must be IFF_UP to report carrier
	 * changes; so after setting the device IFF_UP we must suppress startup
	 * complete (via a pending action) until either the carrier turns on, or
	 * a timeout is reached.
	 */
	if (nm_device_has_capability (self, NM_DEVICE_CAP_CARRIER_DETECT)) {
		gint64 now_ms, until_ms;

		/* we start a grace period of 5 seconds during which we will schedule
		 * a pending action whenever we have no carrier.
		 *
		 * If during that time carrier goes away, we declare the interface
		 * as not ready. */
		nm_clear_g_source (&priv->carrier_wait_id);
		if (!priv->carrier)
			nm_device_add_pending_action (self, NM_PENDING_ACTION_CARRIER_WAIT, FALSE);

		now_ms = nm_utils_get_monotonic_timestamp_ms ();
		until_ms = NM_MAX (now_ms + _get_carrier_wait_ms (self), priv->carrier_wait_until_ms);
		priv->carrier_wait_id = g_timeout_add (until_ms - now_ms, carrier_wait_timeout, self);
	}

	/* Can only get HW address of some devices when they are up */
	nm_device_update_hw_address (self);

	_update_ip4_address (self);

	/* when the link comes up, we must restore IP configuration if necessary. */
	if (priv->ip4_state == IP_DONE) {
		if (!ip4_config_merge_and_apply (self, TRUE))
			_LOGW (LOGD_IP4, "failed applying IP4 config after bringing link up");
	}
	if (priv->ip6_state == IP_DONE) {
		if (!ip6_config_merge_and_apply (self, TRUE))
			_LOGW (LOGD_IP6, "failed applying IP6 config after bringing link up");
	}

	return TRUE;
}

void
nm_device_take_down (NMDevice *self, gboolean block)
{
	int ifindex;
	gboolean device_is_up;

	g_return_if_fail (NM_IS_DEVICE (self));

	ifindex = nm_device_get_ip_ifindex (self);
	_LOGD (LOGD_PLATFORM, "taking down device %d", ifindex);
	if (ifindex <= 0) {
		/* devices without ifindex are always up. */
		return;
	}

	if (!nm_platform_link_set_down (nm_device_get_platform (self), ifindex))
		return;

	device_is_up = nm_device_is_up (self);
	if (block && device_is_up) {
		gint64 wait_until = nm_utils_get_monotonic_timestamp_us () + 10000 /* microseconds */;

		do {
			g_usleep (200);
			if (!nm_platform_link_refresh (nm_device_get_platform (self), ifindex))
				return;
			device_is_up = nm_device_is_up (self);
		} while (device_is_up && nm_utils_get_monotonic_timestamp_us () < wait_until);
	}

	if (device_is_up) {
		if (block)
			_LOGW (LOGD_PLATFORM, "device not down after timeout!");
		else
			_LOGD (LOGD_PLATFORM, "device not down immediately");
	}
}

void
nm_device_set_firmware_missing (NMDevice *self, gboolean new_missing)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);
	if (priv->firmware_missing != new_missing) {
		priv->firmware_missing = new_missing;
		_notify (self, PROP_FIRMWARE_MISSING);
	}
}

gboolean
nm_device_get_firmware_missing (NMDevice *self)
{
	return NM_DEVICE_GET_PRIVATE (self)->firmware_missing;
}

static NMIP4Config *
find_ip4_lease_config (NMDevice *self,
                       NMConnection *connection,
                       NMIP4Config *ext_ip4_config)
{
	const char *ip_iface = nm_device_get_ip_iface (self);
	int ip_ifindex = nm_device_get_ip_ifindex (self);
	GSList *leases, *liter;
	NMIP4Config *found = NULL;

	g_return_val_if_fail (NM_IS_IP4_CONFIG (ext_ip4_config), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	leases = nm_dhcp_manager_get_lease_ip_configs (nm_dhcp_manager_get (),
	                                               nm_device_get_multi_index (self),
	                                               AF_INET,
	                                               ip_iface,
	                                               ip_ifindex,
	                                               nm_connection_get_uuid (connection),
	                                               nm_device_get_route_table (self, AF_INET, TRUE),
	                                               nm_device_get_route_metric (self, AF_INET));
	for (liter = leases; liter && !found; liter = liter->next) {
		NMIP4Config *lease_config = liter->data;
		const NMPlatformIP4Address *address = nm_ip4_config_get_first_address (lease_config);
		const NMPObject *gw1, *gw2;

		g_assert (address);
		if (!nm_ip4_config_address_exists (ext_ip4_config, address))
			continue;
		gw1 = nm_ip4_config_best_default_route_get (lease_config);
		if (!gw1)
			continue;
		gw2 = nm_ip4_config_best_default_route_get (ext_ip4_config);
		if (!gw2)
			continue;
		if (NMP_OBJECT_CAST_IP4_ROUTE (gw1)->gateway != NMP_OBJECT_CAST_IP4_ROUTE (gw2)->gateway)
			continue;
		found = g_object_ref (lease_config);
	}

	g_slist_free_full (leases, g_object_unref);
	return found;
}

static void
capture_lease_config (NMDevice *self,
                      NMIP4Config *ext_ip4_config,
                      NMIP4Config **out_ip4_config,
                      NMIP6Config *ext_ip6_config,
                      NMIP6Config **out_ip6_config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMSettingsConnection *const*connections;
	guint i;
	gboolean dhcp_used = FALSE;
	NMDedupMultiIter ipconf_iter;

	/* Ensure at least one address on the device has a non-infinite lifetime,
	 * otherwise DHCP cannot possibly be active on the device right now.
	 */
	if (ext_ip4_config && out_ip4_config) {
		const NMPlatformIP4Address *addr;

		nm_ip_config_iter_ip4_address_for_each (&ipconf_iter, ext_ip4_config, &addr) {
			if (addr->lifetime != NM_PLATFORM_LIFETIME_PERMANENT) {
				dhcp_used = TRUE;
				break;
			}
		}
	} else if (ext_ip6_config && out_ip6_config) {
		const NMPlatformIP6Address *addr;

		nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, ext_ip6_config, &addr) {
			if (addr->lifetime != NM_PLATFORM_LIFETIME_PERMANENT) {
				dhcp_used = TRUE;
				break;
			}
		}
	} else {
		g_return_if_fail (   (ext_ip6_config && out_ip6_config)
		                  || (ext_ip4_config && out_ip4_config));
	}

	if (!dhcp_used)
		return;

	connections = nm_settings_get_connections (priv->settings, NULL);
	for (i = 0; connections[i]; i++) {
		NMConnection *candidate = (NMConnection *) connections[i];
		const char *method;

		if (!nm_device_check_connection_compatible (self, candidate))
			continue;

		/* IPv4 leases */
		method = nm_utils_get_ip_config_method (candidate, NM_TYPE_SETTING_IP4_CONFIG);
		if (out_ip4_config && strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0) {
			*out_ip4_config = find_ip4_lease_config (self, candidate, ext_ip4_config);
			if (*out_ip4_config)
				return;
		}

		/* IPv6 leases */
		method = nm_utils_get_ip_config_method (candidate, NM_TYPE_SETTING_IP6_CONFIG);
		if (out_ip6_config && strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0) {
			/* FIXME: implement find_ip6_lease_config() */
		}
	}
}

static void
intersect_ext_config (NMDevice *self, AppliedConfig *config)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMIPConfig *ext;
	guint32 penalty;
	int family;

	if (!config->orig)
		return;

	family = nm_ip_config_get_addr_family (config->orig);
	penalty = default_route_metric_penalty_get (self, family);
	ext = family == AF_INET
	      ? (NMIPConfig *) priv->ext_ip4_config
	      : (NMIPConfig *) priv->ext_ip6_config;

	if (config->current)
		nm_ip_config_intersect (config->current, ext, penalty);
	else {
		config->current = nm_ip_config_intersect_alloc (config->orig,
		                                                ext,
		                                                penalty);
	}
}

static gboolean
update_ext_ip_config (NMDevice *self, int addr_family, gboolean initial, gboolean intersect_configs)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	int ifindex;
	gboolean capture_resolv_conf;
	GSList *iter;

	nm_assert_addr_family (addr_family);

	ifindex = nm_device_get_ip_ifindex (self);
	if (!ifindex)
		return FALSE;

	capture_resolv_conf =    initial
	                      && nm_dns_manager_get_resolv_conf_explicit (nm_dns_manager_get ());

	if (addr_family == AF_INET) {

		g_clear_object (&priv->ext_ip4_config);
		priv->ext_ip4_config = nm_ip4_config_capture (nm_device_get_multi_index (self),
		                                              nm_device_get_platform (self),
		                                              ifindex,
		                                              capture_resolv_conf);
		if (priv->ext_ip4_config) {
			if (initial) {
				applied_config_clear (&priv->dev_ip4_config);
				capture_lease_config (self,
				                      priv->ext_ip4_config,
				                      (NMIP4Config **) &priv->dev_ip4_config.orig,
				                      NULL, NULL);
			}

			if (intersect_configs) {
				/* This function was called upon external changes. Remove the configuration
				 * (addresses,routes) that is no longer present externally from the internal
				 * config. This way, we don't re-add addresses that were manually removed
				 * by the user. */
				if (priv->con_ip4_config) {
					nm_ip4_config_intersect (priv->con_ip4_config, priv->ext_ip4_config,
					                         default_route_metric_penalty_get (self, AF_INET));
				}

				intersect_ext_config (self, &priv->dev_ip4_config);
				intersect_ext_config (self, &priv->wwan_ip4_config);

				for (iter = priv->vpn4_configs; iter; iter = iter->next)
					nm_ip4_config_intersect (iter->data, priv->ext_ip4_config, 0);
			}

			/* Remove parts from ext_ip4_config to only contain the information that
			 * was configured externally -- we already have the same configuration from
			 * internal origins. */
			if (priv->con_ip4_config) {
				nm_ip4_config_subtract (priv->ext_ip4_config, priv->con_ip4_config,
				                        default_route_metric_penalty_get (self, AF_INET));
			}
			if (applied_config_get_current (&priv->dev_ip4_config)) {
				nm_ip_config_subtract ((NMIPConfig *) priv->ext_ip4_config,
				                       applied_config_get_current (&priv->dev_ip4_config),
				                       default_route_metric_penalty_get (self, AF_INET));
			}
			if (applied_config_get_current (&priv->wwan_ip4_config)) {
				nm_ip_config_subtract ((NMIPConfig *) priv->ext_ip4_config,
				                       applied_config_get_current (&priv->wwan_ip4_config),
				                       default_route_metric_penalty_get (self, AF_INET));
			}
			for (iter = priv->vpn4_configs; iter; iter = iter->next)
				nm_ip4_config_subtract (priv->ext_ip4_config, iter->data, 0);
		}

	} else {
		nm_assert (addr_family == AF_INET6);

		g_clear_object (&priv->ext_ip6_config);
		g_clear_object (&priv->ext_ip6_config_captured);
		priv->ext_ip6_config_captured = nm_ip6_config_capture (nm_device_get_multi_index (self),
		                                                       nm_device_get_platform (self),
		                                                       ifindex,
		                                                       capture_resolv_conf,
		                                                       NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);
		if (priv->ext_ip6_config_captured) {

			priv->ext_ip6_config = nm_ip6_config_new_cloned (priv->ext_ip6_config_captured);

			if (intersect_configs) {
				/* This function was called upon external changes. Remove the configuration
				 * (addresses,routes) that is no longer present externally from the internal
				 * config. This way, we don't re-add addresses that were manually removed
				 * by the user. */
				if (priv->con_ip6_config) {
					nm_ip6_config_intersect (priv->con_ip6_config, priv->ext_ip6_config,
					                         default_route_metric_penalty_get (self, AF_INET6));
				}

				intersect_ext_config (self, &priv->ac_ip6_config);
				intersect_ext_config (self, &priv->dhcp6.ip6_config);
				intersect_ext_config (self, &priv->wwan_ip6_config);

				for (iter = priv->vpn6_configs; iter; iter = iter->next)
					nm_ip6_config_intersect (iter->data, priv->ext_ip6_config, 0);
			}

			/* Remove parts from ext_ip6_config to only contain the information that
			 * was configured externally -- we already have the same configuration from
			 * internal origins. */
			if (priv->con_ip6_config) {
				nm_ip6_config_subtract (priv->ext_ip6_config, priv->con_ip6_config,
				                        default_route_metric_penalty_get (self, AF_INET6));
			}
			if (applied_config_get_current (&priv->ac_ip6_config)) {
				nm_ip_config_subtract ((NMIPConfig *) priv->ext_ip6_config,
				                       applied_config_get_current (&priv->ac_ip6_config),
				                       default_route_metric_penalty_get (self, AF_INET6));
			}
			if (applied_config_get_current (&priv->dhcp6.ip6_config)) {
				nm_ip_config_subtract ((NMIPConfig *) priv->ext_ip6_config,
				                       applied_config_get_current (&priv->dhcp6.ip6_config),
				                       default_route_metric_penalty_get (self, AF_INET6));
			}
			if (applied_config_get_current (&priv->wwan_ip6_config)) {
				nm_ip_config_subtract ((NMIPConfig *) priv->ext_ip6_config,
				                       applied_config_get_current (&priv->wwan_ip6_config),
				                       default_route_metric_penalty_get (self, AF_INET6));
			}
			for (iter = priv->vpn6_configs; iter; iter = iter->next)
				nm_ip6_config_subtract (priv->ext_ip6_config, iter->data, 0);
		}
	}

	return TRUE;
}

static void
update_ip_config (NMDevice *self, int addr_family, gboolean initial)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	nm_assert_addr_family (addr_family);

	if (update_ext_ip_config (self, addr_family, initial, TRUE)) {
		if (addr_family == AF_INET) {
			if (priv->ext_ip4_config)
				ip4_config_merge_and_apply (self, FALSE);
		} else {
			if (priv->ext_ip6_config_captured)
				ip6_config_merge_and_apply (self, FALSE);
		}
	}

	if (   addr_family == AF_INET6
	    && priv->linklocal6_timeout_id
	    && priv->ext_ip6_config_captured
	    && nm_ip6_config_get_address_first_nontentative (priv->ext_ip6_config_captured, TRUE)) {
		/* linklocal6 is ready now, do the state transition... we are also
		 * invoked as g_idle_add, so no problems with reentrance doing it now.
		 */
		linklocal6_complete (self);
	}
}

void
nm_device_capture_initial_config (NMDevice *self)
{
	update_ip_config (self, AF_INET,  TRUE);
	update_ip_config (self, AF_INET6, TRUE);
}

static gboolean
queued_ip4_config_change (gpointer user_data)
{
	NMDevice *self = user_data;
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), G_SOURCE_REMOVE);

	priv = NM_DEVICE_GET_PRIVATE (self);

	nm_assert (!priv->queued_ip4_config_pending);

	/* Wait for any queued state changes */
	if (priv->queued_state.id)
		return TRUE;

	priv->queued_ip4_config_id = 0;

	/* If a commit is scheduled, this function would potentially interfere with
	 * it changing IP configurations before they are applied. Postpone the
	 * update in such case.
	 */
	if (activation_source_is_scheduled (self,
	                                    activate_stage5_ip4_config_result,
	                                    AF_INET)) {
		priv->queued_ip4_config_pending = FALSE;
		priv->queued_ip4_config_id = g_idle_add (queued_ip4_config_change, self);
		_LOGT (LOGD_DEVICE, "IP4 update was postponed");
	} else
		update_ip_config (self, AF_INET, FALSE);

	set_unmanaged_external_down (self, TRUE);

	if (!nm_device_sys_iface_state_is_external_or_assume (self)) {
		priv->v4_has_shadowed_routes = _v4_has_shadowed_routes_detect (self);;
		ip4_rp_filter_update (self);
	}

	return FALSE;
}

static gboolean
queued_ip6_config_change (gpointer user_data)
{
	NMDevice *self = user_data;
	NMDevicePrivate *priv;
	gboolean need_ipv6ll = FALSE;
	NMPlatform *platform;

	g_return_val_if_fail (NM_IS_DEVICE (self), G_SOURCE_REMOVE);

	priv = NM_DEVICE_GET_PRIVATE (self);

	nm_assert (!priv->queued_ip4_config_pending);

	/* Wait for any queued state changes */
	if (priv->queued_state.id)
		return TRUE;

	priv->queued_ip6_config_id = 0;

	/* If a commit is scheduled, this function would potentially interfere with
	 * it changing IP configurations before they are applied. Postpone the
	 * update in such case.
	 */
	if (activation_source_is_scheduled (self,
	                                    activate_stage5_ip6_config_commit,
	                                    AF_INET6)) {
		priv->queued_ip6_config_pending = FALSE;
		priv->queued_ip6_config_id = g_idle_add (queued_ip6_config_change, self);
		_LOGT (LOGD_DEVICE, "IP6 update was postponed");
	} else
		update_ip_config (self, AF_INET6, FALSE);

	if (   priv->state < NM_DEVICE_STATE_DEACTIVATING
	    && (platform = nm_device_get_platform (self))
	    && nm_platform_link_get (platform, priv->ifindex)) {
		/* Handle DAD failures */
		while (priv->dad6_failed_addrs) {
			nm_auto_nmpobj const NMPObject *obj = NULL;
			const NMPlatformIP6Address *addr;

			obj = priv->dad6_failed_addrs->data;
			priv->dad6_failed_addrs = g_slist_delete_link (priv->dad6_failed_addrs, priv->dad6_failed_addrs);

			if (!nm_ndisc_dad_addr_is_fail_candidate (platform, obj))
				continue;

			addr = NMP_OBJECT_CAST_IP6_ADDRESS (obj);

			_LOGI (LOGD_IP6, "ipv6: duplicate address check failed for the %s address",
			       nm_platform_ip6_address_to_string (addr, NULL, 0));

			if (IN6_IS_ADDR_LINKLOCAL (&addr->address))
				need_ipv6ll = TRUE;
			else if (priv->ndisc)
				nm_ndisc_dad_failed (priv->ndisc, &addr->address);
		}

		/* If no IPv6 link-local address exists but other addresses do then we
		 * must add the LL address to remain conformant with RFC 3513 chapter 2.1
		 * ("Addressing Model"): "All interfaces are required to have at least
		 * one link-local unicast address".
		 */
		if (priv->ip6_config && nm_ip6_config_get_num_addresses (priv->ip6_config))
			need_ipv6ll = TRUE;

		if (need_ipv6ll)
			check_and_add_ipv6ll_addr (self);
	} else {
		g_slist_free_full (priv->dad6_failed_addrs, (GDestroyNotify) nmp_object_unref);
		priv->dad6_failed_addrs = NULL;
	}

	/* Check if DAD is still pending */
	if (   priv->ip6_state == IP_CONF
	    && priv->dad6_ip6_config
	    && priv->ext_ip6_config_captured) {
		if (!nm_ip6_config_has_any_dad_pending (priv->ext_ip6_config_captured,
		                                        priv->dad6_ip6_config)) {
			_LOGD (LOGD_DEVICE | LOGD_IP6, "IPv6 DAD terminated");
			g_clear_object (&priv->dad6_ip6_config);
			_set_ip_state (self, AF_INET6, IP_DONE);
			check_ip_state (self, FALSE, TRUE);
			if (priv->rt6_temporary_not_available)
				nm_device_activate_schedule_ip6_config_result (self);
		}
	}

	set_unmanaged_external_down (self, TRUE);

	return FALSE;
}

static void
device_ipx_changed (NMPlatform *platform,
                    int obj_type_i,
                    int ifindex,
                    gconstpointer platform_object,
                    int change_type_i,
                    NMDevice *self)
{
	const NMPObjectType obj_type = obj_type_i;
	const NMPlatformSignalChangeType change_type = change_type_i;
	NMDevicePrivate *priv;
	const NMPlatformIP6Address *addr;

	if (nm_device_get_ip_ifindex (self) != ifindex)
		return;

	priv = NM_DEVICE_GET_PRIVATE (self);

	switch (obj_type) {
	case NMP_OBJECT_TYPE_IP4_ADDRESS:
	case NMP_OBJECT_TYPE_IP4_ROUTE:
		if (nm_device_get_unmanaged_flags (self, NM_UNMANAGED_PLATFORM_INIT)) {
			priv->queued_ip4_config_pending = TRUE;
			nm_assert_se (!nm_clear_g_source (&priv->queued_ip4_config_id));
		} else if (!priv->queued_ip4_config_id) {
			priv->queued_ip4_config_pending = FALSE;
			priv->queued_ip4_config_id = g_idle_add (queued_ip4_config_change, self);
			_LOGD (LOGD_DEVICE, "queued IP4 config change");
		}
		break;
	case NMP_OBJECT_TYPE_IP6_ADDRESS:
		addr = platform_object;

		if (   priv->state > NM_DEVICE_STATE_DISCONNECTED
		    && priv->state < NM_DEVICE_STATE_DEACTIVATING
		    && nm_ndisc_dad_addr_is_fail_candidate_event (change_type, addr)) {
			priv->dad6_failed_addrs = g_slist_prepend (priv->dad6_failed_addrs,
			                                           (gpointer) nmp_object_ref (NMP_OBJECT_UP_CAST (addr)));
		}
		/* fall through */
	case NMP_OBJECT_TYPE_IP6_ROUTE:
		if (nm_device_get_unmanaged_flags (self, NM_UNMANAGED_PLATFORM_INIT)) {
			priv->queued_ip6_config_pending = TRUE;
			nm_assert_se (!nm_clear_g_source (&priv->queued_ip6_config_id));
		} else if (!priv->queued_ip6_config_id) {
			priv->queued_ip6_config_pending = FALSE;
			priv->queued_ip6_config_id = g_idle_add (queued_ip6_config_change, self);
			_LOGD (LOGD_DEVICE, "queued IP6 config change");
		}
		break;
	default:
		g_return_if_reached ();
	}
}

/*****************************************************************************/

NM_UTILS_FLAGS2STR_DEFINE (nm_unmanaged_flags2str, NMUnmanagedFlags,
	NM_UTILS_FLAGS2STR (NM_UNMANAGED_SLEEPING, "sleeping"),
	NM_UTILS_FLAGS2STR (NM_UNMANAGED_QUITTING, "quitting"),
	NM_UTILS_FLAGS2STR (NM_UNMANAGED_PARENT, "parent"),
	NM_UTILS_FLAGS2STR (NM_UNMANAGED_LOOPBACK, "loopback"),
	NM_UTILS_FLAGS2STR (NM_UNMANAGED_PLATFORM_INIT, "platform-init"),
	NM_UTILS_FLAGS2STR (NM_UNMANAGED_USER_EXPLICIT, "user-explicit"),
	NM_UTILS_FLAGS2STR (NM_UNMANAGED_BY_DEFAULT, "by-default"),
	NM_UTILS_FLAGS2STR (NM_UNMANAGED_USER_SETTINGS, "user-settings"),
	NM_UTILS_FLAGS2STR (NM_UNMANAGED_USER_CONF, "user-conf"),
	NM_UTILS_FLAGS2STR (NM_UNMANAGED_USER_UDEV, "user-udev"),
	NM_UTILS_FLAGS2STR (NM_UNMANAGED_EXTERNAL_DOWN, "external-down"),
	NM_UTILS_FLAGS2STR (NM_UNMANAGED_IS_SLAVE, "is-slave"),
);

static const char *
_unmanaged_flags2str (NMUnmanagedFlags flags, NMUnmanagedFlags mask, char *buf, gsize len)
{
	char buf2[512];
	char *b;
	char *tmp, *tmp2;
	gsize l;

	nm_utils_to_string_buffer_init (&buf, &len);
	if (!len)
		return buf;

	b = buf;

	mask |= flags;

	nm_unmanaged_flags2str (flags, b, len);
	l = strlen (b);
	b += l;
	len -= l;

	nm_unmanaged_flags2str (mask & ~flags, buf2, sizeof (buf2));
	if (buf2[0]) {
		gboolean add_separator = l > 0;

		tmp = buf2;
		while (TRUE) {
			if (add_separator)
				nm_utils_strbuf_append_c (&b, &len, ',');
			add_separator = TRUE;

			tmp2 = strchr (tmp, ',');
			if (tmp2)
				tmp2[0] = '\0';

			nm_utils_strbuf_append_c (&b, &len, '!');
			nm_utils_strbuf_append_str (&b, &len, tmp);
			if (!tmp2)
				break;

			tmp = &tmp2[1];
		}
	}

	return buf;
}

static gboolean
_get_managed_by_flags(NMUnmanagedFlags flags, NMUnmanagedFlags mask, gboolean for_user_request)
{
	/* Evaluate the managed state based on the unmanaged flags.
	 *
	 * Some flags are authoritative, meaning they always cause
	 * the device to be unmanaged (e.g. @NM_UNMANAGED_PLATFORM_INIT).
	 *
	 * OTOH, some flags can be overwritten. For example NM_UNMANAGED_USER_UDEV
	 * is ignored once NM_UNMANAGED_USER_EXPLICIT is set. The idea is that
	 * the flag from the configuration has no effect once the user explicitly
	 * touches the unmanaged flags. */

	if (for_user_request) {

		/* @for_user_request can make the result only ~more~ managed.
		 * If the flags already indicate a managed state for a non-user-request,
		 * then it is also managed for an explict user-request.
		 *
		 * Effectively, this check is redundant, as the code below already
		 * already ensures that. Still, express this invariant explictly here. */
		if (_get_managed_by_flags (flags, mask, FALSE))
			return TRUE;

		/* A for-user-request, is effectively the same as pretending
		 * that user-dbus flag is cleared. */
		mask |= NM_UNMANAGED_USER_EXPLICIT;
		flags &= ~NM_UNMANAGED_USER_EXPLICIT;
	}

	if (   NM_FLAGS_ANY (mask, NM_UNMANAGED_USER_SETTINGS)
	    && !NM_FLAGS_ANY (flags, NM_UNMANAGED_USER_SETTINGS)) {
		/* NM_UNMANAGED_USER_SETTINGS can only explicitly unmanage a device. It cannot
		 * *manage* it. Having NM_UNMANAGED_USER_SETTINGS explicitly not set, is the
		 * same as having it not set at all. */
		mask &= ~NM_UNMANAGED_USER_SETTINGS;
	}

	if (NM_FLAGS_ANY (mask, NM_UNMANAGED_USER_UDEV)) {
		/* configuration from udev or nm-config overwrites the by-default flag
		 * which is based on the device type.
		 * configuration from udev overwrites external-down */
		flags &= ~(  NM_UNMANAGED_BY_DEFAULT
		           | NM_UNMANAGED_EXTERNAL_DOWN);
	}

	if (NM_FLAGS_ANY (mask, NM_UNMANAGED_USER_CONF)) {
		/* configuration from NetworkManager.conf overwrites the by-default flag
		 * which is based on the device type.
		 * It also overwrites the udev configuration and external-down */
		flags &= ~(   NM_UNMANAGED_BY_DEFAULT
		           | NM_UNMANAGED_USER_UDEV
		           | NM_UNMANAGED_EXTERNAL_DOWN);
	}

	if (   NM_FLAGS_HAS (mask, NM_UNMANAGED_IS_SLAVE)
	    && !NM_FLAGS_HAS (flags, NM_UNMANAGED_IS_SLAVE)) {
		/* for an enslaved device, by-default doesn't matter */
		flags &= ~NM_UNMANAGED_BY_DEFAULT;
	}

	if (NM_FLAGS_HAS (mask, NM_UNMANAGED_USER_EXPLICIT)) {
		/* if the device is managed by user-decision, certain other flags
		 * are ignored. */
		flags &= ~(  NM_UNMANAGED_BY_DEFAULT
		           | NM_UNMANAGED_USER_UDEV
		           | NM_UNMANAGED_USER_CONF
		           | NM_UNMANAGED_EXTERNAL_DOWN);
	}

	return flags == NM_UNMANAGED_NONE;
}

/**
 * nm_device_get_managed:
 * @self: the #NMDevice
 * @for_user_request: whether to check the flags for an explict user-request
 *
 * Whether the device is unmanaged according to the unmanaged flags.
 *
 * Returns: %TRUE if the device is unmanaged because of the flags.
 */
gboolean
nm_device_get_managed (NMDevice *self, gboolean for_user_request)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	if (!nm_device_is_real (self)) {
		/* a unrealized device is always considered unmanaged. */
		return FALSE;
	}

	priv = NM_DEVICE_GET_PRIVATE (self);

	return _get_managed_by_flags (priv->unmanaged_flags, priv->unmanaged_mask, for_user_request);
}

/**
 * nm_device_get_unmanaged_mask:
 * @self: the #NMDevice
 * @flag: the unmanaged flags to check.
 *
 * Return the unmanaged flags mask set on this device.
 *
 * Returns: the flags of the device ( & @flag)
 */
NMUnmanagedFlags
nm_device_get_unmanaged_mask (NMDevice *self, NMUnmanagedFlags flag)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_UNMANAGED_NONE);
	g_return_val_if_fail (flag != NM_UNMANAGED_NONE, NM_UNMANAGED_NONE);

	return NM_DEVICE_GET_PRIVATE (self)->unmanaged_mask & flag;
}

/**
 * nm_device_get_unmanaged_flags:
 * @self: the #NMDevice
 * @flag: the unmanaged flags to check.
 *
 * Return the unmanaged flags of the device.
 *
 * Returns: the flags of the device ( & @flag)
 */
NMUnmanagedFlags
nm_device_get_unmanaged_flags (NMDevice *self, NMUnmanagedFlags flag)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_UNMANAGED_NONE);
	g_return_val_if_fail (flag != NM_UNMANAGED_NONE, NM_UNMANAGED_NONE);

	return NM_DEVICE_GET_PRIVATE (self)->unmanaged_flags & flag;
}

/**
 * _set_unmanaged_flags:
 * @self: the #NMDevice instance
 * @flags: which #NMUnmanagedFlags to set.
 * @set_op: whether to set/clear/forget the flags. You can also pass
 *   boolean values %TRUE and %FALSE, which mean %NM_UNMAN_FLAG_OP_SET_UNMANAGED
 *   and %NM_UNMAN_FLAG_OP_SET_MANAGED, respectively.
 * @allow_state_transition: if %FALSE, setting flags never triggers a device
 *   state change. If %TRUE, the device can change state, if it is real and
 *   switches from managed to unmanaged (or vice versa).
 * @now: whether the state change should be immediate or delayed
 * @reason: the device state reason passed to nm_device_state_changed() if
 *   the device becomes managed/unmanaged. This is only relevant if the
 *   device switches state and if @allow_state_transition is %TRUE.
 *
 * Set the unmanaged flags of the device.
 **/
static void
_set_unmanaged_flags (NMDevice *self,
                      NMUnmanagedFlags flags,
                      NMUnmanFlagOp set_op,
                      gboolean allow_state_transition,
                      gboolean now,
                      NMDeviceStateReason reason)
{
	NMDevicePrivate *priv;
	gboolean was_managed, transition_state;
	NMUnmanagedFlags old_flags, old_mask;
	NMDeviceState new_state;
	const char *operation = NULL;
	char str1[512];
	char str2[512];
	gboolean do_notify_has_pending_actions = FALSE;
	gboolean had_pending_actions = FALSE;

	g_return_if_fail (NM_IS_DEVICE (self));
	g_return_if_fail (flags);

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (!priv->real)
		allow_state_transition = FALSE;
	was_managed = allow_state_transition && nm_device_get_managed (self, FALSE);

	if (   NM_FLAGS_HAS (priv->unmanaged_flags, NM_UNMANAGED_PLATFORM_INIT)
	    && NM_FLAGS_HAS (flags, NM_UNMANAGED_PLATFORM_INIT)
	    && NM_IN_SET (set_op, NM_UNMAN_FLAG_OP_SET_MANAGED)) {
		/* we are clearing the platform-init flags. This triggers additional actions. */
		if (!NM_FLAGS_HAS (flags, NM_UNMANAGED_USER_SETTINGS)) {
			gboolean unmanaged;

			unmanaged = nm_device_spec_match_list (self,
			                                       nm_settings_get_unmanaged_specs (NM_DEVICE_GET_PRIVATE (self)->settings));
			nm_device_set_unmanaged_flags (self,
			                               NM_UNMANAGED_USER_SETTINGS,
			                               !!unmanaged);
		}

		if (priv->queued_ip4_config_pending) {
			priv->queued_ip4_config_pending = FALSE;
			nm_assert_se (!nm_clear_g_source (&priv->queued_ip4_config_id));
			priv->queued_ip4_config_id = g_idle_add (queued_ip4_config_change, self);
		}

		if (priv->queued_ip6_config_pending) {
			priv->queued_ip6_config_pending = FALSE;
			nm_assert_se (!nm_clear_g_source (&priv->queued_ip6_config_id));
			priv->queued_ip6_config_id = g_idle_add (queued_ip6_config_change, self);
		}

		if (!priv->pending_actions) {
			do_notify_has_pending_actions = TRUE;
			had_pending_actions = nm_device_has_pending_action (self);
		}
	}

	old_flags = priv->unmanaged_flags;
	old_mask = priv->unmanaged_mask;

	switch (set_op) {
	case NM_UNMAN_FLAG_OP_FORGET:
		priv->unmanaged_mask &= ~flags;
		priv->unmanaged_flags &= ~flags;
		operation = "forget";
		break;
	case NM_UNMAN_FLAG_OP_SET_UNMANAGED:
		priv->unmanaged_mask |= flags;
		priv->unmanaged_flags |= flags;
		operation = "set-unmanaged";
		break;
	case NM_UNMAN_FLAG_OP_SET_MANAGED:
		priv->unmanaged_mask |= flags;
		priv->unmanaged_flags &= ~flags;
		operation = "set-managed";
		break;
	default:
		g_return_if_reached ();
	}

	if (   old_flags == priv->unmanaged_flags
	    && old_mask == priv->unmanaged_mask)
		return;

	transition_state =    allow_state_transition
	                   && was_managed != nm_device_get_managed (self, FALSE)
	                   && (   was_managed
	                       || (   !was_managed
	                           && nm_device_get_state (self) == NM_DEVICE_STATE_UNMANAGED));

	_LOGD (LOGD_DEVICE, "unmanaged: flags set to [%s%s0x%0x/0x%x/%s%s], %s [%s=0x%0x]%s%s%s)",
	       _unmanaged_flags2str (priv->unmanaged_flags, priv->unmanaged_mask, str1, sizeof (str1)), \
	       (priv->unmanaged_flags | priv->unmanaged_mask) ? "=" : "", \
	       (guint) priv->unmanaged_flags, \
	       (guint) priv->unmanaged_mask, \
	       (_get_managed_by_flags (priv->unmanaged_flags, priv->unmanaged_mask, FALSE) \
	            ? "managed" \
	            : (_get_managed_by_flags (priv->unmanaged_flags, priv->unmanaged_mask, TRUE) \
	                   ? "manageable" \
	                   : "unmanaged")),
	       priv->real ? "" : "/unrealized",
	       operation,
	       nm_unmanaged_flags2str (flags, str2, sizeof (str2)),
	       flags,
	       NM_PRINT_FMT_QUOTED (allow_state_transition,
	                            ", reason ",
	                            reason_to_string (reason),
	                            transition_state ? ", transition-state" : "",
	                            ""));

	if (   do_notify_has_pending_actions
	    && had_pending_actions != nm_device_has_pending_action (self))
		_notify (self, PROP_HAS_PENDING_ACTION);

	if (transition_state) {
		new_state = was_managed ? NM_DEVICE_STATE_UNMANAGED : NM_DEVICE_STATE_UNAVAILABLE;
		if (now)
			nm_device_state_changed (self, new_state, reason);
		else
			nm_device_queue_state (self, new_state, reason);
	}
}

/**
 * @self: the #NMDevice instance
 * @flags: which #NMUnmanagedFlags to set.
 * @set_op: whether to set/clear/forget the flags. You can also pass
 *   boolean values %TRUE and %FALSE, which mean %NM_UNMAN_FLAG_OP_SET_UNMANAGED
 *   and %NM_UNMAN_FLAG_OP_SET_MANAGED, respectively.
 *
 * Set the unmanaged flags of the device (does not trigger a state change).
 **/
void
nm_device_set_unmanaged_flags (NMDevice *self,
                               NMUnmanagedFlags flags,
                               NMUnmanFlagOp set_op)
{
	_set_unmanaged_flags (self, flags, set_op, FALSE, FALSE, NM_DEVICE_STATE_REASON_NONE);
}

/**
 * nm_device_set_unmanaged_by_flags:
 * @self: the #NMDevice instance
 * @flags: which #NMUnmanagedFlags to set.
 * @set_op: whether to set/clear/forget the flags. You can also pass
 *   boolean values %TRUE and %FALSE, which mean %NM_UNMAN_FLAG_OP_SET_UNMANAGED
 *   and %NM_UNMAN_FLAG_OP_SET_MANAGED, respectively.
 * @reason: the device state reason passed to nm_device_state_changed() if
 *   the device becomes managed/unmanaged.
 *
 * Set the unmanaged flags of the device and possibly trigger a state change.
 **/
void
nm_device_set_unmanaged_by_flags (NMDevice *self,
                                  NMUnmanagedFlags flags,
                                  NMUnmanFlagOp set_op,
                                  NMDeviceStateReason reason)
{
	_set_unmanaged_flags (self, flags, set_op, TRUE, TRUE, reason);
}

void
nm_device_set_unmanaged_by_flags_queue (NMDevice *self,
                                        NMUnmanagedFlags flags,
                                        NMUnmanFlagOp set_op,
                                        NMDeviceStateReason reason)
{
	_set_unmanaged_flags (self, flags, set_op, TRUE, FALSE, reason);
}

void
nm_device_set_unmanaged_by_user_settings (NMDevice *self)
{
	gboolean unmanaged;

	g_return_if_fail (NM_IS_DEVICE (self));

	if (nm_device_get_unmanaged_flags (self, NM_UNMANAGED_PLATFORM_INIT)) {
		/* the device is already unmanaged due to platform-init.
		 *
		 * We want to delay evaluating the device spec, because it will freeze
		 * the permanent MAC address. That should not be done, before the platform
		 * link is fully initialized (via UDEV).
		 *
		 * Note that when clearing NM_UNMANAGED_PLATFORM_INIT, we will re-evaluate
		 * whether the device is unmanaged by user-settings. */
		return;
	}

	unmanaged = nm_device_spec_match_list (self,
	                                       nm_settings_get_unmanaged_specs (NM_DEVICE_GET_PRIVATE (self)->settings));

	nm_device_set_unmanaged_by_flags (self,
	                                  NM_UNMANAGED_USER_SETTINGS,
	                                  !!unmanaged,
	                                  unmanaged
	                                      ? NM_DEVICE_STATE_REASON_NOW_UNMANAGED
	                                      : NM_DEVICE_STATE_REASON_NOW_MANAGED);
}

void
nm_device_set_unmanaged_by_user_udev (NMDevice *self)
{
	int ifindex;
	gboolean platform_unmanaged = FALSE;

	ifindex = self->_priv->ifindex;

	if (   ifindex <= 0
	    || !nm_platform_link_get_unmanaged (nm_device_get_platform (self), ifindex, &platform_unmanaged))
		return;

	nm_device_set_unmanaged_by_flags (self,
	                                  NM_UNMANAGED_USER_UDEV,
	                                  platform_unmanaged,
	                                  NM_DEVICE_STATE_REASON_USER_REQUESTED);
}

void
nm_device_set_unmanaged_by_user_conf (NMDevice *self)
{
	gboolean value;
	NMUnmanFlagOp set_op;

	value = nm_config_data_get_device_config_boolean (NM_CONFIG_GET_DATA,
	                                                  NM_CONFIG_KEYFILE_KEY_DEVICE_MANAGED,
	                                                  self,
	                                                  -1,
	                                                  TRUE);
	switch (value) {
	case TRUE:
		set_op = NM_UNMAN_FLAG_OP_SET_MANAGED;
		break;
	case FALSE:
		set_op = NM_UNMAN_FLAG_OP_SET_UNMANAGED;
		break;
	default:
		set_op = NM_UNMAN_FLAG_OP_FORGET;
		break;
	}

	nm_device_set_unmanaged_by_flags (self,
	                                  NM_UNMANAGED_USER_CONF,
	                                  set_op,
	                                  NM_DEVICE_STATE_REASON_USER_REQUESTED);
}

void
nm_device_set_unmanaged_by_quitting (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean need_deactivate = nm_device_is_activating (self) ||
	                           priv->state == NM_DEVICE_STATE_ACTIVATED;

	/* It's OK to block here because we're quitting */
	if (need_deactivate)
		_set_state_full (self, NM_DEVICE_STATE_DEACTIVATING, NM_DEVICE_STATE_REASON_NOW_UNMANAGED, TRUE);

	nm_device_set_unmanaged_by_flags (self,
	                                  NM_UNMANAGED_QUITTING,
	                                  TRUE,
	                                  need_deactivate ? NM_DEVICE_STATE_REASON_REMOVED
	                                                  : NM_DEVICE_STATE_REASON_NOW_UNMANAGED);
}

/*****************************************************************************/

void
nm_device_set_dhcp_anycast_address (NMDevice *self, const char *addr)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));
	g_return_if_fail (!addr || nm_utils_hwaddr_valid (addr, ETH_ALEN));

	priv = NM_DEVICE_GET_PRIVATE (self);

	g_free (priv->dhcp_anycast_address);
	priv->dhcp_anycast_address = g_strdup (addr);
}

void
nm_device_reapply_settings_immediately (NMDevice *self)
{
	NMConnection *applied_connection;
	NMSettingsConnection *settings_connection;
	NMDeviceState state;
	NMSettingConnection *s_con_settings;
	NMSettingConnection *s_con_applied;
	const char *zone;
	NMMetered metered;
	guint64 version_id;

	g_return_if_fail (NM_IS_DEVICE (self));

	state = nm_device_get_state (self);
	if (   state <= NM_DEVICE_STATE_DISCONNECTED
	    || state > NM_DEVICE_STATE_ACTIVATED)
		return;

	applied_connection = nm_device_get_applied_connection (self);
	settings_connection = nm_device_get_settings_connection (self);

	if (!nm_settings_connection_has_unmodified_applied_connection (settings_connection,
	                                                               applied_connection,
	                                                               NM_SETTING_COMPARE_FLAG_IGNORE_REAPPLY_IMMEDIATELY))
		return;

	s_con_settings = nm_connection_get_setting_connection ((NMConnection *) settings_connection);
	s_con_applied = nm_connection_get_setting_connection (applied_connection);

	if (g_strcmp0 ((zone = nm_setting_connection_get_zone (s_con_settings)),
	               nm_setting_connection_get_zone (s_con_applied)) != 0) {

		version_id = nm_active_connection_version_id_bump ((NMActiveConnection *) self->_priv->act_request);
		_LOGD (LOGD_DEVICE, "reapply setting: zone = %s%s%s (version-id %llu)", NM_PRINT_FMT_QUOTE_STRING (zone), (unsigned long long) version_id);

		g_object_set (G_OBJECT (s_con_applied),
		              NM_SETTING_CONNECTION_ZONE, zone,
		              NULL);

		nm_device_update_firewall_zone (self);
	}

	if ((metered = nm_setting_connection_get_metered (s_con_settings)) != nm_setting_connection_get_metered (s_con_applied)) {

		version_id = nm_active_connection_version_id_bump ((NMActiveConnection *) self->_priv->act_request);
		_LOGD (LOGD_DEVICE, "reapply setting: metered = %d (version-id %llu)", (int) metered, (unsigned long long) version_id);

		g_object_set (G_OBJECT (s_con_applied),
		              NM_SETTING_CONNECTION_METERED, metered,
		              NULL);

		nm_device_update_metered (self);
	}
}

void
nm_device_update_firewall_zone (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (   priv->fw_state >= FIREWALL_STATE_INITIALIZED
	    && !nm_device_sys_iface_state_is_external (self))
		fw_change_zone (self);
}

void
nm_device_update_metered (NMDevice *self)
{
#define NM_METERED_INVALID ((NMMetered) -1)
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMSettingConnection *setting;
	NMMetered conn_value, value = NM_METERED_INVALID;
	NMConnection *connection = NULL;
	NMDeviceState state;

	g_return_if_fail (NM_IS_DEVICE (self));

	state = nm_device_get_state (self);
	if (   state <= NM_DEVICE_STATE_DISCONNECTED
	    || state > NM_DEVICE_STATE_ACTIVATED)
		value = NM_METERED_UNKNOWN;

	if (value == NM_METERED_INVALID) {
		connection = nm_device_get_applied_connection (self);
		if (connection) {
			setting = nm_connection_get_setting_connection (connection);
			if (setting) {
				conn_value = nm_setting_connection_get_metered (setting);
				if (conn_value != NM_METERED_UNKNOWN)
					value = conn_value;
			}
		}
	}

	/* Try to guess a value using the metered flag in IP configuration */
	if (value == NM_METERED_INVALID) {
		if (   priv->ip4_config
		    && priv->ip4_state == IP_DONE
		    && nm_ip4_config_get_metered (priv->ip4_config))
			value = NM_METERED_GUESS_YES;
	}

	/* Otherwise look at connection type. For Bluetooth, we look at the type of
	 * Bluetooth sharing: for PANU/DUN (where we are receiving internet from
	 * another device) we set GUESS_YES; for NAP (where we are sharing internet
	 * to another device) we set GUESS_NO. We ignore WiMAX here as it’s no
	 * longer supported by NetworkManager. */
	if (   value == NM_METERED_INVALID
	    && nm_connection_is_type (connection, NM_SETTING_BLUETOOTH_SETTING_NAME)) {

		if (_nm_connection_get_setting_bluetooth_for_nap (connection)) {
			/* NAP types are not metered, but other types are. */
			value = NM_METERED_GUESS_NO;
		} else
			value = NM_METERED_GUESS_YES;
	}

	if (value == NM_METERED_INVALID) {
		if (   nm_connection_is_type (connection, NM_SETTING_GSM_SETTING_NAME)
		    || nm_connection_is_type (connection, NM_SETTING_CDMA_SETTING_NAME))
			value = NM_METERED_GUESS_YES;
		else
			value = NM_METERED_GUESS_NO;
	}

	if (value != priv->metered) {
		_LOGD (LOGD_DEVICE, "set metered value %d", value);
		priv->metered = value;
		_notify (self, PROP_METERED);
	}
}

static gboolean
_nm_device_check_connection_available (NMDevice *self,
                                       NMConnection *connection,
                                       NMDeviceCheckConAvailableFlags flags,
                                       const char *specific_object)
{
	NMDeviceState state;

	/* an unrealized software device is always available, hardware devices never. */
	if (!nm_device_is_real (self)) {
		if (nm_device_is_software (self))
			return nm_device_check_connection_compatible (self, connection);
		return FALSE;
	}

	state = nm_device_get_state (self);
	if (state < NM_DEVICE_STATE_UNMANAGED)
		return FALSE;
	if (   state < NM_DEVICE_STATE_UNAVAILABLE
	    && (   (   !NM_FLAGS_ANY (flags, NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST)
	            && !nm_device_get_managed (self, FALSE))
	        || (    NM_FLAGS_ANY (flags, NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST)
	            && !nm_device_get_managed (self, TRUE))))
		return FALSE;
	if (   state < NM_DEVICE_STATE_DISCONNECTED
	    && !nm_device_is_software (self)
	    && (   (   !NM_FLAGS_ANY (flags, NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST)
	            && !nm_device_is_available (self, NM_DEVICE_CHECK_DEV_AVAILABLE_NONE))
	        || (    NM_FLAGS_ANY (flags, NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST)
	            && !nm_device_is_available (self, NM_DEVICE_CHECK_DEV_AVAILABLE_FOR_USER_REQUEST))))
		return FALSE;

	if (!nm_device_check_connection_compatible (self, connection))
		return FALSE;

	return NM_DEVICE_GET_CLASS (self)->check_connection_available (self, connection, flags, specific_object);
}

/**
 * nm_device_check_connection_available():
 * @self: the #NMDevice
 * @connection: the #NMConnection to check for availability
 * @flags: flags to affect the decision making of whether a connection
 *   is available. Adding a flag can only make a connection more available,
 *   not less.
 * @specific_object: a device type dependent argument to further
 *   filter the result. Passing a non %NULL specific object can only reduce
 *   the availability of a connection.
 *
 * Check if @connection is available to be activated on @self.
 *
 * Returns: %TRUE if @connection can be activated on @self
 */
gboolean
nm_device_check_connection_available (NMDevice *self,
                                      NMConnection *connection,
                                      NMDeviceCheckConAvailableFlags flags,
                                      const char *specific_object)
{
	gboolean available;

	available = _nm_device_check_connection_available (self, connection, flags, specific_object);

#if NM_MORE_ASSERTS >= 2
	{
		/* The meaning of the flags is so that *adding* a flag relaxes a condition, thus making
		 * the device *more* available. Assert against that requirement by testing all the flags. */
		NMDeviceCheckConAvailableFlags i, j, k;
		gboolean available_all[NM_DEVICE_CHECK_CON_AVAILABLE_ALL + 1] = { FALSE };

		for (i = 0; i <= NM_DEVICE_CHECK_CON_AVAILABLE_ALL; i++)
			available_all[i] = _nm_device_check_connection_available (self, connection, i, specific_object);

		for (i = 0; i <= NM_DEVICE_CHECK_CON_AVAILABLE_ALL; i++) {
			for (j = 1; j <= NM_DEVICE_CHECK_CON_AVAILABLE_ALL; j <<= 1) {
				if (NM_FLAGS_ANY (i, j)) {
					k = i & ~j;
					nm_assert (   available_all[i] == available_all[k]
					           || available_all[i]);
				}
			}
		}
	}
#endif

	return available;
}

static gboolean
available_connections_del_all (NMDevice *self)
{
	if (g_hash_table_size (self->_priv->available_connections) == 0)
		return FALSE;
	g_hash_table_remove_all (self->_priv->available_connections);
	return TRUE;
}

static gboolean
available_connections_add (NMDevice *self, NMConnection *connection)
{
	return g_hash_table_add (self->_priv->available_connections, g_object_ref (connection));
}

static gboolean
available_connections_del (NMDevice *self, NMConnection *connection)
{
	return g_hash_table_remove (self->_priv->available_connections, connection);
}

static gboolean
check_connection_available (NMDevice *self,
                            NMConnection *connection,
                            NMDeviceCheckConAvailableFlags flags,
                            const char *specific_object)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

	/* Connections which require a network connection are not available when
	 * the device has no carrier, even with ignore-carrer=TRUE.
	 */
	if (   priv->carrier
	    || !connection_requires_carrier (connection))
		return TRUE;

	if (   NM_FLAGS_HAS (flags, _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_WAITING_CARRIER)
	    && priv->carrier_wait_id != 0) {
		/* The device has no carrier though the connection requires it.
		 *
		 * If we are still waiting for carrier, the connection is available
		 * for an explicit user-request. */
		return TRUE;
	}

	/* master types are always available even without carrier.
	 * Making connection non-available would un-enslave slaves which
	 * is not desired. */
	if (nm_device_is_master (self))
		return TRUE;

	return FALSE;
}

void
nm_device_recheck_available_connections (NMDevice *self)
{
	NMDevicePrivate *priv;
	NMSettingsConnection *const*connections;
	gboolean changed = FALSE;
	GHashTableIter h_iter;
	NMConnection *connection;
	guint i;
	gs_unref_hashtable GHashTable *prune_list = NULL;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE(self);

	if (g_hash_table_size (priv->available_connections) > 0) {
		prune_list = g_hash_table_new (nm_direct_hash, NULL);
		g_hash_table_iter_init (&h_iter, priv->available_connections);
		while (g_hash_table_iter_next (&h_iter, (gpointer *) &connection, NULL))
			g_hash_table_add (prune_list, connection);
	}

	connections = nm_settings_get_connections (priv->settings, NULL);
	for (i = 0; connections[i]; i++) {
		connection = (NMConnection *) connections[i];

		if (nm_device_check_connection_available (self,
		                                          connection,
		                                          NM_DEVICE_CHECK_CON_AVAILABLE_NONE,
		                                          NULL)) {
			if (available_connections_add (self, connection))
				changed = TRUE;
			if (prune_list)
				g_hash_table_remove (prune_list, connection);
		}
	}

	if (prune_list) {
		g_hash_table_iter_init (&h_iter, prune_list);
		while (g_hash_table_iter_next (&h_iter, (gpointer *) &connection, NULL)) {
			if (available_connections_del (self, connection))
				changed = TRUE;
		}
	}

	if (changed)
		_notify (self, PROP_AVAILABLE_CONNECTIONS);
	available_connections_check_delete_unrealized (self);
}

/**
 * nm_device_get_best_connection:
 * @self: the #NMDevice
 * @specific_object: a specific object path if any
 * @error: reason why no connection was returned
 *
 * Returns a connection that's most suitable for user-initiated activation
 * of a device, optionally with a given specific object.
 *
 * Returns: the #NMSettingsConnection or %NULL (setting an @error)
 */
NMSettingsConnection *
nm_device_get_best_connection (NMDevice *self,
                               const char *specific_object,
                               GError **error)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMSettingsConnection *connection = NULL;
	NMSettingsConnection *candidate;
	guint64 best_timestamp = 0;
	GHashTableIter iter;

	g_hash_table_iter_init (&iter, priv->available_connections);
	while (g_hash_table_iter_next (&iter, (gpointer) &candidate, NULL)) {
		guint64 candidate_timestamp = 0;

		/* If a specific object is given, only include connections that are
		 * compatible with it.
		 */
		if (    specific_object /* << Optimization: we know that the connection is available without @specific_object.  */
		    && !nm_device_check_connection_available (self,
		                                              NM_CONNECTION (candidate),
		                                              _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST,
		                                              specific_object))
			continue;

		nm_settings_connection_get_timestamp (candidate, &candidate_timestamp);
		if (!connection || (candidate_timestamp > best_timestamp)) {
			connection = candidate;
			best_timestamp = candidate_timestamp;
		}
	}

	if (!connection) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
		             "The device '%s' has no connections available for activation.",
		              nm_device_get_iface (self));
	}

	return connection;
}

static void
cp_connection_added_or_updated (NMDevice *self, NMConnection *connection)
{
	gboolean changed;

	g_return_if_fail (NM_IS_DEVICE (self));
	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (connection));

	if (nm_device_check_connection_available (self,
	                                          connection,
	                                          _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST,
	                                          NULL))
		changed = available_connections_add (self, connection);
	else
		changed = available_connections_del (self, connection);

	if (changed) {
		_notify (self, PROP_AVAILABLE_CONNECTIONS);
		available_connections_check_delete_unrealized (self);
	}
}

static void
cp_connection_added (NMConnectionProvider *cp, NMConnection *connection, gpointer user_data)
{
	cp_connection_added_or_updated (user_data, connection);
}

static void
cp_connection_updated (NMConnectionProvider *cp, NMConnection *connection, gboolean by_user, gpointer user_data)
{
	cp_connection_added_or_updated (user_data, connection);
}

static void
cp_connection_removed (NMConnectionProvider *cp, NMConnection *connection, gpointer user_data)
{
	NMDevice *self = user_data;

	g_return_if_fail (NM_IS_DEVICE (self));

	if (available_connections_del (self, connection)) {
		_notify (self, PROP_AVAILABLE_CONNECTIONS);
		available_connections_check_delete_unrealized (self);
	}
}

gboolean
nm_device_supports_vlans (NMDevice *self)
{
	return nm_platform_link_supports_vlans (nm_device_get_platform (self), nm_device_get_ifindex (self));
}

/**
 * nm_device_add_pending_action():
 * @self: the #NMDevice to add the pending action to
 * @action: a static string that identifies the action. The string instance must
 *   stay valid until the pending action is removed (that is, the string is
 *   not cloned, but ownership stays with the caller).
 * @assert_not_yet_pending: if %TRUE, assert that the @action is currently not yet pending.
 * Otherwise, ignore duplicate scheduling of the same action silently.
 *
 * Adds a pending action to the device.
 *
 * Returns: %TRUE if the action was added (and not already added before). %FALSE
 * if the same action is already scheduled. In the latter case, the action was not scheduled
 * a second time.
 */
gboolean
nm_device_add_pending_action (NMDevice *self, const char *action, gboolean assert_not_yet_pending)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	GSList *iter;
	guint count = 0;

	g_return_val_if_fail (action, FALSE);

	/* Check if the action is already pending. Cannot add duplicate actions */
	for (iter = priv->pending_actions; iter; iter = iter->next) {
		if (!strcmp (action, iter->data)) {
			if (assert_not_yet_pending) {
				_LOGW (LOGD_DEVICE, "add_pending_action (%d): '%s' already pending",
				       count + g_slist_length (iter), action);
				g_return_val_if_reached (FALSE);
			} else {
				_LOGT (LOGD_DEVICE, "add_pending_action (%d): '%s' already pending (expected)",
				       count + g_slist_length (iter), action);
			}
			return FALSE;
		}
		count++;
	}

	priv->pending_actions = g_slist_prepend (priv->pending_actions, (char *) action);
	count++;

	_LOGD (LOGD_DEVICE, "add_pending_action (%d): '%s'", count, action);

	if (count == 1)
		_notify (self, PROP_HAS_PENDING_ACTION);

	return TRUE;
}

/**
 * nm_device_remove_pending_action():
 * @self: the #NMDevice to remove the pending action from
 * @action: a string that identifies the action.
 * @assert_is_pending: if %TRUE, assert that the @action is pending.
 * If %FALSE, don't do anything if the current action is not pending and
 * return %FALSE.
 *
 * Removes a pending action previously added by nm_device_add_pending_action().
 *
 * Returns: whether the @action was pending and is now removed.
 */
gboolean
nm_device_remove_pending_action (NMDevice *self, const char *action, gboolean assert_is_pending)
{
	NMDevicePrivate *priv;
	GSList *iter, *next;
	guint count = 0;

	g_return_val_if_fail (self, FALSE);
	g_return_val_if_fail (action, FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);

	for (iter = priv->pending_actions; iter; iter = next) {
		next = iter->next;
		if (!strcmp (action, iter->data)) {
			_LOGD (LOGD_DEVICE, "remove_pending_action (%d): '%s'",
			       count + g_slist_length (iter->next), /* length excluding 'iter' */
			       action);
			priv->pending_actions = g_slist_delete_link (priv->pending_actions, iter);
			if (priv->pending_actions == NULL)
				_notify (self, PROP_HAS_PENDING_ACTION);
			return TRUE;
		}
		count++;
	}

	if (assert_is_pending) {
		_LOGW (LOGD_DEVICE, "remove_pending_action (%d): '%s' not pending", count, action);
		g_return_val_if_reached (FALSE);
	} else
		_LOGT (LOGD_DEVICE, "remove_pending_action (%d): '%s' not pending (expected)", count, action);

	return FALSE;
}

gboolean
nm_device_has_pending_action (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->pending_actions)
		return TRUE;

	if (   nm_device_is_real (self)
	    && nm_device_get_unmanaged_flags (self, NM_UNMANAGED_PLATFORM_INIT)) {
		/* as long as the platform link is not yet initialized, we have a pending
		 * action. */
		return TRUE;
	}

	return FALSE;
}

/*****************************************************************************/

static void
_cancel_activation (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->fw_call) {
		nm_firewall_manager_cancel_call (priv->fw_call);
		nm_assert (!priv->fw_call);
		priv->fw_call = NULL;
		priv->fw_state = FIREWALL_STATE_INITIALIZED;
	}

	ip_check_gw_ping_cleanup (self);

	/* Break the activation chain */
	activation_source_clear (self, AF_INET);
	activation_source_clear (self, AF_INET6);
}

static void
_cleanup_generic_pre (NMDevice *self, CleanupType cleanup_type)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	_cancel_activation (self);

	if (cleanup_type != CLEANUP_TYPE_KEEP) {
		nm_manager_device_route_metric_clear (nm_manager_get (),
		                                      nm_device_get_ip_ifindex (self));
	}

	if (   cleanup_type == CLEANUP_TYPE_DECONFIGURE
	    && priv->fw_state >= FIREWALL_STATE_INITIALIZED
	    && priv->fw_mgr
	    && !nm_device_sys_iface_state_is_external (self)) {
		nm_firewall_manager_remove_from_zone (priv->fw_mgr,
		                                      nm_device_get_ip_iface (self),
		                                      NULL,
		                                      NULL,
		                                      NULL);
	}
	priv->fw_state = FIREWALL_STATE_UNMANAGED;
	g_clear_object (&priv->fw_mgr);

	queued_state_clear (self);

	_cleanup_ip4_pre (self, cleanup_type);
	_cleanup_ip6_pre (self, cleanup_type);
}

static void
_cleanup_generic_post (NMDevice *self, CleanupType cleanup_type)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	priv->v4_commit_first_time = TRUE;
	priv->v6_commit_first_time = TRUE;

	priv->v4_route_table_initialized = FALSE;
	priv->v6_route_table_initialized = FALSE;

	priv->default_route_metric_penalty_ip4_has = FALSE;
	priv->default_route_metric_penalty_ip6_has = FALSE;

	priv->linklocal6_dad_counter = 0;

	/* Clean up IP configs; this does not actually deconfigure the
	 * interface; the caller must flush routes and addresses explicitly.
	 */
	nm_device_set_ip4_config (self, NULL, TRUE, NULL);
	nm_device_set_ip6_config (self, NULL, TRUE);
	g_clear_object (&priv->proxy_config);
	g_clear_object (&priv->con_ip4_config);
	applied_config_clear (&priv->dev_ip4_config);
	applied_config_clear (&priv->wwan_ip4_config);
	g_clear_object (&priv->ext_ip4_config);
	g_clear_object (&priv->ip4_config);
	g_clear_object (&priv->con_ip6_config);
	applied_config_clear (&priv->ac_ip6_config);
	g_clear_object (&priv->ext_ip6_config);
	g_clear_object (&priv->ext_ip6_config_captured);
	applied_config_clear (&priv->wwan_ip6_config);
	g_clear_object (&priv->ip6_config);
	g_clear_object (&priv->dad6_ip6_config);

	g_clear_pointer (&priv->rt6_temporary_not_available, g_hash_table_unref);
	nm_clear_g_source (&priv->rt6_temporary_not_available_id);

	g_slist_free_full (priv->vpn4_configs, g_object_unref);
	priv->vpn4_configs = NULL;
	g_slist_free_full (priv->vpn6_configs, g_object_unref);
	priv->vpn6_configs = NULL;

	/* We no longer accept the delegations. nm_device_set_ip6_config(NULL)
	 * above disables them. */
	nm_assert (priv->needs_ip6_subnet == FALSE);

	if (priv->act_request) {
		nm_active_connection_set_default (NM_ACTIVE_CONNECTION (priv->act_request), AF_INET, FALSE);

		priv->master_ready_handled = FALSE;
		nm_clear_g_signal_handler (priv->act_request, &priv->master_ready_id);

		act_request_set (self, NULL);
	}

	/* Clear legacy IPv4 address property */
	if (priv->ip4_address) {
		priv->ip4_address = 0;
		_notify (self, PROP_IP4_ADDRESS);
	}

	if (cleanup_type == CLEANUP_TYPE_DECONFIGURE) {
		/* Check if the device was deactivated, and if so, delete_link.
		 * Don't call delete_link synchronously because we are currently
		 * handling a state change -- which is not reentrant. */
		delete_on_deactivate_check_and_schedule (self, nm_device_get_ip_ifindex (self));
	}

	/* ip_iface should be cleared after flushing all routes and addreses, since
	 * those are identified by ip_iface, not by iface (which might be a tty
	 * or ATM device).
	 */
	_set_ip_ifindex (self, 0, NULL);
}

/*
 * nm_device_cleanup
 *
 * Remove a device's routing table entries and IP addresses.
 *
 */
static void
nm_device_cleanup (NMDevice *self, NMDeviceStateReason reason, CleanupType cleanup_type)
{
	NMDevicePrivate *priv;
	int ifindex;

	g_return_if_fail (NM_IS_DEVICE (self));

	if (reason == NM_DEVICE_STATE_REASON_NOW_MANAGED)
		_LOGD (LOGD_DEVICE, "preparing device");
	else
		_LOGD (LOGD_DEVICE, "deactivating device (reason '%s') [%d]", reason_to_string (reason), reason);

	/* Save whether or not we tried IPv6 for later */
	priv = NM_DEVICE_GET_PRIVATE (self);

	_cleanup_generic_pre (self, cleanup_type);

	/* Turn off kernel IPv6 */
	if (cleanup_type == CLEANUP_TYPE_DECONFIGURE) {
		set_disable_ipv6 (self, "1");
		nm_device_ipv6_sysctl_set (self, "accept_ra", "0");
		nm_device_ipv6_sysctl_set (self, "use_tempaddr", "0");
	}

	/* Call device type-specific deactivation */
	if (NM_DEVICE_GET_CLASS (self)->deactivate)
		NM_DEVICE_GET_CLASS (self)->deactivate (self);

	ifindex = nm_device_get_ip_ifindex (self);

	if (cleanup_type == CLEANUP_TYPE_DECONFIGURE) {
		/* master: release slaves */
		nm_device_master_release_slaves (self);

		/* Take out any entries in the routing table and any IP address the device had. */
		if (ifindex > 0) {
			NMPlatform *platform = nm_device_get_platform (self);

			nm_platform_ip_route_flush (platform, AF_UNSPEC, ifindex);
			nm_platform_ip_address_flush (platform, AF_UNSPEC, ifindex);
			nm_platform_tfilter_sync (platform, ifindex, NULL);
			nm_platform_qdisc_sync (platform, ifindex, NULL);
		}
	}

	if (ifindex > 0)
		nm_platform_ip4_dev_route_blacklist_set (nm_device_get_platform (self), ifindex, NULL);

	/* slave: mark no longer enslaved */
	if (   priv->master
	    && nm_platform_link_get_master (nm_device_get_platform (self), priv->ifindex) <= 0)
		nm_device_master_release_one_slave (priv->master, self, FALSE, NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);

	if (priv->lldp_listener)
		nm_lldp_listener_stop (priv->lldp_listener);

	nm_device_update_metered (self);

	/* during device cleanup, we want to reset the MAC address of the device
	 * to the initial state.
	 *
	 * We certainly want to do that when reaching the UNMANAGED state... */
	if (nm_device_get_state (self) <= NM_DEVICE_STATE_UNMANAGED)
		nm_device_hw_addr_reset (self, "unmanage");
	else {
		/* for other device states (UNAVAILABLE, DISCONNECTED), allow the
		 * device to overwrite the reset behavior, so that Wi-Fi can set
		 * a randomized MAC address used during scanning. */
		NM_DEVICE_GET_CLASS (self)->deactivate_reset_hw_addr (self);
	}

	priv->mtu_initialized = FALSE;
	if (priv->mtu_initial || priv->ip6_mtu_initial) {
		ifindex = nm_device_get_ip_ifindex (self);

		if (   ifindex > 0
		    && cleanup_type == CLEANUP_TYPE_DECONFIGURE) {
			_LOGT (LOGD_DEVICE, "mtu: reset device-mtu: %u, ipv6-mtu: %u, ifindex: %d",
			       (guint) priv->mtu_initial, (guint) priv->ip6_mtu_initial, ifindex);
			if (priv->mtu_initial) {
				nm_platform_link_set_mtu (nm_device_get_platform (self), ifindex, priv->mtu_initial);
				priv->carrier_wait_until_ms = nm_utils_get_monotonic_timestamp_ms () + CARRIER_WAIT_TIME_AFTER_MTU_MS;
			}
			if (priv->ip6_mtu_initial) {
				char sbuf[64];

				nm_device_ipv6_sysctl_set (self, "mtu",
				                           nm_sprintf_buf (sbuf, "%u", (unsigned) priv->ip6_mtu_initial));
			}
		}
		priv->mtu_initial = 0;
		priv->ip6_mtu_initial = 0;
	}

	_cleanup_generic_post (self, cleanup_type);
}

static void
deactivate_reset_hw_addr (NMDevice *self)
{
	nm_device_hw_addr_reset (self, "deactivate");
}

static char *
find_dhcp4_address (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	const NMPlatformIP4Address *a;
	NMDedupMultiIter ipconf_iter;

	if (!priv->ip4_config)
		return NULL;

	nm_ip_config_iter_ip4_address_for_each (&ipconf_iter, priv->ip4_config, &a) {
		if (a->addr_source == NM_IP_CONFIG_SOURCE_DHCP)
			return g_strdup (nm_utils_inet4_ntop (a->address, NULL));
	}
	return NULL;
}

void
nm_device_spawn_iface_helper (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean configured = FALSE;
	NMConnection *connection;
	GError *error = NULL;
	const char *method;
	GPtrArray *argv;
	gs_free char *dhcp4_address = NULL;
	char *logging_backend;
	NMUtilsStableType stable_type;
	const char *stable_id;

	if (priv->state != NM_DEVICE_STATE_ACTIVATED)
		return;
	if (!nm_device_can_assume_connections (self))
		return;

	connection = nm_device_get_applied_connection (self);
	g_assert (connection);

	argv = g_ptr_array_sized_new (10);
	g_ptr_array_set_free_func (argv, g_free);

	g_ptr_array_add (argv, g_strdup (LIBEXECDIR "/nm-iface-helper"));
	g_ptr_array_add (argv, g_strdup ("--ifname"));
	g_ptr_array_add (argv, g_strdup (nm_device_get_ip_iface (self)));
	g_ptr_array_add (argv, g_strdup ("--uuid"));
	g_ptr_array_add (argv, g_strdup (nm_connection_get_uuid (connection)));

	stable_id = _get_stable_id (self, connection, &stable_type);
	if (stable_id && stable_type != NM_UTILS_STABLE_TYPE_UUID) {
		g_ptr_array_add (argv, g_strdup ("--stable-id"));
		g_ptr_array_add (argv, g_strdup_printf ("%d %s", (int) stable_type, stable_id));
	}

	logging_backend = nm_config_get_is_debug (nm_config_get ())
	                  ? g_strdup ("debug")
	                  : nm_config_data_get_value (NM_CONFIG_GET_DATA_ORIG,
	                                              NM_CONFIG_KEYFILE_GROUP_LOGGING,
	                                              NM_CONFIG_KEYFILE_KEY_LOGGING_BACKEND,
	                                              NM_CONFIG_GET_VALUE_STRIP | NM_CONFIG_GET_VALUE_NO_EMPTY);
	if (logging_backend) {
		g_ptr_array_add (argv, g_strdup ("--logging-backend"));
		g_ptr_array_add (argv, logging_backend);
	}

	g_ptr_array_add (argv, g_strdup ("--log-level"));
	g_ptr_array_add (argv, g_strdup (nm_logging_level_to_string ()));

	g_ptr_array_add (argv, g_strdup ("--log-domains"));
	g_ptr_array_add (argv, g_strdup (nm_logging_domains_to_string ()));

	dhcp4_address = find_dhcp4_address (self);

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	if (g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0) {
		NMSettingIPConfig *s_ip4;

		s_ip4 = nm_connection_get_setting_ip4_config (connection);
		g_assert (s_ip4);

		g_ptr_array_add (argv, g_strdup ("--priority4"));
		g_ptr_array_add (argv, g_strdup_printf ("%u", nm_device_get_route_metric (self, AF_INET)));

		g_ptr_array_add (argv, g_strdup ("--dhcp4"));
		g_ptr_array_add (argv, g_strdup (dhcp4_address));
		if (nm_setting_ip_config_get_may_fail (s_ip4) == FALSE)
			g_ptr_array_add (argv, g_strdup ("--dhcp4-required"));

		if (priv->dhcp4.client) {
			const char *hostname;
			GBytes *client_id;

			client_id = nm_dhcp_client_get_client_id (priv->dhcp4.client);
			if (client_id) {
				g_ptr_array_add (argv, g_strdup ("--dhcp4-clientid"));
				g_ptr_array_add (argv,
				                 _nm_utils_bin2str (g_bytes_get_data (client_id, NULL),
				                                    g_bytes_get_size (client_id),
				                                    FALSE));
			}

			hostname = nm_dhcp_client_get_hostname (priv->dhcp4.client);
			if (hostname) {
				if (nm_dhcp_client_get_use_fqdn (priv->dhcp4.client))
					g_ptr_array_add (argv, g_strdup ("--dhcp4-fqdn"));
				else
					g_ptr_array_add (argv, g_strdup ("--dhcp4-hostname"));
				g_ptr_array_add (argv, g_strdup (hostname));
			}
		}

		configured = TRUE;
	}

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
	if (g_strcmp0 (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0) {
		NMSettingIPConfig *s_ip6;
		NMUtilsIPv6IfaceId iid = NM_UTILS_IPV6_IFACE_ID_INIT;

		s_ip6 = nm_connection_get_setting_ip6_config (connection);
		g_assert (s_ip6);

		g_ptr_array_add (argv, g_strdup ("--priority6"));
		g_ptr_array_add (argv, g_strdup_printf ("%u", nm_device_get_route_metric (self, AF_INET6)));

		g_ptr_array_add (argv, g_strdup ("--slaac"));

		if (nm_setting_ip_config_get_may_fail (s_ip6) == FALSE)
			g_ptr_array_add (argv, g_strdup ("--slaac-required"));

		g_ptr_array_add (argv, g_strdup ("--slaac-tempaddr"));
		g_ptr_array_add (argv, g_strdup_printf ("%d", priv->ndisc_use_tempaddr));

		if (nm_device_get_ip_iface_identifier (self, &iid, FALSE)) {
			g_ptr_array_add (argv, g_strdup ("--iid"));
			g_ptr_array_add (argv,
			                 _nm_utils_bin2str (iid.id_u8,
			                                    sizeof (NMUtilsIPv6IfaceId),
			                                    FALSE));
		}

		g_ptr_array_add (argv, g_strdup ("--addr-gen-mode"));
		g_ptr_array_add (argv, g_strdup_printf ("%d", nm_setting_ip6_config_get_addr_gen_mode (NM_SETTING_IP6_CONFIG (s_ip6))));

		configured = TRUE;
	}

	if (configured) {
		GPid pid;

		g_ptr_array_add (argv, NULL);

		if (nm_logging_enabled (LOGL_DEBUG, LOGD_DEVICE)) {
			char *tmp;

			tmp = g_strjoinv (" ", (char **) argv->pdata);
			_LOGD (LOGD_DEVICE, "running '%s'", tmp);
			g_free (tmp);
		}

		if (g_spawn_async (NULL, (char **) argv->pdata, NULL,
		                   G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, &error)) {
			_LOGI (LOGD_DEVICE, "spawned helper PID %u", (guint) pid);
		} else {
			_LOGW (LOGD_DEVICE, "failed to spawn helper: %s", error->message);
			g_error_free (error);
		}
	}

	g_ptr_array_unref (argv);
}

/*****************************************************************************/

static gboolean
ip_config_valid (NMDeviceState state)
{
	return (state == NM_DEVICE_STATE_UNMANAGED) ||
	        (state >= NM_DEVICE_STATE_IP_CHECK &&
	         state <= NM_DEVICE_STATE_DEACTIVATING);
}

static void
notify_ip_properties (NMDevice *self)
{
	_notify (self, PROP_IP_IFACE);
	_notify (self, PROP_IP4_CONFIG);
	_notify (self, PROP_DHCP4_CONFIG);
	_notify (self, PROP_IP6_CONFIG);
	_notify (self, PROP_DHCP6_CONFIG);
}

static void
ip6_managed_setup (NMDevice *self)
{
	set_nm_ipv6ll (self, TRUE);
	set_disable_ipv6 (self, "1");
	nm_device_ipv6_sysctl_set (self, "accept_ra_defrtr", "0");
	nm_device_ipv6_sysctl_set (self, "accept_ra_pinfo", "0");
	nm_device_ipv6_sysctl_set (self, "accept_ra_rtr_pref", "0");
	nm_device_ipv6_sysctl_set (self, "use_tempaddr", "0");
	nm_device_ipv6_sysctl_set (self, "forwarding", "0");
}

static void
deactivate_async_ready (NMDevice *self,
                        GAsyncResult *res,
                        gpointer user_data)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceStateReason reason = GPOINTER_TO_UINT (user_data);
	GError *error = NULL;

	NM_DEVICE_GET_CLASS (self)->deactivate_async_finish (self, res, &error);

	/* If operation cancelled, just return */
	if (   g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)
	    || (priv->deactivating_cancellable && g_cancellable_is_cancelled (priv->deactivating_cancellable))) {
		_LOGW (LOGD_DEVICE, "Deactivation cancelled");
	} else {
		/* In every other case, transition to the DISCONNECTED state */
		if (error) {
			_LOGW (LOGD_DEVICE, "Deactivation failed: %s",
			       error->message);
		}
		nm_device_queue_state (self, NM_DEVICE_STATE_DISCONNECTED, reason);
	}

	g_clear_object (&priv->deactivating_cancellable);
	g_clear_error (&error);
}

static void
deactivate_dispatcher_complete (guint call_id, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceStateReason reason;

	g_return_if_fail (call_id == priv->dispatcher.call_id);
	g_return_if_fail (priv->dispatcher.post_state == NM_DEVICE_STATE_DISCONNECTED);

	reason = priv->dispatcher.post_state_reason;

	priv->dispatcher.call_id = 0;
	priv->dispatcher.post_state = NM_DEVICE_STATE_UNKNOWN;
	priv->dispatcher.post_state_reason = NM_DEVICE_STATE_REASON_NONE;

	if (nm_clear_g_cancellable (&priv->deactivating_cancellable))
		g_warn_if_reached ();

	if (   NM_DEVICE_GET_CLASS (self)->deactivate_async
	    && NM_DEVICE_GET_CLASS (self)->deactivate_async_finish) {
		priv->deactivating_cancellable = g_cancellable_new ();
		NM_DEVICE_GET_CLASS (self)->deactivate_async (self,
		                                              priv->deactivating_cancellable,
		                                              (GAsyncReadyCallback) deactivate_async_ready,
		                                              GUINT_TO_POINTER (reason));
	} else
		nm_device_queue_state (self, NM_DEVICE_STATE_DISCONNECTED, reason);
}

static void
_set_state_full (NMDevice *self,
                 NMDeviceState state,
                 NMDeviceStateReason reason,
                 gboolean quitting)
{
	NMDevicePrivate *priv;
	NMDeviceState old_state;
	NMActRequest *req;
	gboolean no_firmware = FALSE;
	NMSettingsConnection *connection;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);

	/* Track re-entry */
	g_warn_if_fail (priv->in_state_changed == FALSE);

	old_state = priv->state;

	/* Do nothing if state isn't changing, but as a special case allow
	 * re-setting UNAVAILABLE if the device is missing firmware so that we
	 * can retry device initialization.
	 */
	if (   (priv->state == state)
	    && (   state != NM_DEVICE_STATE_UNAVAILABLE
	        || !priv->firmware_missing)) {
		_LOGD (LOGD_DEVICE, "state change: %s -> %s (reason '%s', sys-iface-state: '%s'%s)",
		       nm_device_state_to_str (old_state),
		       nm_device_state_to_str (state),
		       reason_to_string (reason),
		       _sys_iface_state_to_str (priv->sys_iface_state),
		       priv->firmware_missing ? ", missing firmware" : "");
		return;
	}

	_LOGI (LOGD_DEVICE, "state change: %s -> %s (reason '%s', sys-iface-state: '%s')",
	       nm_device_state_to_str (old_state),
	       nm_device_state_to_str (state),
	       reason_to_string (reason),
	       _sys_iface_state_to_str (priv->sys_iface_state));

	priv->in_state_changed = TRUE;

	priv->state = state;
	priv->state_reason = reason;

	queued_state_clear (self);

	dispatcher_cleanup (self);
	if (priv->deactivating_cancellable)
		g_cancellable_cancel (priv->deactivating_cancellable);

	/* Cache the activation request for the dispatcher */
	req = nm_g_object_ref (priv->act_request);

	if (   state >  NM_DEVICE_STATE_UNMANAGED
	    && state <= NM_DEVICE_STATE_ACTIVATED
	    && nm_device_state_reason_check (reason) == NM_DEVICE_STATE_REASON_NOW_MANAGED
	    && NM_IN_SET_TYPED (NMDeviceSysIfaceState,
	                        priv->sys_iface_state,
	                        NM_DEVICE_SYS_IFACE_STATE_EXTERNAL,
	                        NM_DEVICE_SYS_IFACE_STATE_ASSUME))
		nm_device_sys_iface_state_set (self, NM_DEVICE_SYS_IFACE_STATE_MANAGED);

	if (   state <= NM_DEVICE_STATE_DISCONNECTED
	    || state >= NM_DEVICE_STATE_ACTIVATED)
		priv->auth_retries = NM_DEVICE_AUTH_RETRIES_UNSET;

	if (state > NM_DEVICE_STATE_DISCONNECTED)
		nm_device_assume_state_reset (self);

	if (state <= NM_DEVICE_STATE_UNAVAILABLE) {
		if (available_connections_del_all (self))
			_notify (self, PROP_AVAILABLE_CONNECTIONS);
		if (old_state > NM_DEVICE_STATE_UNAVAILABLE)
			_clear_queued_act_request (priv);
	}

	/* Update the available connections list when a device first becomes available */
	if (state >= NM_DEVICE_STATE_DISCONNECTED && old_state < NM_DEVICE_STATE_DISCONNECTED)
		nm_device_recheck_available_connections (self);

	if (state <= NM_DEVICE_STATE_DISCONNECTED || state > NM_DEVICE_STATE_DEACTIVATING) {
		if (nm_clear_g_free (&priv->current_stable_id))
			_LOGT (LOGD_DEVICE, "stable-id: clear");
	}

	/* Handle the new state here; but anything that could trigger
	 * another state change should be done below.
	 */
	switch (state) {
	case NM_DEVICE_STATE_UNMANAGED:
		nm_device_set_firmware_missing (self, FALSE);
		if (old_state > NM_DEVICE_STATE_UNMANAGED) {
			if (priv->sys_iface_state != NM_DEVICE_SYS_IFACE_STATE_MANAGED) {
				nm_device_cleanup (self, reason,
				                   priv->sys_iface_state == NM_DEVICE_SYS_IFACE_STATE_REMOVED
				                       ? CLEANUP_TYPE_REMOVED
				                       : CLEANUP_TYPE_KEEP);
			} else {
				/* Clean up if the device is now unmanaged but was activated */
				if (nm_device_get_act_request (self))
					nm_device_cleanup (self, reason, CLEANUP_TYPE_DECONFIGURE);
				nm_device_take_down (self, TRUE);
				nm_device_hw_addr_reset (self, "unmanage");
				set_nm_ipv6ll (self, FALSE);
				restore_ip6_properties (self);
				break;
			}
		}
		break;
	case NM_DEVICE_STATE_UNAVAILABLE:
		if (old_state == NM_DEVICE_STATE_UNMANAGED) {
			save_ip6_properties (self);
			if (priv->sys_iface_state == NM_DEVICE_SYS_IFACE_STATE_MANAGED)
				ip6_managed_setup (self);
		}

		if (priv->sys_iface_state == NM_DEVICE_SYS_IFACE_STATE_MANAGED) {
			if (old_state == NM_DEVICE_STATE_UNMANAGED || priv->firmware_missing) {
				if (!nm_device_bring_up (self, TRUE, &no_firmware) && no_firmware)
					_LOGW (LOGD_PLATFORM, "firmware may be missing.");
				nm_device_set_firmware_missing (self, no_firmware ? TRUE : FALSE);
			}

			/* Ensure the device gets deactivated in response to stuff like
			 * carrier changes or rfkill.  But don't deactivate devices that are
			 * about to assume a connection since that defeats the purpose of
			 * assuming the device's existing connection.
			 *
			 * Note that we "deactivate" the device even when coming from
			 * UNMANAGED, to ensure that it's in a clean state.
			 */
			nm_device_cleanup (self, reason, CLEANUP_TYPE_DECONFIGURE);
		}
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		if (old_state > NM_DEVICE_STATE_DISCONNECTED) {
			/* Ensure devices that previously assumed a connection now have
			 * userspace IPv6LL enabled.
			 */
			set_nm_ipv6ll (self, TRUE);

			nm_device_cleanup (self, reason, CLEANUP_TYPE_DECONFIGURE);
		} else if (old_state < NM_DEVICE_STATE_DISCONNECTED) {
			if (priv->sys_iface_state == NM_DEVICE_SYS_IFACE_STATE_MANAGED) {
				/* Ensure IPv6 is set up as it may not have been done when
				 * entering the UNAVAILABLE state depending on the reason.
				 */
				ip6_managed_setup (self);
			}
		}
		break;
	case NM_DEVICE_STATE_PREPARE:
		nm_device_update_initial_hw_address (self);
		break;
	case NM_DEVICE_STATE_NEED_AUTH:
		if (old_state > NM_DEVICE_STATE_NEED_AUTH) {
			/* Clean up any half-done IP operations if the device's layer2
			 * finds out it needs authentication during IP config.
			 */
			_cleanup_ip4_pre (self, CLEANUP_TYPE_DECONFIGURE);
			_cleanup_ip6_pre (self, CLEANUP_TYPE_DECONFIGURE);
		}
		break;
	default:
		break;
	}

	/* Reset intern autoconnect flags when the device is activating or connected. */
	if (   state >= NM_DEVICE_STATE_PREPARE
	    && state <= NM_DEVICE_STATE_ACTIVATED)
		nm_device_autoconnect_blocked_unset (self, NM_DEVICE_AUTOCONNECT_BLOCKED_INTERNAL);

	_notify (self, PROP_STATE);
	_notify (self, PROP_STATE_REASON);
	nm_dbus_object_emit_signal (NM_DBUS_OBJECT (self),
	                            &interface_info_device,
	                            &signal_info_state_changed,
	                            "(uuu)",
	                            (guint32) state,
	                            (guint32) old_state,
	                            (guint32) reason);
	g_signal_emit (self, signals[STATE_CHANGED], 0, (guint) state, (guint) old_state, (guint) reason);

	/* Post-process the event after internal notification */

	switch (state) {
	case NM_DEVICE_STATE_UNAVAILABLE:
		/* If the device can activate now (ie, it's got a carrier, the supplicant
		 * is active, or whatever) schedule a delayed transition to DISCONNECTED
		 * to get things rolling.  The device can't transition immediately because
		 * we can't change states again from the state handler for a variety of
		 * reasons.
		 */
		if (nm_device_is_available (self, NM_DEVICE_CHECK_DEV_AVAILABLE_NONE)) {
			nm_device_queue_recheck_available (self,
			                                   NM_DEVICE_STATE_REASON_NONE,
			                                   NM_DEVICE_STATE_REASON_NONE);
		} else {
			_LOGD (LOGD_DEVICE, "device not yet available for transition to DISCONNECTED");
		}
		break;
	case NM_DEVICE_STATE_DEACTIVATING:
		_cancel_activation (self);

		/* We cache the ignore_carrier state to not react on config-reloads while the connection
		 * is active. But on deactivating, reset the ignore-carrier flag to the current state. */
		priv->ignore_carrier = nm_config_data_get_ignore_carrier (NM_CONFIG_GET_DATA, self);

		if (quitting) {
			nm_dispatcher_call_device_sync (NM_DISPATCHER_ACTION_PRE_DOWN,
			                                self, req);
		} else {
			priv->dispatcher.post_state = NM_DEVICE_STATE_DISCONNECTED;
			priv->dispatcher.post_state_reason = reason;
			if (!nm_dispatcher_call_device (NM_DISPATCHER_ACTION_PRE_DOWN,
			                                self,
			                                req,
			                                deactivate_dispatcher_complete,
			                                self,
			                                &priv->dispatcher.call_id)) {
				/* Just proceed on errors */
				deactivate_dispatcher_complete (0, self);
			}
		}

		nm_pacrunner_manager_remove_clear (priv->pacrunner_manager,
		                                   &priv->pacrunner_call_id);
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		if (   priv->queued_act_request
		    && !priv->queued_act_request_is_waiting_for_carrier) {
			gs_unref_object NMActRequest *queued_req = NULL;

			queued_req = g_steal_pointer (&priv->queued_act_request);
			_device_activate (self, queued_req);
		}
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		_LOGI (LOGD_DEVICE, "Activation: successful, device activated.");
		nm_device_update_metered (self);
		nm_dispatcher_call_device (NM_DISPATCHER_ACTION_UP,
		                           self,
		                           req,
		                           NULL, NULL, NULL);

		if (priv->proxy_config)
			_pacrunner_manager_send (self);
		break;
	case NM_DEVICE_STATE_FAILED:
		/* Usually upon failure the activation chain is interrupted in
		 * one of the stages; but in some cases the device fails for
		 * external events (as a failure of master connection) while
		 * the activation sequence is running and so we need to ensure
		 * that the chain is terminated here.
		 */
		_cancel_activation (self);

		if (nm_device_sys_iface_state_is_external_or_assume (self)) {
			/* Avoid tearing down assumed connection, assume it's connected */
			nm_device_queue_state (self,
			                       NM_DEVICE_STATE_ACTIVATED,
			                       NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
			break;
		}

		connection = nm_device_get_settings_connection (self);
		_LOGW (LOGD_DEVICE | LOGD_WIFI,
		       "Activation: failed for connection '%s'",
		       connection ? nm_settings_connection_get_id (connection) : "<unknown>");

		/* Notify any slaves of the unexpected failure */
		nm_device_master_release_slaves (self);

		/* If the connection doesn't yet have a timestamp, set it to zero so that
		 * we can distinguish between connections we've tried to activate and have
		 * failed (zero timestamp), connections that succeeded (non-zero timestamp),
		 * and those we haven't tried yet (no timestamp).
		 */
		if (connection && !nm_settings_connection_get_timestamp (connection, NULL))
			nm_settings_connection_update_timestamp (connection, (guint64) 0, TRUE);

		/* Schedule the transition to DISCONNECTED.  The device can't transition
		 * immediately because we can't change states again from the state
		 * handler for a variety of reasons.
		 */
		nm_device_queue_state (self, NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_NONE);
		break;
	case NM_DEVICE_STATE_IP_CHECK:
		if (   priv->fw_state >= FIREWALL_STATE_INITIALIZED
		    && priv->ip_iface
		    && !nm_device_sys_iface_state_is_external (self)) {
			priv->fw_state = FIREWALL_STATE_WAIT_IP_CONFIG;
			fw_change_zone (self);
		} else
			nm_device_start_ip_check (self);

		/* IP-related properties are only valid when the device has IP configuration;
		 * now that it does, ensure their change notifications are emitted.
		 */
		notify_ip_properties (self);
		break;
	case NM_DEVICE_STATE_SECONDARIES:
		ip_check_gw_ping_cleanup (self);
		_LOGD (LOGD_DEVICE, "device entered SECONDARIES state");
		break;
	default:
		break;
	}

	if (state > NM_DEVICE_STATE_DISCONNECTED)
		delete_on_deactivate_unschedule (self);

	if (   (old_state == NM_DEVICE_STATE_ACTIVATED || old_state == NM_DEVICE_STATE_DEACTIVATING)
	    && (state != NM_DEVICE_STATE_DEACTIVATING)) {
		if (quitting) {
			nm_dispatcher_call_device_sync (NM_DISPATCHER_ACTION_DOWN,
			                                self, req);
		} else {
			nm_dispatcher_call_device (NM_DISPATCHER_ACTION_DOWN,
			                           self,
			                           req,
			                           NULL, NULL, NULL);
		}
	}

	/* IP-related properties are only valid when the device has IP configuration.
	 * If it no longer does, ensure their change notifications are emitted.
	 */
	if (ip_config_valid (old_state) && !ip_config_valid (state))
	    notify_ip_properties (self);

	concheck_periodic_update (self);

	/* Dispose of the cached activation request */
	if (req)
		g_object_unref (req);

	priv->in_state_changed = FALSE;

	if ((old_state > NM_DEVICE_STATE_UNMANAGED) != (state > NM_DEVICE_STATE_UNMANAGED))
		_notify (self, PROP_MANAGED);
}

void
nm_device_state_changed (NMDevice *self,
                         NMDeviceState state,
                         NMDeviceStateReason reason)
{
	_set_state_full (self, state, reason, FALSE);
}

static gboolean
queued_state_set (gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMDeviceState new_state;
	NMDeviceStateReason new_reason;

	nm_assert (priv->queued_state.id);

	_LOGD (LOGD_DEVICE, "queue-state[%s, reason:%s, id:%u]: %s",
	       nm_device_state_to_str (priv->queued_state.state),
	       reason_to_string (priv->queued_state.reason),
	       priv->queued_state.id,
	       "change state");

	/* Clear queued state struct before triggering state change, since
	 * the state change may queue another state.
	 */
	priv->queued_state.id = 0;
	new_state = priv->queued_state.state;
	new_reason = priv->queued_state.reason;

	nm_device_state_changed (self, new_state, new_reason);
	nm_device_remove_pending_action (self, queued_state_to_string (new_state), TRUE);

	return G_SOURCE_REMOVE;
}

void
nm_device_queue_state (NMDevice *self,
                       NMDeviceState state,
                       NMDeviceStateReason reason)
{
	NMDevicePrivate *priv;

	g_return_if_fail (NM_IS_DEVICE (self));

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->queued_state.id && priv->queued_state.state == state) {
		_LOGD (LOGD_DEVICE, "queue-state[%s, reason:%s, id:%u]: %s%s%s%s",
		       nm_device_state_to_str (priv->queued_state.state),
		       reason_to_string (priv->queued_state.reason),
		       priv->queued_state.id,
		       "ignore queuing same state change",
		       NM_PRINT_FMT_QUOTED (priv->queued_state.reason != reason,
		                            " (reason differs: ", reason_to_string (reason), ")", ""));
		return;
	}

	/* Add pending action for the new state before clearing the queued states, so
	 * that we don't accidently pop all pending states and reach 'startup complete'  */
	nm_device_add_pending_action (self, queued_state_to_string (state), TRUE);

	/* We should only ever have one delayed state transition at a time */
	if (priv->queued_state.id) {
		_LOGW (LOGD_DEVICE, "queue-state[%s, reason:%s, id:%u]: %s",
		       nm_device_state_to_str (priv->queued_state.state),
		       reason_to_string (priv->queued_state.reason),
		       priv->queued_state.id,
		       "replace previously queued state change");
		nm_clear_g_source (&priv->queued_state.id);
		nm_device_remove_pending_action (self, queued_state_to_string (priv->queued_state.state), TRUE);
	}

	priv->queued_state.state = state;
	priv->queued_state.reason = reason;
	priv->queued_state.id = g_idle_add (queued_state_set, self);

	_LOGD (LOGD_DEVICE, "queue-state[%s, reason:%s, id:%u]: %s",
	       nm_device_state_to_str (state),
	       reason_to_string (reason),
	       priv->queued_state.id,
	       "queue state change");
}

static void
queued_state_clear (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (!priv->queued_state.id)
		return;

	_LOGD (LOGD_DEVICE, "queue-state[%s, reason:%s, id:%u]: %s",
	       nm_device_state_to_str (priv->queued_state.state),
	       reason_to_string (priv->queued_state.reason),
	       priv->queued_state.id,
	       "clear queued state change");
	nm_clear_g_source (&priv->queued_state.id);
	nm_device_remove_pending_action (self, queued_state_to_string (priv->queued_state.state), TRUE);
}

NMDeviceState
nm_device_get_state (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_DEVICE_STATE_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (self)->state;
}

/*****************************************************************************/
/* NMConfigDevice interface related stuff */

const char *
nm_device_get_hw_address (NMDevice *self)
{
	NMDevicePrivate *priv;
	char buf[NM_UTILS_HWADDR_LEN_MAX];
	gsize l;

	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	priv = NM_DEVICE_GET_PRIVATE (self);

	nm_assert (   (!priv->hw_addr && priv->hw_addr_len == 0)
	           || (   priv->hw_addr
	               && _nm_utils_hwaddr_aton (priv->hw_addr, buf, sizeof (buf), &l)
	               && l == priv->hw_addr_len));

	return priv->hw_addr;
}

gboolean
nm_device_update_hw_address (NMDevice *self)
{
	NMDevicePrivate *priv;
	const guint8 *hwaddr;
	gsize hwaddrlen = 0;

	priv = NM_DEVICE_GET_PRIVATE (self);
	if (priv->ifindex <= 0)
		return FALSE;

	hwaddr = nm_platform_link_get_address (nm_device_get_platform (self), priv->ifindex, &hwaddrlen);

	if (   priv->type == NM_DEVICE_TYPE_ETHERNET
	    && hwaddr
	    && nm_utils_hwaddr_matches (hwaddr, hwaddrlen, nm_ip_addr_zero.addr_eth, sizeof (nm_ip_addr_zero.addr_eth)))
		hwaddrlen = 0;

	if (!hwaddrlen)
		return FALSE;

	if (   priv->hw_addr_len
	    && priv->hw_addr_len != hwaddrlen) {
		char s_buf[NM_UTILS_HWADDR_LEN_MAX_STR];

		/* we cannot change the address length of a device once it is set (except
		 * unrealizing the device).
		 *
		 * The reason is that the permanent and initial MAC addresses also must have the
		 * same address length, so it's unclear what it would mean that the length changes. */
		_LOGD (LOGD_PLATFORM | LOGD_DEVICE,
		       "hw-addr: read a MAC address with differing length (%s vs. %s)",
		       priv->hw_addr,
		       nm_utils_hwaddr_ntoa_buf (hwaddr, hwaddrlen, TRUE, s_buf, sizeof (s_buf)));
		return FALSE;
	}

	if (   priv->hw_addr
	    && nm_utils_hwaddr_matches (priv->hw_addr, -1, hwaddr, hwaddrlen))
		return FALSE;

	g_free (priv->hw_addr);
	priv->hw_addr_len_ = hwaddrlen;
	priv->hw_addr = nm_utils_hwaddr_ntoa (hwaddr, hwaddrlen);

	_LOGD (LOGD_PLATFORM | LOGD_DEVICE, "hw-addr: hardware address now %s", priv->hw_addr);
	_notify (self, PROP_HW_ADDRESS);

	if (   !priv->hw_addr_initial
	    || (   priv->hw_addr_type == HW_ADDR_TYPE_UNSET
	        && priv->state < NM_DEVICE_STATE_PREPARE
	        && !nm_device_is_activating (self))) {
		/* when we get a hw_addr the first time or while the device
		 * is not activated (with no explict hw address set), always
		 * update our initial hw-address as well. */
		nm_device_update_initial_hw_address (self);
	}
	return TRUE;
}

void
nm_device_update_initial_hw_address (NMDevice *self)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (   priv->hw_addr
	    && !nm_streq0 (priv->hw_addr_initial, priv->hw_addr)) {
		if (   priv->hw_addr_initial
		    && priv->hw_addr_type != HW_ADDR_TYPE_UNSET) {
			/* once we have the initial hw address set, we only allow
			 * update if the currenty type is "unset". */
			return;
		}
		g_free (priv->hw_addr_initial);
		priv->hw_addr_initial = g_strdup (priv->hw_addr);
		_LOGD (LOGD_DEVICE, "hw-addr: update initial MAC address %s",
		       priv->hw_addr_initial);
	}
}

void
nm_device_update_permanent_hw_address (NMDevice *self, gboolean force_freeze)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint8 buf[NM_UTILS_HWADDR_LEN_MAX];
	size_t len = 0;
	gboolean success_read;
	int ifindex;
	const NMPlatformLink *pllink;
	const NMConfigDeviceStateData *dev_state;

	if (priv->hw_addr_perm) {
		/* the permanent hardware address is only read once and not
		 * re-read later.
		 *
		 * Except during unrealize/realize cycles, where we clear the permanent
		 * hardware address during unrealization. */
		return;
	}

	ifindex = priv->ifindex;
	if (ifindex <= 0)
		return;

	/* the user is advised to configure stable MAC addresses for software devices via
	 * UDEV. Thus, check whether the link is fully initialized. */
	pllink = nm_platform_link_get (nm_device_get_platform (self), ifindex);
	if (   !pllink
	    || !pllink->initialized) {
		if (!force_freeze) {
			/* we can afford to wait. Back off and leave the permanent MAC address
			 * undecided for now. */
			return;
		}
		/* try to refresh the link just to give UDEV a bit more time... */
		nm_platform_link_refresh (nm_device_get_platform (self), ifindex);
		/* maybe the MAC address changed... */
		nm_device_update_hw_address (self);
	} else if (!priv->hw_addr_len)
		nm_device_update_hw_address (self);

	if (!priv->hw_addr_len) {
		/* we need the current MAC address because we require the permanent MAC address
		 * to have the same length as the current address.
		 *
		 * Abort if there is no current MAC address. */
		return;
	}

	success_read = nm_platform_link_get_permanent_address (nm_device_get_platform (self), ifindex, buf, &len);
	if (success_read && priv->hw_addr_len == len) {
		priv->hw_addr_perm_fake = FALSE;
		priv->hw_addr_perm = nm_utils_hwaddr_ntoa (buf, len);
		_LOGD (LOGD_DEVICE, "hw-addr: read permanent MAC address '%s'",
		       priv->hw_addr_perm);
		goto notify_and_out;
	}

	/* we failed to read a permanent MAC address, thus we use a fake address,
	 * that is the current MAC address of the device.
	 *
	 * Note that the permanet MAC address of a NMDevice instance does not change
	 * after being set once. Thus, we use now a fake address and stick to that
	 * (until we unrealize the device). */
	priv->hw_addr_perm_fake = TRUE;

	/* We also persist our choice of the fake address to the device state
	 * file to use the same address on restart of NetworkManager.
	 * First, try to reload the address from the state file. */
	dev_state = nm_config_device_state_get (nm_config_get (), ifindex);
	if (   dev_state
	    && dev_state->perm_hw_addr_fake
	    && nm_utils_hwaddr_aton (dev_state->perm_hw_addr_fake, buf, priv->hw_addr_len)
	    && !nm_utils_hwaddr_matches (buf, priv->hw_addr_len, priv->hw_addr, -1)) {
		_LOGD (LOGD_PLATFORM | LOGD_ETHER, "hw-addr: %s (use from statefile: %s, current: %s)",
		       success_read
		           ? "read HW addr length of permanent MAC address differs"
		           : "unable to read permanent MAC address",
		       dev_state->perm_hw_addr_fake,
		       priv->hw_addr);
		priv->hw_addr_perm = nm_utils_hwaddr_ntoa (buf, priv->hw_addr_len);
		goto notify_and_out;
	}

	_LOGD (LOGD_PLATFORM | LOGD_ETHER, "hw-addr: %s (use current: %s)",
	       success_read
	           ? "read HW addr length of permanent MAC address differs"
	           : "unable to read permanent MAC address",
	       priv->hw_addr);
	priv->hw_addr_perm = g_strdup (priv->hw_addr);

notify_and_out:
	_notify (self, PROP_PERM_HW_ADDRESS);
}

static const char *
_get_cloned_mac_address_setting (NMDevice *self, NMConnection *connection, gboolean is_wifi, char **out_addr)
{
	NMSetting *setting;
	const char *addr = NULL;

	nm_assert (out_addr && !*out_addr);

	setting = nm_connection_get_setting (connection,
	                                     is_wifi ? NM_TYPE_SETTING_WIRELESS : NM_TYPE_SETTING_WIRED);
	if (setting) {
		addr = is_wifi
		       ? nm_setting_wireless_get_cloned_mac_address ((NMSettingWireless *) setting)
		       : nm_setting_wired_get_cloned_mac_address ((NMSettingWired *) setting);
	}

	if (!addr) {
		gs_free char *a = NULL;

		a = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
		                                           is_wifi ? "wifi.cloned-mac-address" : "ethernet.cloned-mac-address",
		                                           self);

		addr = NM_CLONED_MAC_PRESERVE;

		if (!a) {
			if (is_wifi) {
				NMSettingMacRandomization v;

				/* for backward compatibility, read the deprecated wifi.mac-address-randomization setting. */
				a = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
				                                           "wifi." NM_SETTING_WIRELESS_MAC_ADDRESS_RANDOMIZATION,
				                                           self);
				v = _nm_utils_ascii_str_to_int64 (a, 10,
				                                  NM_SETTING_MAC_RANDOMIZATION_DEFAULT,
				                                  NM_SETTING_MAC_RANDOMIZATION_ALWAYS,
				                                  NM_SETTING_MAC_RANDOMIZATION_DEFAULT);
				if (v == NM_SETTING_MAC_RANDOMIZATION_ALWAYS)
					addr = NM_CLONED_MAC_RANDOM;
			}
		} else if (   NM_CLONED_MAC_IS_SPECIAL (a)
		           || nm_utils_hwaddr_valid (a, ETH_ALEN))
			addr = *out_addr = g_steal_pointer (&a);
	}

	return addr;
}

static const char *
_get_generate_mac_address_mask_setting (NMDevice *self, NMConnection *connection, gboolean is_wifi, char **out_value)
{
	NMSetting *setting;
	const char *value = NULL;
	char *a;

	nm_assert (out_value && !*out_value);

	setting = nm_connection_get_setting (connection,
	                                     is_wifi ? NM_TYPE_SETTING_WIRELESS : NM_TYPE_SETTING_WIRED);
	if (setting) {
		value = is_wifi
		        ? nm_setting_wireless_get_generate_mac_address_mask ((NMSettingWireless *) setting)
		        : nm_setting_wired_get_generate_mac_address_mask ((NMSettingWired *) setting);
		if (value)
			return value;
	}

	a = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
	                                           is_wifi ? "wifi.generate-mac-address-mask" : "ethernet.generate-mac-mac-address-mask",
	                                           self);
	if (!a)
		return NULL;
	*out_value = a;
	return a;
}

gboolean
nm_device_hw_addr_is_explict (NMDevice *self)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	return !NM_IN_SET ((HwAddrType) priv->hw_addr_type,
	                   HW_ADDR_TYPE_PERMANENT,
	                   HW_ADDR_TYPE_UNSET);
}

static gboolean
_hw_addr_matches (NMDevice *self, const guint8 *addr, gsize addr_len)
{
	const char *cur_addr;

	cur_addr = nm_device_get_hw_address (self);
	return cur_addr && nm_utils_hwaddr_matches (addr, addr_len, cur_addr, -1);
}

static gboolean
_hw_addr_set (NMDevice *self,
              const char *const addr,
              const char *const operation,
              const char *const detail)
{
	NMDevicePrivate *priv;
	gboolean success = FALSE;
	NMPlatformError plerr;
	guint8 addr_bytes[NM_UTILS_HWADDR_LEN_MAX];
	gsize addr_len;
	gboolean was_up;

	nm_assert (NM_IS_DEVICE (self));
	nm_assert (addr);
	nm_assert (operation);

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (!_nm_utils_hwaddr_aton (addr, addr_bytes, sizeof (addr_bytes), &addr_len))
		g_return_val_if_reached (FALSE);

	/* Do nothing if current MAC is same */
	if (_hw_addr_matches (self, addr_bytes, addr_len)) {
		_LOGT (LOGD_DEVICE, "set-hw-addr: no MAC address change needed (%s)", addr);
		return TRUE;
	}

	if (   priv->hw_addr_len
	    && priv->hw_addr_len != addr_len)
		g_return_val_if_reached (FALSE);

	_LOGT (LOGD_DEVICE, "set-hw-addr: setting MAC address to '%s' (%s, %s)...", addr, operation, detail);

	was_up = nm_device_is_up (self);
	if (was_up) {
		/* Can't change MAC address while device is up */
		nm_device_take_down (self, FALSE);
	}

	plerr = nm_platform_link_set_address (nm_device_get_platform (self), nm_device_get_ip_ifindex (self), addr_bytes, addr_len);
	success = (plerr == NM_PLATFORM_ERROR_SUCCESS);
	if (success) {
		/* MAC address succesfully changed; update the current MAC to match */
		nm_device_update_hw_address (self);
		if (_hw_addr_matches (self, addr_bytes, addr_len)) {
			_LOGI (LOGD_DEVICE, "set-hw-addr: %s MAC address to %s (%s)",
			       operation, addr, detail);
		} else {
			gint64 poll_end, now;

			_LOGD (LOGD_DEVICE,
			       "set-hw-addr: new MAC address %s not successfully %s (%s) (refresh link)",
			       addr, operation, detail);

			/* The platform call indicated success, however the address is not
			 * as expected. That is either due to a driver issue (brcmfmac, bgo#770456,
			 * rh#1374023) or a race where externally the MAC address was reset.
			 * The race is rather unlikely.
			 *
			 * The alternative would be to postpone the activation in case the
			 * MAC address is not yet ready and poll without blocking. However,
			 * that is rather complicated and it is not expected that this case
			 * happens for regular drivers.
			 * Note that brcmfmac can block NetworkManager for 500 msec while
			 * taking down the device. Let's add annother 100 msec to that.
			 *
			 * wait/poll up to 100 msec until it changes. */

			poll_end = nm_utils_get_monotonic_timestamp_us () + (100 * 1000);
			for (;;) {
				if (!nm_platform_link_refresh (nm_device_get_platform (self), nm_device_get_ip_ifindex (self)))
					goto handle_fail;
				if (!nm_device_update_hw_address (self))
					goto handle_wait;
				if (!_hw_addr_matches (self, addr_bytes, addr_len))
					goto handle_fail;

				break;
handle_wait:
				now = nm_utils_get_monotonic_timestamp_us ();
				if (now < poll_end) {
					g_usleep (NM_MIN (poll_end - now, 500));
					continue;
				}
handle_fail:
				success = FALSE;
				break;
			}

			if (success) {
				_LOGI (LOGD_DEVICE, "set-hw-addr: %s MAC address to %s (%s)",
				       operation, addr, detail);
			} else {
				_LOGW (LOGD_DEVICE,
				       "set-hw-addr: new MAC address %s not successfully %s (%s)",
				       addr, operation, detail);
			}
		}
	} else {
		_NMLOG (plerr == NM_PLATFORM_ERROR_NOT_FOUND ? LOGL_DEBUG : LOGL_WARN,
		        LOGD_DEVICE, "set-hw-addr: failed to %s MAC address to %s (%s) (%s)",
		        operation, addr, detail,
		        nm_platform_error_to_string_a (plerr));
	}

	if (was_up) {
		if (!nm_device_bring_up (self, TRUE, NULL))
			return FALSE;
	}

	return success;
}

gboolean
nm_device_hw_addr_set (NMDevice *self,
                       const char *addr,
                       const char *detail,
                       gboolean set_permanent)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (!addr)
		g_return_val_if_reached (FALSE);

	if (set_permanent) {
		/* The type is set to PERMANENT by NMDeviceVlan when taking the MAC
		 * address from the parent and by NMDeviceWifi when setting a random MAC
		 * address during scanning.
		 */
		priv->hw_addr_type = HW_ADDR_TYPE_PERMANENT;
	}

	return _hw_addr_set (self, addr, "set", detail);
}

/*
 * _hw_addr_get_cloned:
 * @self: a #NMDevice
 * @connection: a #NMConnection
 * @is_wifi: whether the device is Wi-Fi
 * @preserve: (out): whether the address must be reset to initial one
 * @hwaddr: (out): the cloned MAC address to set on interface
 * @hwaddr_type: (out): the type of address to set
 * @hwaddr_detail: (out): the detail (origin) of address to set
 * @error: (out): on return, an error or %NULL
 *
 * Computes the MAC to be set on a interface. On success, one of the
 * following exclusive conditions are verified:
 *
 *  - @preserve is %TRUE: the address must be reset to the initial one
 *  - @hwaddr is not %NULL: the given address must be set on the device
 *  - @hwaddr is %NULL and @preserve is %FALSE: no action needed
 *
 * Returns: %FALSE in case of error in determining the cloned MAC address,
 * %TRUE otherwise
 */
static gboolean
_hw_addr_get_cloned (NMDevice *self, NMConnection *connection, gboolean is_wifi,
                     gboolean *preserve, char **hwaddr, HwAddrType *hwaddr_type,
                     char **hwaddr_detail, GError **error)
{
	NMDevicePrivate *priv;
	gs_free char *addr_setting_free = NULL;
	gs_free char *hw_addr_generated = NULL;
	gs_free char *generate_mac_address_mask_tmp = NULL;
	const char *addr, *addr_setting;
	char *addr_out;
	HwAddrType type_out;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (!connection)
		g_return_val_if_reached (FALSE);

	addr = addr_setting = _get_cloned_mac_address_setting (self, connection, is_wifi, &addr_setting_free);

	if (nm_streq (addr, NM_CLONED_MAC_PRESERVE)) {
		/* "preserve" means to reset the initial MAC address. */
		NM_SET_OUT (preserve, TRUE);
		NM_SET_OUT (hwaddr, NULL);
		NM_SET_OUT (hwaddr_type, HW_ADDR_TYPE_UNSET);
		NM_SET_OUT (hwaddr_detail, g_steal_pointer (&addr_setting_free) ?: g_strdup (addr_setting));
		return TRUE;
	}

	if (nm_streq (addr, NM_CLONED_MAC_PERMANENT)) {
		gboolean is_fake;

		addr = nm_device_get_permanent_hw_address_full (self, TRUE, &is_fake);
		if (is_fake) {
			/* Preserve the current address if the permanent address if fake */
			NM_SET_OUT (preserve, TRUE);
			NM_SET_OUT (hwaddr, NULL);
			NM_SET_OUT (hwaddr_type, HW_ADDR_TYPE_UNSET);
			NM_SET_OUT (hwaddr_detail, g_steal_pointer (&addr_setting_free) ?: g_strdup (addr_setting));
			return TRUE;
		} else if (!addr) {
			g_set_error_literal (error,
			                     NM_DEVICE_ERROR,
			                     NM_DEVICE_ERROR_FAILED,
			                     "failed to retrieve permanent address");
			return FALSE;
		}
		addr_out = g_strdup (addr);
		type_out = HW_ADDR_TYPE_PERMANENT;
	} else if (NM_IN_STRSET (addr, NM_CLONED_MAC_RANDOM)) {
		if (priv->hw_addr_type == HW_ADDR_TYPE_GENERATED) {
			/* hm, we already use a generate MAC address. Most certainly, that is from the same
			 * activation request, so we should not create a new random address, instead keep
			 * the current. */
			goto out_no_action;
		}
		hw_addr_generated = nm_utils_hw_addr_gen_random_eth (nm_device_get_initial_hw_address (self),
		                                                     _get_generate_mac_address_mask_setting (self, connection,
		                                                                                             is_wifi,
		                                                                                             &generate_mac_address_mask_tmp));
		if (!hw_addr_generated) {
			g_set_error (error,
			             NM_DEVICE_ERROR,
			             NM_DEVICE_ERROR_FAILED,
			             "failed to generate %s MAC address", "random");
			return FALSE;
		}

		addr_out = g_steal_pointer (&hw_addr_generated);
		type_out = HW_ADDR_TYPE_GENERATED;
	} else if (NM_IN_STRSET (addr, NM_CLONED_MAC_STABLE)) {
		NMUtilsStableType stable_type;
		const char *stable_id;

		if (priv->hw_addr_type == HW_ADDR_TYPE_GENERATED) {
			/* hm, we already use a generate MAC address. Most certainly, that is from the same
			 * activation request, so let's skip creating the stable address anew. */
			goto out_no_action;
		}

		stable_id = _get_stable_id (self, connection, &stable_type);
		if (stable_id) {
			hw_addr_generated = nm_utils_hw_addr_gen_stable_eth (stable_type, stable_id,
			                                                     nm_device_get_ip_iface (self),
			                                                     nm_device_get_initial_hw_address (self),
			                                                     _get_generate_mac_address_mask_setting (self, connection, is_wifi, &generate_mac_address_mask_tmp));
		}
		if (!hw_addr_generated) {
			g_set_error (error,
			             NM_DEVICE_ERROR,
			             NM_DEVICE_ERROR_FAILED,
			             "failed to generate %s MAC address", "stable");
			return FALSE;
		}

		addr_out = g_steal_pointer (&hw_addr_generated);
		type_out = HW_ADDR_TYPE_GENERATED;
	} else {
		/* this must be a valid address. Otherwise, we shouldn't come here. */
		if (!nm_utils_hwaddr_valid (addr, -1))
			g_return_val_if_reached (FALSE);

		addr_out = g_strdup (addr);
		type_out = HW_ADDR_TYPE_EXPLICIT;
	}

	NM_SET_OUT (preserve, FALSE);
	NM_SET_OUT (hwaddr, addr_out);
	NM_SET_OUT (hwaddr_type, type_out);
	NM_SET_OUT (hwaddr_detail, g_steal_pointer (&addr_setting_free) ?: g_strdup (addr_setting));
	return TRUE;
out_no_action:
	NM_SET_OUT (preserve, FALSE);
	NM_SET_OUT (hwaddr, NULL);
	NM_SET_OUT (hwaddr_type, HW_ADDR_TYPE_UNSET);
	NM_SET_OUT (hwaddr_detail, NULL);
	return TRUE;
}

gboolean
nm_device_hw_addr_get_cloned (NMDevice *self, NMConnection *connection, gboolean is_wifi,
                              char **hwaddr, gboolean *preserve, GError **error)
{
	if (!_hw_addr_get_cloned (self, connection, is_wifi, preserve, hwaddr, NULL, NULL, error))
		return FALSE;

	return TRUE;
}

gboolean
nm_device_hw_addr_set_cloned (NMDevice *self, NMConnection *connection, gboolean is_wifi)
{
	NMDevicePrivate *priv;
	gboolean preserve = FALSE;
	gs_free char *hwaddr = NULL;
	gs_free char *detail = NULL;
	HwAddrType type = HW_ADDR_TYPE_UNSET;
	gs_free_error GError *error = NULL;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);
	priv = NM_DEVICE_GET_PRIVATE (self);

	if (!_hw_addr_get_cloned (self, connection, is_wifi, &preserve, &hwaddr, &type, &detail, &error)) {
		_LOGW (LOGD_DEVICE, "set-hw-addr: %s", error->message);
		return FALSE;
	}

	if (preserve)
		return nm_device_hw_addr_reset (self, detail);

	if (hwaddr) {
		priv->hw_addr_type = type;
		return _hw_addr_set (self, hwaddr, "set-cloned", detail);
	}

	return TRUE;
}

gboolean
nm_device_hw_addr_reset (NMDevice *self, const char *detail)
{
	NMDevicePrivate *priv;
	const char *addr;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->hw_addr_type == HW_ADDR_TYPE_UNSET)
		return TRUE;

	priv->hw_addr_type = HW_ADDR_TYPE_UNSET;
	addr = nm_device_get_initial_hw_address (self);
	if (!addr) {
		/* as hw_addr_type is not UNSET, we expect that we can get an
		 * initial address to which to reset. */
		g_return_val_if_reached (FALSE);
	}

	return _hw_addr_set (self, addr, "reset", detail);
}

const char *
nm_device_get_permanent_hw_address_full (NMDevice *self, gboolean force_freeze, gboolean *out_is_fake)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	priv = NM_DEVICE_GET_PRIVATE (self);

	if (   !priv->hw_addr_perm
	    && force_freeze) {
		/* somebody requests a permanent MAC address, but we don't have it set
		 * yet. We cannot delay it any longer and try to get it without waiting
		 * for UDEV. */
		nm_device_update_permanent_hw_address (self, TRUE);
	}

	NM_SET_OUT (out_is_fake, priv->hw_addr_perm && priv->hw_addr_perm_fake);
	return priv->hw_addr_perm;
}

const char *
nm_device_get_permanent_hw_address (NMDevice *self)
{
	return nm_device_get_permanent_hw_address_full (self, TRUE, NULL);
}

const char *
nm_device_get_initial_hw_address (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NULL);

	return NM_DEVICE_GET_PRIVATE (self)->hw_addr_initial;
}

/**
 * nm_device_spec_match_list:
 * @self: an #NMDevice
 * @specs: (element-type utf8): a list of device specs
 *
 * Checks if @self matches any of the specifications in @specs. The
 * currently-supported spec types are:
 *
 *     "mac:00:11:22:33:44:55" - matches a device with the given
 *     hardware address
 *
 *     "interface-name:foo0" - matches a device with the given
 *     interface name
 *
 *     "s390-subchannels:00.11.22" - matches a device with the given
 *     z/VM / s390 subchannels.
 *
 *     "*" - matches any device
 *
 * Returns: #TRUE if @self matches one of the specs in @specs
 */
gboolean
nm_device_spec_match_list (NMDevice *self, const GSList *specs)
{
	return nm_device_spec_match_list_full (self, specs, FALSE);
}

int
nm_device_spec_match_list_full (NMDevice *self, const GSList *specs, int no_match_value)
{
	NMDeviceClass *klass;
	NMMatchSpecMatchType m;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	klass = NM_DEVICE_GET_CLASS (self);

	m = nm_match_spec_device (specs,
	                          nm_device_get_iface (self),
	                          nm_device_get_type_description (self),
	                          nm_device_get_driver (self),
	                          nm_device_get_driver_version (self),
	                          nm_device_get_permanent_hw_address (self),
	                          klass->get_s390_subchannels ? klass->get_s390_subchannels (self) : NULL);

	switch (m) {
	case NM_MATCH_SPEC_MATCH:
		return TRUE;
	case NM_MATCH_SPEC_NEG_MATCH:
		return FALSE;
	case NM_MATCH_SPEC_NO_MATCH:
		return no_match_value;
	}
	nm_assert_not_reached ();
	return no_match_value;
}

guint
nm_device_get_supplicant_timeout (NMDevice *self)
{
	NMConnection *connection;
	NMSetting8021x *s_8021x;
	gs_free char *value = NULL;
	gint timeout;
#define SUPPLICANT_DEFAULT_TIMEOUT 25

	g_return_val_if_fail (NM_IS_DEVICE (self), SUPPLICANT_DEFAULT_TIMEOUT);

	connection = nm_device_get_applied_connection (self);
	g_return_val_if_fail (connection, SUPPLICANT_DEFAULT_TIMEOUT);
	s_8021x = nm_connection_get_setting_802_1x (connection);
	if (s_8021x) {
		timeout = nm_setting_802_1x_get_auth_timeout (s_8021x);
		if (timeout > 0)
			return timeout;
	}

	value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
	                                               "802-1x.auth-timeout",
	                                               self);
	return _nm_utils_ascii_str_to_int64 (value, 10, 1, G_MAXINT32,
	                                     SUPPLICANT_DEFAULT_TIMEOUT);
}

gboolean
nm_device_auth_retries_try_next (NMDevice *self)
{
	NMDevicePrivate *priv;
	NMSettingConnection *s_con;
	int auth_retries;

	g_return_val_if_fail (NM_IS_DEVICE (self), FALSE);

	priv = NM_DEVICE_GET_PRIVATE (self);
	auth_retries = priv->auth_retries;

	if (G_UNLIKELY (auth_retries == NM_DEVICE_AUTH_RETRIES_UNSET)) {
		auth_retries = -1;

		s_con = NM_SETTING_CONNECTION (nm_device_get_applied_setting (self, NM_TYPE_SETTING_CONNECTION));
		if (s_con)
			auth_retries = nm_setting_connection_get_auth_retries (s_con);

		if (auth_retries == -1) {
			gs_free char *value = NULL;

			value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
			                                               "connection.auth-retries",
			                                               self);
			auth_retries = _nm_utils_ascii_str_to_int64 (value, 10, -1, G_MAXINT32, -1);
		}

		if (auth_retries == 0)
			auth_retries = NM_DEVICE_AUTH_RETRIES_INFINITY;
		else if (auth_retries == -1)
			auth_retries = NM_DEVICE_AUTH_RETRIES_DEFAULT;
		else
			nm_assert (auth_retries > 0);

		priv->auth_retries = auth_retries;
	}

	if (auth_retries == NM_DEVICE_AUTH_RETRIES_INFINITY)
		return TRUE;
	if (auth_retries <= 0) {
		nm_assert (auth_retries == 0);
		return FALSE;
	}
	priv->auth_retries--;
	return TRUE;
}

/*****************************************************************************/

static const char *
_activation_func_to_string (ActivationHandleFunc func)
{
#define FUNC_TO_STRING_CHECK_AND_RETURN(func, f) \
	G_STMT_START { \
		if ((func) == (f)) \
			return #f; \
	} G_STMT_END
	FUNC_TO_STRING_CHECK_AND_RETURN (func, activate_stage1_device_prepare);
	FUNC_TO_STRING_CHECK_AND_RETURN (func, activate_stage2_device_config);
	FUNC_TO_STRING_CHECK_AND_RETURN (func, activate_stage3_ip_config_start);
	FUNC_TO_STRING_CHECK_AND_RETURN (func, activate_stage4_ip4_config_timeout);
	FUNC_TO_STRING_CHECK_AND_RETURN (func, activate_stage4_ip6_config_timeout);
	FUNC_TO_STRING_CHECK_AND_RETURN (func, activate_stage5_ip4_config_result);
	FUNC_TO_STRING_CHECK_AND_RETURN (func, activate_stage5_ip6_config_commit);
	g_return_val_if_reached ("unknown");
}

/*****************************************************************************/

static void
nm_device_init (NMDevice *self)
{
	NMDevicePrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_DEVICE, NMDevicePrivate);

	self->_priv = priv;

	c_list_init (&priv->slaves);

	priv->netns = g_object_ref (NM_NETNS_GET);

	priv->autoconnect_blocked_flags = DEFAULT_AUTOCONNECT
	                                  ? NM_DEVICE_AUTOCONNECT_BLOCKED_NONE
	                                  : NM_DEVICE_AUTOCONNECT_BLOCKED_USER;

	priv->auth_retries = NM_DEVICE_AUTH_RETRIES_UNSET;
	priv->type = NM_DEVICE_TYPE_UNKNOWN;
	priv->capabilities = NM_DEVICE_CAP_NM_SUPPORTED;
	priv->state = NM_DEVICE_STATE_UNMANAGED;
	priv->state_reason = NM_DEVICE_STATE_REASON_NONE;
	priv->rfkill_type = RFKILL_TYPE_UNKNOWN;
	priv->unmanaged_flags = NM_UNMANAGED_PLATFORM_INIT;
	priv->unmanaged_mask = priv->unmanaged_flags;
	priv->available_connections = g_hash_table_new_full (nm_direct_hash, NULL, g_object_unref, NULL);
	priv->ip6_saved_properties = g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, g_free);
	priv->sys_iface_state = NM_DEVICE_SYS_IFACE_STATE_EXTERNAL;

	priv->v4_commit_first_time = TRUE;
	priv->v6_commit_first_time = TRUE;
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	GObjectClass *klass;
	NMDevice *self;
	NMDevicePrivate *priv;
	const NMPlatformLink *pllink;

	klass = G_OBJECT_CLASS (nm_device_parent_class);
	object = klass->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	self = NM_DEVICE (object);
	priv = NM_DEVICE_GET_PRIVATE (self);

	if (   priv->iface
	    && G_LIKELY (!nm_utils_get_testing ())) {
		pllink = nm_platform_link_get_by_ifname (nm_device_get_platform (self), priv->iface);

		if (pllink && link_type_compatible (self, pllink->type, NULL, NULL)) {
			priv->ifindex = pllink->ifindex;
			priv->up = NM_FLAGS_HAS (pllink->n_ifi_flags, IFF_UP);
		}
	}

	if (priv->hw_addr_perm) {
		guint8 buf[NM_UTILS_HWADDR_LEN_MAX];
		gsize l;

		if (!_nm_utils_hwaddr_aton (priv->hw_addr_perm, buf, sizeof (buf), &l)) {
			g_clear_pointer (&priv->hw_addr_perm, g_free);
			g_return_val_if_reached (object);
		}

		priv->hw_addr_len_ = l;
		priv->hw_addr = nm_utils_hwaddr_ntoa (buf, l);
		_LOGT (LOGD_DEVICE, "hw-addr: has permanent hw-address '%s'", priv->hw_addr_perm);
	}

	return object;
}

static void
constructed (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMPlatform *platform;

	if (NM_DEVICE_GET_CLASS (self)->get_generic_capabilities)
		priv->capabilities |= NM_DEVICE_GET_CLASS (self)->get_generic_capabilities (self);

	/* Watch for external IP config changes */
	platform = nm_device_get_platform (self);
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, G_CALLBACK (device_ipx_changed), self);
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED, G_CALLBACK (device_ipx_changed), self);
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, G_CALLBACK (device_ipx_changed), self);
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED, G_CALLBACK (device_ipx_changed), self);
	g_signal_connect (platform, NM_PLATFORM_SIGNAL_LINK_CHANGED, G_CALLBACK (link_changed_cb), self);

	priv->settings = g_object_ref (NM_SETTINGS_GET);
	g_assert (priv->settings);

	g_signal_connect (priv->settings,
	                  NM_SETTINGS_SIGNAL_CONNECTION_ADDED,
	                  G_CALLBACK (cp_connection_added),
	                  self);
	g_signal_connect (priv->settings,
	                  NM_SETTINGS_SIGNAL_CONNECTION_UPDATED,
	                  G_CALLBACK (cp_connection_updated),
	                  self);
	g_signal_connect (priv->settings,
	                  NM_SETTINGS_SIGNAL_CONNECTION_REMOVED,
	                  G_CALLBACK (cp_connection_removed),
	                  self);

	G_OBJECT_CLASS (nm_device_parent_class)->constructed (object);

	_LOGD (LOGD_DEVICE, "constructed (%s)", G_OBJECT_TYPE_NAME (self));
}

static void
dispose (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	NMPlatform *platform;

	_LOGD (LOGD_DEVICE, "disposing");

	nm_clear_g_cancellable (&priv->deactivating_cancellable);

	nm_device_assume_state_reset (self);

	_parent_set_ifindex (self, 0, FALSE);

	platform = nm_device_get_platform (self);
	g_signal_handlers_disconnect_by_func (platform, G_CALLBACK (device_ipx_changed), self);
	g_signal_handlers_disconnect_by_func (platform, G_CALLBACK (link_changed_cb), self);

	g_slist_free_full (priv->arping.dad_list, (GDestroyNotify) nm_arping_manager_destroy);
	priv->arping.dad_list = NULL;

	arp_cleanup (self);

	nm_clear_g_signal_handler (nm_config_get (), &priv->config_changed_id);

	dispatcher_cleanup (self);

	nm_pacrunner_manager_remove_clear (priv->pacrunner_manager,
	                                   &priv->pacrunner_call_id);
	g_clear_object (&priv->pacrunner_manager);

	_cleanup_generic_pre (self, CLEANUP_TYPE_KEEP);

	g_warn_if_fail (c_list_is_empty (&priv->slaves));
	g_assert (priv->master_ready_id == 0);

	/* Let the kernel manage IPv6LL again */
	set_nm_ipv6ll (self, FALSE);

	_cleanup_generic_post (self, CLEANUP_TYPE_KEEP);

	g_hash_table_remove_all (priv->ip6_saved_properties);

	nm_clear_g_source (&priv->recheck_assume_id);
	nm_clear_g_source (&priv->recheck_available.call_id);

	nm_clear_g_source (&priv->check_delete_unrealized_id);

	nm_clear_g_source (&priv->stats.timeout_id);

	carrier_disconnected_action_cancel (self);

	if (priv->ifindex > 0) {
		priv->ifindex = 0;
		_notify (self, PROP_IFINDEX);
	}

	if (priv->settings) {
		g_signal_handlers_disconnect_by_func (priv->settings, cp_connection_added, self);
		g_signal_handlers_disconnect_by_func (priv->settings, cp_connection_updated, self);
		g_signal_handlers_disconnect_by_func (priv->settings, cp_connection_removed, self);
	}

	available_connections_del_all (self);

	if (nm_clear_g_source (&priv->carrier_wait_id))
		nm_device_remove_pending_action (self, NM_PENDING_ACTION_CARRIER_WAIT, FALSE);

	_clear_queued_act_request (priv);

	nm_clear_g_source (&priv->device_link_changed_id);
	nm_clear_g_source (&priv->device_ip_link_changed_id);

	if (priv->lldp_listener) {
		g_signal_handlers_disconnect_by_func (priv->lldp_listener,
		                                      G_CALLBACK (lldp_neighbors_changed),
		                                      self);
		nm_lldp_listener_stop (priv->lldp_listener);
		g_clear_object (&priv->lldp_listener);
	}

	G_OBJECT_CLASS (nm_device_parent_class)->dispose (object);

	if (nm_clear_g_source (&priv->queued_state.id)) {
		/* FIXME: we'd expect the queud_state to be alredy cleared and this statement
		 * not being necessary. Add this check here to hopefully investigate crash
		 * rh#1270247. */
		g_return_if_reached ();
	}
}

static void
finalize (GObject *object)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	_LOGD (LOGD_DEVICE, "finalize(): %s", G_OBJECT_TYPE_NAME (self));

	g_free (priv->hw_addr);
	g_free (priv->hw_addr_perm);
	g_free (priv->hw_addr_initial);
	g_slist_free (priv->pending_actions);
	g_slist_free_full (priv->dad6_failed_addrs, (GDestroyNotify) nmp_object_unref);
	g_clear_pointer (&priv->physical_port_id, g_free);
	g_free (priv->udi);
	g_free (priv->iface);
	g_free (priv->ip_iface);
	g_free (priv->driver);
	g_free (priv->driver_version);
	g_free (priv->firmware_version);
	g_free (priv->type_desc);
	g_free (priv->dhcp_anycast_address);
	g_free (priv->current_stable_id);

	g_hash_table_unref (priv->ip6_saved_properties);
	g_hash_table_unref (priv->available_connections);

	G_OBJECT_CLASS (nm_device_parent_class)->finalize (object);

	/* for testing, NMDeviceTest does not invoke NMDevice::constructed,
	 * and thus @settings might be unset. */
	if (priv->settings)
		g_object_unref (priv->settings);

	g_object_unref (priv->netns);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMDevice *self = (NMDevice *) object;
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_UDI:
		/* construct-only */
		priv->udi = g_value_dup_string (value);
		break;
	case PROP_IFACE:
		/* construct-only */
		priv->iface = g_value_dup_string (value);
		break;
	case PROP_DRIVER:
		/* construct-only */
		priv->driver = g_value_dup_string (value);
		break;
	case PROP_DRIVER_VERSION:
		/* construct-only */
		priv->driver_version = g_value_dup_string (value);
		break;
	case PROP_FIRMWARE_VERSION:
		/* construct-only */
		priv->firmware_version = g_value_dup_string (value);
		break;
	case PROP_IP4_ADDRESS:
		priv->ip4_address = g_value_get_uint (value);
		break;
	case PROP_MANAGED:
		if (nm_device_is_real (self)) {
			gboolean managed;
			NMDeviceStateReason reason;

			managed = g_value_get_boolean (value);
			if (managed) {
				reason = NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED;
				if (NM_IN_SET_TYPED (NMDeviceSysIfaceState,
				                     priv->sys_iface_state,
				                     NM_DEVICE_SYS_IFACE_STATE_EXTERNAL,
				                     NM_DEVICE_SYS_IFACE_STATE_REMOVED))
					nm_device_sys_iface_state_set (self, NM_DEVICE_SYS_IFACE_STATE_ASSUME);
			} else {
				reason = NM_DEVICE_STATE_REASON_REMOVED;
				nm_device_sys_iface_state_set (self, NM_DEVICE_SYS_IFACE_STATE_REMOVED);
			}
			nm_device_set_unmanaged_by_flags (self,
			                                  NM_UNMANAGED_USER_EXPLICIT,
			                                  !managed,
			                                  reason);
		}
		break;
	case PROP_AUTOCONNECT:
		if (g_value_get_boolean (value))
			nm_device_autoconnect_blocked_unset (self, NM_DEVICE_AUTOCONNECT_BLOCKED_ALL);
		else
			nm_device_autoconnect_blocked_set (self, NM_DEVICE_AUTOCONNECT_BLOCKED_USER);
		break;
	case PROP_FIRMWARE_MISSING:
		/* construct-only */
		priv->firmware_missing = g_value_get_boolean (value);
		break;
	case PROP_NM_PLUGIN_MISSING:
		/* construct-only */
		priv->nm_plugin_missing = g_value_get_boolean (value);
		break;
	case PROP_DEVICE_TYPE:
		/* construct-only */
		nm_assert (priv->type == NM_DEVICE_TYPE_UNKNOWN);
		priv->type = g_value_get_uint (value);
		break;
	case PROP_LINK_TYPE:
		/* construct-only */
		nm_assert (priv->link_type == NM_LINK_TYPE_NONE);
		priv->link_type = g_value_get_uint (value);
		break;
	case PROP_TYPE_DESC:
		/* construct-only */
		priv->type_desc = g_value_dup_string (value);
		break;
	case PROP_RFKILL_TYPE:
		/* construct-only */
		priv->rfkill_type = g_value_get_uint (value);
		break;
	case PROP_PERM_HW_ADDRESS:
		/* construct-only */
		priv->hw_addr_perm = g_value_dup_string (value);
		break;
	case PROP_REFRESH_RATE_MS:
		_stats_set_refresh_rate (self, g_value_get_uint (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	GPtrArray *array;
	GHashTableIter iter;
	NMConnection *connection;
	GVariantBuilder array_builder;

	switch (prop_id) {
	case PROP_UDI:
		/* UDI is (depending on the device type) a path to sysfs and can contain
		 * non-UTF-8.
		 *   ip link add name $'d\xccf\\c' type dummy  */
		g_value_take_string (value,
		                     nm_utils_str_utf8safe_escape_cp (priv->udi,
		                                                      NM_UTILS_STR_UTF8_SAFE_FLAG_NONE));
		break;
	case PROP_IFACE:
		g_value_take_string (value,
		                     nm_utils_str_utf8safe_escape_cp (priv->iface,
		                                                      NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL));
		break;
	case PROP_IP_IFACE:
		if (ip_config_valid (priv->state)) {
			g_value_take_string (value,
			                     nm_utils_str_utf8safe_escape_cp (nm_device_get_ip_iface (self),
			                                                      NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL));
		} else
			g_value_set_string (value, NULL);
		break;
	case PROP_IFINDEX:
		g_value_set_int (value, priv->ifindex);
		break;
	case PROP_DRIVER:
		g_value_take_string (value,
		                     nm_utils_str_utf8safe_escape_cp (priv->driver,
		                                                      NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL));
		break;
	case PROP_DRIVER_VERSION:
		g_value_take_string (value,
		                     nm_utils_str_utf8safe_escape_cp (priv->driver_version,
		                                                      NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL));
		break;
	case PROP_FIRMWARE_VERSION:
		g_value_take_string (value,
		                     nm_utils_str_utf8safe_escape_cp (priv->firmware_version,
		                                                      NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL));
		break;
	case PROP_CAPABILITIES:
		g_value_set_uint (value, (priv->capabilities & ~NM_DEVICE_CAP_INTERNAL_MASK));
		break;
	case PROP_IP4_ADDRESS:
		g_value_set_uint (value, priv->ip4_address);
		break;
	case PROP_CARRIER:
		g_value_set_boolean (value, priv->carrier);
		break;
	case PROP_MTU:
		g_value_set_uint (value, priv->mtu);
		break;
	case PROP_IP4_CONFIG:
		nm_dbus_utils_g_value_set_object_path (value, ip_config_valid (priv->state) ? priv->ip4_config : NULL);
		break;
	case PROP_DHCP4_CONFIG:
		nm_dbus_utils_g_value_set_object_path (value, ip_config_valid (priv->state) ? priv->dhcp4.config : NULL);
		break;
	case PROP_IP6_CONFIG:
		nm_dbus_utils_g_value_set_object_path (value, ip_config_valid (priv->state) ? priv->ip6_config : NULL);
		break;
	case PROP_DHCP6_CONFIG:
		nm_dbus_utils_g_value_set_object_path (value, ip_config_valid (priv->state) ? priv->dhcp6.config : NULL);
		break;
	case PROP_STATE:
		g_value_set_uint (value, priv->state);
		break;
	case PROP_STATE_REASON:
		g_value_take_variant (value,
		                      g_variant_new ("(uu)", priv->state, priv->state_reason));
		break;
	case PROP_ACTIVE_CONNECTION:
		nm_dbus_utils_g_value_set_object_path (value, priv->act_request_public ? priv->act_request : NULL);
		break;
	case PROP_DEVICE_TYPE:
		g_value_set_uint (value, priv->type);
		break;
	case PROP_LINK_TYPE:
		g_value_set_uint (value, priv->link_type);
		break;
	case PROP_MANAGED:
		/* The managed state exposed on D-Bus only depends on the current device state alone. */
		g_value_set_boolean (value, nm_device_get_state (self) > NM_DEVICE_STATE_UNMANAGED);
		break;
	case PROP_AUTOCONNECT:
		g_value_set_boolean (value,
		                     nm_device_autoconnect_blocked_get (self, NM_DEVICE_AUTOCONNECT_BLOCKED_ALL)
		                       ? FALSE
		                       : TRUE);
		break;
	case PROP_FIRMWARE_MISSING:
		g_value_set_boolean (value, priv->firmware_missing);
		break;
	case PROP_NM_PLUGIN_MISSING:
		g_value_set_boolean (value, priv->nm_plugin_missing);
		break;
	case PROP_TYPE_DESC:
		g_value_set_string (value, priv->type_desc);
		break;
	case PROP_RFKILL_TYPE:
		g_value_set_uint (value, priv->rfkill_type);
		break;
	case PROP_AVAILABLE_CONNECTIONS:
		array = g_ptr_array_sized_new (g_hash_table_size (priv->available_connections));
		g_hash_table_iter_init (&iter, priv->available_connections);
		while (g_hash_table_iter_next (&iter, (gpointer) &connection, NULL))
			g_ptr_array_add (array, g_strdup (nm_connection_get_path (connection)));
		g_ptr_array_add (array, NULL);
		g_value_take_boxed (value, (char **) g_ptr_array_free (array, FALSE));
		break;
	case PROP_PHYSICAL_PORT_ID:
		g_value_set_string (value, priv->physical_port_id);
		break;
	case PROP_MASTER:
		g_value_set_object (value, nm_device_get_master (self));
		break;
	case PROP_PARENT:
		nm_dbus_utils_g_value_set_object_path (value, priv->parent_device);
		break;
	case PROP_HW_ADDRESS:
		g_value_set_string (value, priv->hw_addr);
		break;
	case PROP_PERM_HW_ADDRESS: {
		const char *perm_hw_addr;
		gboolean perm_hw_addr_is_fake;

		perm_hw_addr = nm_device_get_permanent_hw_address_full (self, FALSE, &perm_hw_addr_is_fake);
		/* this property is exposed on D-Bus for NMDeviceEthernet and NMDeviceWifi. */
		g_value_set_string (value, perm_hw_addr && !perm_hw_addr_is_fake ? perm_hw_addr : NULL);
		break;
	}
	case PROP_HAS_PENDING_ACTION:
		g_value_set_boolean (value, nm_device_has_pending_action (self));
		break;
	case PROP_METERED:
		g_value_set_uint (value, priv->metered);
		break;
	case PROP_LLDP_NEIGHBORS:
		if (priv->lldp_listener)
			g_value_set_variant (value, nm_lldp_listener_get_neighbors (priv->lldp_listener));
		else {
			g_variant_builder_init (&array_builder, G_VARIANT_TYPE ("aa{sv}"));
			g_value_take_variant (value, g_variant_builder_end (&array_builder));
		}
		break;
	case PROP_REAL:
		g_value_set_boolean (value, nm_device_is_real (self));
		break;
	case PROP_SLAVES: {
		CList *slave_iter;
		char **slave_list;
		gsize i, n;

		n = c_list_length (&priv->slaves);
		slave_list = g_new (char *, n + 1);
		i = 0;
		c_list_for_each (slave_iter, &priv->slaves) {
			SlaveInfo *info = c_list_entry (slave_iter, SlaveInfo, lst_slave);
			const char *path;

			if (!NM_DEVICE_GET_PRIVATE (info->slave)->is_enslaved)
				continue;
			path = nm_dbus_object_get_path (NM_DBUS_OBJECT (info->slave));
			if (path)
				slave_list[i++] = g_strdup (path);
		}
		nm_assert (i <= n);
		slave_list[i] = NULL;
		g_value_take_boxed (value, slave_list);
		break;
	}
	case PROP_REFRESH_RATE_MS:
		g_value_set_uint (value, priv->stats.refresh_rate_ms);
		break;
	case PROP_TX_BYTES:
		g_value_set_uint64 (value, priv->stats.tx_bytes);
		break;
	case PROP_RX_BYTES:
		g_value_set_uint64 (value, priv->stats.rx_bytes);
		break;
	case PROP_CONNECTIVITY:
		g_value_set_uint (value, priv->connectivity_state);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static const GDBusSignalInfo signal_info_state_changed = NM_DEFINE_GDBUS_SIGNAL_INFO_INIT (
	"StateChanged",
	.args = NM_DEFINE_GDBUS_ARG_INFOS (
		NM_DEFINE_GDBUS_ARG_INFO ("new_state", "u"),
		NM_DEFINE_GDBUS_ARG_INFO ("old_state", "u"),
		NM_DEFINE_GDBUS_ARG_INFO ("reason",    "u"),
	),
);

static const NMDBusInterfaceInfoExtended interface_info_device = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE,
		.methods = NM_DEFINE_GDBUS_METHOD_INFOS (
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"Reapply",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("connection", "a{sa{sv}}"),
						NM_DEFINE_GDBUS_ARG_INFO ("version_id", "t"),
						NM_DEFINE_GDBUS_ARG_INFO ("flags",      "u"),
					),
				),
				.handle = impl_device_reapply,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"GetAppliedConnection",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("flags", "u"),
					),
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("connection", "a{sa{sv}}"),
						NM_DEFINE_GDBUS_ARG_INFO ("version_id", "t"),
					),
				),
				.handle = impl_device_get_applied_connection,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"Disconnect",
				),
				.handle = impl_device_disconnect,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"Delete",
				),
				.handle = impl_device_delete,
			),
		),
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&signal_info_state_changed,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("Udi",                  "s",      NM_DEVICE_UDI),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("Interface",            "s",      NM_DEVICE_IFACE),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("IpInterface",          "s",      NM_DEVICE_IP_IFACE),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("Driver",               "s",      NM_DEVICE_DRIVER),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("DriverVersion",        "s",      NM_DEVICE_DRIVER_VERSION),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("FirmwareVersion",      "s",      NM_DEVICE_FIRMWARE_VERSION),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("Capabilities",         "u",      NM_DEVICE_CAPABILITIES),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("Ip4Address",           "u",      NM_DEVICE_IP4_ADDRESS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("State",                "u",      NM_DEVICE_STATE),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("StateReason",          "(uu)",   NM_DEVICE_STATE_REASON),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("ActiveConnection",     "o",      NM_DEVICE_ACTIVE_CONNECTION),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("Ip4Config",            "o",      NM_DEVICE_IP4_CONFIG),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("Dhcp4Config",          "o",      NM_DEVICE_DHCP4_CONFIG),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("Ip6Config",            "o",      NM_DEVICE_IP6_CONFIG),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("Dhcp6Config",          "o",      NM_DEVICE_DHCP6_CONFIG),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READWRITABLE_L ("Managed",              "b",      NM_DEVICE_MANAGED,               NM_AUTH_PERMISSION_NETWORK_CONTROL, NM_AUDIT_OP_DEVICE_MANAGED),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READWRITABLE_L ("Autoconnect",          "b",      NM_DEVICE_AUTOCONNECT,           NM_AUTH_PERMISSION_NETWORK_CONTROL, NM_AUDIT_OP_DEVICE_AUTOCONNECT),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("FirmwareMissing",      "b",      NM_DEVICE_FIRMWARE_MISSING),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("NmPluginMissing",      "b",      NM_DEVICE_NM_PLUGIN_MISSING),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("DeviceType",           "u",      NM_DEVICE_DEVICE_TYPE),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("AvailableConnections", "ao",     NM_DEVICE_AVAILABLE_CONNECTIONS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("PhysicalPortId",       "s",      NM_DEVICE_PHYSICAL_PORT_ID),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("Mtu",                  "u",      NM_DEVICE_MTU),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("Metered",              "u",      NM_DEVICE_METERED),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("LldpNeighbors",        "aa{sv}", NM_DEVICE_LLDP_NEIGHBORS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L     ("Real",                 "b",      NM_DEVICE_REAL),
		),
	),
};

const NMDBusInterfaceInfoExtended nm_interface_info_device_statistics = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_STATISTICS,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READWRITABLE ("RefreshRateMs", "u", NM_DEVICE_STATISTICS_REFRESH_RATE_MS, NM_AUTH_PERMISSION_ENABLE_DISABLE_STATISTICS, NM_AUDIT_OP_STATISTICS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE     ("TxBytes",       "t", NM_DEVICE_STATISTICS_TX_BYTES),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE     ("RxBytes",       "t", NM_DEVICE_STATISTICS_RX_BYTES),
		),
	),
};

static void
nm_device_class_init (NMDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDevicePrivate));

	dbus_object_class->export_path = NM_EXPORT_PATH_NUMBERED (NM_DBUS_PATH"/Devices");
	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device,
	                                                              &nm_interface_info_device_statistics);

	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->constructor = constructor;
	object_class->constructed = constructed;

	klass->link_changed = link_changed;

	klass->is_available = is_available;
	klass->act_stage1_prepare = act_stage1_prepare;
	klass->act_stage2_config = act_stage2_config;
	klass->act_stage3_ip4_config_start = act_stage3_ip4_config_start;
	klass->act_stage3_ip6_config_start = act_stage3_ip6_config_start;
	klass->act_stage4_ip4_config_timeout = act_stage4_ip4_config_timeout;
	klass->act_stage4_ip6_config_timeout = act_stage4_ip6_config_timeout;

	klass->get_type_description = get_type_description;
	klass->can_auto_connect = can_auto_connect;
	klass->check_connection_compatible = check_connection_compatible;
	klass->check_connection_available = check_connection_available;
	klass->can_unmanaged_external_down = can_unmanaged_external_down;
	klass->realize_start_notify = realize_start_notify;
	klass->unrealize_notify = unrealize_notify;
	klass->carrier_changed_notify = carrier_changed_notify;
	klass->get_ip_iface_identifier = get_ip_iface_identifier;
	klass->unmanaged_on_quit = unmanaged_on_quit;
	klass->deactivate_reset_hw_addr = deactivate_reset_hw_addr;
	klass->parent_changed_notify = parent_changed_notify;
	klass->can_reapply_change = can_reapply_change;
	klass->reapply_connection = reapply_connection;

	obj_properties[PROP_UDI] =
	    g_param_spec_string (NM_DEVICE_UDI, "", "",
	                         NULL,
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_IFACE] =
	    g_param_spec_string (NM_DEVICE_IFACE, "", "",
	                         NULL,
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_IP_IFACE] =
	    g_param_spec_string (NM_DEVICE_IP_IFACE, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DRIVER] =
	    g_param_spec_string (NM_DEVICE_DRIVER, "", "",
	                         NULL,
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DRIVER_VERSION] =
	    g_param_spec_string (NM_DEVICE_DRIVER_VERSION, "", "",
	                         NULL,
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_FIRMWARE_VERSION] =
	    g_param_spec_string (NM_DEVICE_FIRMWARE_VERSION, "", "",
	                         NULL,
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_CAPABILITIES] =
	    g_param_spec_uint (NM_DEVICE_CAPABILITIES, "", "",
	                       0, G_MAXUINT32, NM_DEVICE_CAP_NONE,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_CARRIER] =
	    g_param_spec_boolean (NM_DEVICE_CARRIER, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_MTU] =
	    g_param_spec_uint (NM_DEVICE_MTU, "", "",
	                       0, G_MAXUINT32, 1500,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_IP4_ADDRESS] =
	    g_param_spec_uint (NM_DEVICE_IP4_ADDRESS, "", "",
	                       0, G_MAXUINT32, 0, /* FIXME */
	                       G_PARAM_READWRITE |
	                       G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_IP4_CONFIG] =
	    g_param_spec_string (NM_DEVICE_IP4_CONFIG, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DHCP4_CONFIG] =
	    g_param_spec_string (NM_DEVICE_DHCP4_CONFIG, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_IP6_CONFIG] =
	    g_param_spec_string (NM_DEVICE_IP6_CONFIG, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DHCP6_CONFIG] =
	    g_param_spec_string (NM_DEVICE_DHCP6_CONFIG, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_STATE] =
	    g_param_spec_uint (NM_DEVICE_STATE, "", "",
	                       0, G_MAXUINT32, NM_DEVICE_STATE_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_STATE_REASON] =
	    g_param_spec_variant (NM_DEVICE_STATE_REASON, "", "",
	                          G_VARIANT_TYPE ("(uu)"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_ACTIVE_CONNECTION] =
	    g_param_spec_string (NM_DEVICE_ACTIVE_CONNECTION, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DEVICE_TYPE] =
	    g_param_spec_uint (NM_DEVICE_DEVICE_TYPE, "", "",
	                       0, G_MAXUINT32, NM_DEVICE_TYPE_UNKNOWN,
	                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_LINK_TYPE] =
	    g_param_spec_uint (NM_DEVICE_LINK_TYPE, "", "",
	                       0, G_MAXUINT32, NM_LINK_TYPE_NONE,
	                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_MANAGED] =
	    g_param_spec_boolean (NM_DEVICE_MANAGED, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_AUTOCONNECT] =
	    g_param_spec_boolean (NM_DEVICE_AUTOCONNECT, "", "",
	                          DEFAULT_AUTOCONNECT,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_FIRMWARE_MISSING] =
	    g_param_spec_boolean (NM_DEVICE_FIRMWARE_MISSING, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_NM_PLUGIN_MISSING] =
	    g_param_spec_boolean (NM_DEVICE_NM_PLUGIN_MISSING, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_TYPE_DESC] =
	    g_param_spec_string (NM_DEVICE_TYPE_DESC, "", "",
	                         NULL,
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_RFKILL_TYPE] =
	    g_param_spec_uint (NM_DEVICE_RFKILL_TYPE, "", "",
	                       RFKILL_TYPE_WLAN,
	                       RFKILL_TYPE_MAX,
	                       RFKILL_TYPE_UNKNOWN,
	                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_IFINDEX] =
	    g_param_spec_int (NM_DEVICE_IFINDEX, "", "",
	                      0, G_MAXINT, 0,
	                      G_PARAM_READABLE |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_AVAILABLE_CONNECTIONS] =
	    g_param_spec_boxed (NM_DEVICE_AVAILABLE_CONNECTIONS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_PHYSICAL_PORT_ID] =
	    g_param_spec_string (NM_DEVICE_PHYSICAL_PORT_ID, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_MASTER] =
	    g_param_spec_object (NM_DEVICE_MASTER, "", "",
	                         NM_TYPE_DEVICE,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_PARENT] =
	    g_param_spec_string (NM_DEVICE_PARENT, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_HW_ADDRESS] =
	    g_param_spec_string (NM_DEVICE_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_PERM_HW_ADDRESS] =
	    g_param_spec_string (NM_DEVICE_PERM_HW_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_HAS_PENDING_ACTION] =
	    g_param_spec_boolean (NM_DEVICE_HAS_PENDING_ACTION, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:metered:
	 *
	 * Whether the connection is metered.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_METERED] =
	    g_param_spec_uint (NM_DEVICE_METERED, "", "",
	                       0, G_MAXUINT32, NM_METERED_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_LLDP_NEIGHBORS] =
	    g_param_spec_variant (NM_DEVICE_LLDP_NEIGHBORS, "", "",
	                          G_VARIANT_TYPE ("aa{sv}"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_REAL] =
	    g_param_spec_boolean (NM_DEVICE_REAL, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_SLAVES] =
	    g_param_spec_boxed (NM_DEVICE_SLAVES, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_REFRESH_RATE_MS] =
	    g_param_spec_uint (NM_DEVICE_STATISTICS_REFRESH_RATE_MS, "", "",
	                       0, UINT32_MAX, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_TX_BYTES] =
	    g_param_spec_uint64 (NM_DEVICE_STATISTICS_TX_BYTES, "", "",
	                         0, UINT64_MAX, 0,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_RX_BYTES] =
	    g_param_spec_uint64 (NM_DEVICE_STATISTICS_RX_BYTES, "", "",
	                         0, UINT64_MAX, 0,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CONNECTIVITY] =
	     g_param_spec_uint (NM_DEVICE_CONNECTIVITY, "", "",
	                        NM_CONNECTIVITY_UNKNOWN, NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_UNKNOWN,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[STATE_CHANGED] =
	    g_signal_new (NM_DEVICE_STATE_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (NMDeviceClass, state_changed),
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 3,
	                  G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT);

	signals[AUTOCONNECT_ALLOWED] =
	    g_signal_new (NM_DEVICE_AUTOCONNECT_ALLOWED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0,
	                  autoconnect_allowed_accumulator, NULL, NULL,
	                  G_TYPE_BOOLEAN, 0);

	signals[AUTH_REQUEST] =
	    g_signal_new (NM_DEVICE_AUTH_REQUEST,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  /* context, connection, permission, allow_interaction, callback, user_data */
	                  G_TYPE_NONE, 6, G_TYPE_DBUS_METHOD_INVOCATION, NM_TYPE_CONNECTION, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_POINTER, G_TYPE_POINTER);

	signals[IP4_CONFIG_CHANGED] =
	    g_signal_new (NM_DEVICE_IP4_CONFIG_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_OBJECT, G_TYPE_OBJECT);

	signals[IP6_CONFIG_CHANGED] =
	    g_signal_new (NM_DEVICE_IP6_CONFIG_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_OBJECT, G_TYPE_OBJECT);

	signals[IP6_PREFIX_DELEGATED] =
	    g_signal_new (NM_DEVICE_IP6_PREFIX_DELEGATED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, G_TYPE_POINTER);

	signals[IP6_SUBNET_NEEDED] =
	    g_signal_new (NM_DEVICE_IP6_SUBNET_NEEDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);

	signals[REMOVED] =
	    g_signal_new (NM_DEVICE_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);

	signals[RECHECK_AUTO_ACTIVATE] =
	    g_signal_new (NM_DEVICE_RECHECK_AUTO_ACTIVATE,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);

	signals[RECHECK_ASSUME] =
	    g_signal_new (NM_DEVICE_RECHECK_ASSUME,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);
}
