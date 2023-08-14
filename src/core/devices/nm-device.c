/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2005 - 2018 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device.h"

#include <unistd.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if.h>
#include "nm-compat-headers/linux/if_addr.h"
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/if_infiniband.h>

#include "libnm-std-aux/unaligned.h"
#include "libnm-glib-aux/nm-uuid.h"
#include "libnm-glib-aux/nm-dedup-multi.h"
#include "libnm-glib-aux/nm-random-utils.h"
#include "libnm-systemd-shared/nm-sd-utils-shared.h"

#include "libnm-base/nm-ethtool-base.h"
#include "libnm-core-aux-intern/nm-common-macros.h"
#include "nm-device-private.h"
#include "nm-l3cfg.h"
#include "nm-l3-config-data.h"
#include "nm-l3-ipv4ll.h"
#include "nm-l3-ipv6ll.h"
#include "NetworkManagerUtils.h"
#include "nm-manager.h"
#include "libnm-platform/nm-platform.h"
#include "libnm-platform/nm-platform-utils.h"
#include "libnm-platform/nmp-object.h"
#include "libnm-platform/nmp-global-tracker.h"
#include "ndisc/nm-ndisc.h"
#include "ndisc/nm-lndp-ndisc.h"

#include "dhcp/nm-dhcp-manager.h"
#include "dhcp/nm-dhcp-utils.h"
#include "nm-act-request.h"
#include "nm-pacrunner-manager.h"
#include "dnsmasq/nm-dnsmasq-manager.h"
#include "nm-ip-config.h"
#include "nm-dhcp-config.h"
#include "nm-rfkill-manager.h"
#include "nm-firewall-utils.h"
#include "nm-firewalld-manager.h"
#include "settings/nm-settings-connection.h"
#include "settings/nm-settings.h"
#include "nm-setting-ethtool.h"
#include "nm-setting-ovs-external-ids.h"
#include "nm-setting-ovs-other-config.h"
#include "nm-setting-user.h"
#include "nm-auth-utils.h"
#include "nm-keep-alive.h"
#include "nm-netns.h"
#include "nm-dispatcher.h"
#include "nm-config.h"
#include "c-list/src/c-list.h"
#include "dns/nm-dns-manager.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-systemd-core/nm-sd.h"
#include "nm-lldp-listener.h"
#include "nm-audit-manager.h"
#include "nm-connectivity.h"
#include "nm-dbus-interface.h"
#include "nm-hostname-manager.h"

#include "nm-device-generic.h"
#include "nm-device-bridge.h"
#include "nm-device-loopback.h"
#include "nm-device-vlan.h"
#include "nm-device-vrf.h"
#include "nm-device-wireguard.h"

#include "nm-device-logging.h"

/*****************************************************************************/

#define DEFAULT_AUTOCONNECT TRUE

#define GRACE_PERIOD_MULTIPLIER 2U

#define CARRIER_WAIT_TIME_MS             6000
#define CARRIER_WAIT_TIME_AFTER_MTU_MSEC 10000

#define NM_DEVICE_AUTH_RETRIES_UNSET    -1
#define NM_DEVICE_AUTH_RETRIES_INFINITY -2
#define NM_DEVICE_AUTH_RETRIES_DEFAULT  3

/*****************************************************************************/

typedef void (*ActivationHandleFunc)(NMDevice *self);

typedef enum {
    RELEASE_SLAVE_TYPE_NO_CONFIG,
    RELEASE_SLAVE_TYPE_CONFIG,
    RELEASE_SLAVE_TYPE_CONFIG_FORCE,
} ReleaseSlaveType;

typedef enum {
    CLEANUP_TYPE_KEEP,
    CLEANUP_TYPE_REMOVED,
    CLEANUP_TYPE_DECONFIGURE,
    CLEANUP_TYPE_KEEP_REAPPLY,
} CleanupType;

typedef enum _nm_packed {
    ADDR_METHOD_STATE_DISABLED,
    ADDR_METHOD_STATE_PENDING,
    ADDR_METHOD_STATE_GOOD,
    ADDR_METHOD_STATE_FAILED,
} AddrMethodState;

typedef struct {
    CList         lst_slave;
    NMDevice     *slave;
    GCancellable *cancellable;
    gulong        watch_id;
    bool          slave_is_enslaved;
    bool          configure;
} SlaveInfo;

typedef struct {
    NMDevice               *device;
    GCancellable           *cancellable;
    NMPlatformAsyncCallback callback;
    gpointer                callback_data;
    guint                   num_vfs;
    NMOptionBool            autoprobe;
} SriovOp;

typedef enum {
    /* The various NML3ConfigData types that we track explicitly. Note that
     * their relative order matters: higher numbers in this enum means more
     * important (and during merge overwrites other settings). This is passed
     * as priority to nm_l3cfg_add_config(). */

    L3_CONFIG_DATA_TYPE_LL_4,
    L3_CONFIG_DATA_TYPE_LL_6,

#define L3_CONFIG_DATA_TYPE_LL_X(IS_IPv4) \
    ((IS_IPv4) ? L3_CONFIG_DATA_TYPE_LL_4 : L3_CONFIG_DATA_TYPE_LL_6)

    L3_CONFIG_DATA_TYPE_AC_6,
    L3_CONFIG_DATA_TYPE_PD_6,

    L3_CONFIG_DATA_TYPE_DHCP_4,
    L3_CONFIG_DATA_TYPE_DHCP_6,

#define L3_CONFIG_DATA_TYPE_DHCP_X(IS_IPv4) \
    ((IS_IPv4) ? L3_CONFIG_DATA_TYPE_DHCP_4 : L3_CONFIG_DATA_TYPE_DHCP_6)

    L3_CONFIG_DATA_TYPE_SHARED_4,
    L3_CONFIG_DATA_TYPE_DEVIP_UNSPEC,
    L3_CONFIG_DATA_TYPE_DEVIP_4,
    L3_CONFIG_DATA_TYPE_DEVIP_6,

#define L3_CONFIG_DATA_TYPE_DEVIP(addr_family)     \
    ({                                             \
        L3ConfigDataType _t;                       \
                                                   \
        switch (addr_family) {                     \
        case AF_INET:                              \
            _t = L3_CONFIG_DATA_TYPE_DEVIP_4;      \
            break;                                 \
        case AF_INET6:                             \
            _t = L3_CONFIG_DATA_TYPE_DEVIP_6;      \
            break;                                 \
        default:                                   \
            nm_assert_not_reached();               \
            /* fall-through */                     \
        case AF_UNSPEC:                            \
            _t = L3_CONFIG_DATA_TYPE_DEVIP_UNSPEC; \
            break;                                 \
        }                                          \
                                                   \
        _t;                                        \
    })

    L3_CONFIG_DATA_TYPE_MANUALIP,

    _L3_CONFIG_DATA_TYPE_NUM,
    _L3_CONFIG_DATA_TYPE_NONE,
    _L3_CONFIG_DATA_TYPE_ACD_ONLY,
} L3ConfigDataType;

G_STATIC_ASSERT(NM_L3CFG_CONFIG_PRIORITY_IPV4LL == L3_CONFIG_DATA_TYPE_LL_4);
G_STATIC_ASSERT(NM_L3CFG_CONFIG_PRIORITY_IPV6LL == L3_CONFIG_DATA_TYPE_LL_6);
G_STATIC_ASSERT(NM_L3CFG_CONFIG_PRIORITY_VPN == L3_CONFIG_DATA_TYPE_DEVIP_6);

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
    NMIPConfig *ip_config;
} L3IPData;

typedef struct {
    GSource *check_async_source;
    GSource *req_timeout_source;
    union {
        const NMDeviceIPState state;
        NMDeviceIPState       state_;
    };
    bool wait_for_carrier : 1;
    bool wait_for_ports : 1;
    bool is_disabled : 1;
    bool is_ignore : 1;
    bool do_reapply : 1;
} IPStateData;

typedef struct {
    NMDhcpClient   *client;
    NMDhcpConfig   *config;
    gulong          notify_sigid;
    NMDeviceIPState state;
    union {
        struct {
        } v4;
        struct {
            guint            needed_prefixes;
            NMNDiscDHCPLevel mode;
        } v6;
    };
} IPDhcpStateData;

typedef struct {
    NMDeviceIPState     state;
    NMDeviceStateReason failed_reason;
} IPDevStateData;

typedef struct {
    NMDeviceIPState state;
    union {
        struct {
            NMDnsMasqManager      *dnsmasq_manager;
            NMNetnsSharedIPHandle *shared_ip_handle;
            NMFirewallConfig      *firewall_config;
            gulong                 dnsmasq_state_id;
            const NML3ConfigData  *l3cd;
        } v4;
        struct {
        } v6;
    };
} IPSharedStateData;

typedef struct {
    NMDeviceIPState state;
    union {
        struct {
            NML3IPv4LL             *ipv4ll;
            NML3IPv4LLRegistration *ipv4ll_registation;
            GSource                *timeout_source;
        } v4;
        struct {
            NML3IPv6LL     *ipv6ll;
            GSource        *retry_source;
            NML3IPv6LLState llstate;
            struct in6_addr lladdr;
        } v6;
    };
} IPLLStateData;

struct _NMDeviceConnectivityHandle {
    CList                        concheck_lst;
    NMDevice                    *self;
    NMDeviceConnectivityCallback callback;
    gpointer                     user_data;
    NMConnectivityCheckHandle   *c_handle;
    guint64                      seq;
    bool                         is_periodic : 1;
    bool                         is_periodic_bump : 1;
    bool                         is_periodic_bump_on_complete : 1;
    int                          addr_family;
};

typedef struct {
    int                     ifindex;
    NMEthtoolFeatureStates *features;
    NMOptionBool            requested[_NM_ETHTOOL_ID_FEATURE_NUM];
    NMEthtoolCoalesceState *coalesce;
    NMEthtoolRingState     *ring;
    NMEthtoolPauseState    *pause;
} EthtoolState;

typedef enum {
    RESOLVER_WAIT_ADDRESS = 0,
    RESOLVER_STARTED,
    RESOLVER_DONE,
} ResolverState;

typedef struct {
    ResolverState state;
    GInetAddress *address;
    GCancellable *cancellable;
    char         *hostname;
    NMDevice     *device;
    guint         timeout_id; /* Used when waiting for the address */
    int           addr_family;
} HostnameResolver;

/*****************************************************************************/

enum {
    STATE_CHANGED,
    AUTOCONNECT_ALLOWED,
    L3CD_CHANGED,
    IP6_PREFIX_DELEGATED,
    IP6_SUBNET_NEEDED,
    REMOVED,
    RECHECK_ASSUME,
    DNS_LOOKUP_DONE,
    PLATFORM_ADDRESS_CHANGED,
    LAST_SIGNAL,
};
static guint signals[LAST_SIGNAL] = {0};

NM_GOBJECT_PROPERTIES_DEFINE(NMDevice,
                             PROP_UDI,
                             PROP_PATH,
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

#define PROP_DHCPX_CONFIG(IS_IPv4) ((IS_IPv4) ? PROP_DHCP4_CONFIG : PROP_DHCP6_CONFIG)

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
                             PROP_STATISTICS_REFRESH_RATE_MS,
                             PROP_STATISTICS_TX_BYTES,
                             PROP_STATISTICS_RX_BYTES,
                             PROP_IP4_CONNECTIVITY,
                             PROP_IP6_CONNECTIVITY,
                             PROP_INTERFACE_FLAGS,
                             PROP_PORTS, );

typedef struct _NMDevicePrivate {
    guint device_link_changed_id;
    guint device_ip_link_changed_id;

    GSource *delay_activation_source;

    NMDeviceState       state;
    NMDeviceStateReason state_reason;
    struct {
        guint id;

        /* The @state/@reason is only valid, when @id is set. */
        NMDeviceState       state;
        NMDeviceStateReason reason;
    } queued_state;

    struct {
        const char **arr;
        guint        len;
        guint        alloc;
    } pending_actions;

    NMDBusTrackObjPath parent_device;

    char *udi;
    char *path;

    union {
        const char *const iface;
        char             *iface_;
    };
    union {
        const char *const ip_iface;
        char             *ip_iface_;
    };

    union {
        NML3Cfg *const l3cfg;
        NML3Cfg       *l3cfg_;
    };

    union {
        struct {
            L3IPData l3ipdata_6;
            L3IPData l3ipdata_4;
        };
        L3IPData l3ipdata_x[2];
    };

    NML3CfgCommitTypeHandle *l3cfg_commit_type;

    union {
        const int ifindex;
        int       ifindex_;
    };

    union {
        const int ip_ifindex;
        int       ip_ifindex_;
    };

    union {
        const NML3ConfigData *d;
    } l3cds[_L3_CONFIG_DATA_TYPE_NUM];

    int parent_ifindex;

    int auth_retries;

    union {
        struct {
            HostnameResolver *hostname_resolver_6;
            HostnameResolver *hostname_resolver_4;
        };
        HostnameResolver *hostname_resolver_x[2];
    };

    union {
        const guint8 hw_addr_len; /* read-only */
        guint8       hw_addr_len_;
    };

    HwAddrType hw_addr_type : 5;

    bool real : 1;

    NMDeviceType         type;
    char                *type_desc;
    NMLinkType           link_type;
    NMDeviceCapabilities capabilities;
    char                *driver;
    char                *driver_version;
    char                *firmware_version;
    bool                 firmware_missing : 1;
    bool                 nm_plugin_missing : 1;
    bool
        hw_addr_perm_fake : 1; /* whether the permanent HW address could not be read and is a fake */

    guint8 in_state_changed : 4;

    NMUtilsStableType current_stable_id_type : 3;

    bool activation_state_preserve_external_ports : 1;

    bool nm_owned : 1; /* whether the device is a device owned and created by NM */

    bool assume_state_guess_assume : 1;

    char *assume_state_connection_uuid;

    guint64 udi_id;

    GHashTable *available_connections;
    char       *hw_addr;
    char       *hw_addr_perm;
    char       *hw_addr_initial;
    char       *physical_port_id;
    guint       dev_id;

    NMUnmanagedFlags unmanaged_mask;
    NMUnmanagedFlags unmanaged_flags;

    GSource *delete_on_deactivate_idle_source;

    GCancellable *deactivating_cancellable;

    NMActRequest      *queued_act_request;
    bool               queued_act_request_is_waiting_for_carrier : 1;
    NMDBusTrackObjPath act_request;

    GSource             *activation_idle_source;
    ActivationHandleFunc activation_func;

    guint recheck_assume_id;

    struct {
        guint               call_id;
        NMDeviceStateReason available_reason;
        NMDeviceStateReason unavailable_reason;
    } recheck_available;

    struct {
        NMDispatcherCallId *call_id;
        NMDeviceState       post_state;
        NMDeviceStateReason post_state_reason;
    } dispatcher;

    /* Link stuff */
    guint             link_connected_id;
    guint             link_disconnected_id;
    gulong            config_changed_id;
    gulong            ifindex_changed_id;
    GSource          *carrier_wait_source;
    GSource          *carrier_defer_source;
    guint32           mtu;
    guint32           ip6_mtu; /* FIXME(l3cfg) */
    guint32           mtu_initial;
    guint32           ip6_mtu_initial;
    NMDeviceMtuSource mtu_source;

    guint32 v4_route_table;
    guint32 v6_route_table;

    /* when carrier goes away, we give a grace period of _get_carrier_wait_ms()
     * until taking action.
     *
     * When changing MTU, the device might take longer then that. So, whenever
     * NM changes the MTU it sets @carrier_wait_until_msec to CARRIER_WAIT_TIME_AFTER_MTU_MSEC
     * in the future. This is used to extend the grace period in this particular case. */
    gint64 carrier_wait_until_msec;

    union {
        struct {
            NML3ConfigMergeFlags l3config_merge_flags_6;
            NML3ConfigMergeFlags l3config_merge_flags_4;
        };
        NML3ConfigMergeFlags l3config_merge_flags_x[2];
    };

    union {
        const NMDeviceSysIfaceState sys_iface_state;
        NMDeviceSysIfaceState       sys_iface_state_;
    };

    NMDeviceSysIfaceState sys_iface_state_before_sleep;

    bool carrier : 1;
    bool ignore_carrier : 1;

    bool up : 1; /* IFF_UP */

    bool v4_route_table_initialized : 1;
    bool v6_route_table_initialized : 1;

    bool l3config_merge_flags_has : 1;

    bool v4_route_table_all_sync_before : 1;
    bool v6_route_table_all_sync_before : 1;

    NMDeviceAutoconnectBlockedFlags autoconnect_blocked_flags : 5;

    bool is_enslaved : 1;

    bool device_link_changed_down : 1;

    bool concheck_rp_filter_checked : 1;

    bool tc_committed : 1;

    bool link_props_set : 1;

    NMDeviceStageState stage1_sriov_state : 3;

    char *current_stable_id;

    NMPacrunnerConfId *pacrunner_conf_id;

    struct {
        union {
            const NMDeviceIPState state;
            NMDeviceIPState       state_;
        };
        gulong dnsmgr_update_pending_signal_id;
    } ip_data;

    union {
        struct {
            IPStateData ip_data_6;
            IPStateData ip_data_4;
        };
        IPStateData ip_data_x[2];
    };

    struct {
        GSource *carrier_timeout;
        union {
            struct {
                NMDeviceIPState state_6;
                NMDeviceIPState state_4;
            };
            NMDeviceIPState state_x[2];
        };
        bool carrier_timeout_expired;
    } ipmanual_data;

    union {
        struct {
            IPDhcpStateData ipdhcp_data_6;
            IPDhcpStateData ipdhcp_data_4;
        };
        IPDhcpStateData ipdhcp_data_x[2];
    };

    struct {
        NMNDisc              *ndisc;
        GSource              *ndisc_grace_source;
        gulong                ndisc_changed_id;
        gulong                ndisc_timeout_id;
        NMDeviceIPState       state;
        const NML3ConfigData *l3cd;
    } ipac6_data;

    union {
        struct {
            IPLLStateData ipll_data_6;
            IPLLStateData ipll_data_4;
        };
        IPLLStateData ipll_data_x[2];
    };

    union {
        struct {
            IPSharedStateData ipshared_data_6;
            IPSharedStateData ipshared_data_4;
        };
        IPSharedStateData ipshared_data_x[2];
    };

    union {
        struct {
            IPDevStateData ipdev_data_6;
            IPDevStateData ipdev_data_4;
        };
        IPDevStateData ipdev_data_x[2];
    };

    IPDevStateData ipdev_data_unspec;

    struct {
        /* If we set the addrgenmode6, this records the previously set value. */
        guint8 previous_mode_val;

        /* whether @previous_mode_val is set. */
        bool previous_mode_has : 1;
    } addrgenmode6_data;

    struct {
        NMLogDomain log_domain;
        guint       timeout;
        guint       watch;
        GPid        pid;
        char       *binary;
        char       *address;
        guint       deadline;
    } gw_ping;

    /* Firewall */
    FirewallState             fw_state : 4;
    NMFirewalldManager       *fw_mgr;
    NMFirewalldManagerCallId *fw_call;

    GHashTable *ip6_saved_properties;

    EthtoolState *ethtool_state;
    struct {
        NMPlatformLinkProps       props;
        NMPlatformLinkChangeFlags flags;
    } link_props_state;

    /* master interface for bridge/bond/team slave */
    NMDevice *master;
    gulong    master_ready_id;
    int       master_ifindex;

    /* slave management */
    CList slaves; /* list of SlaveInfo */

    NMMetered metered;

    NMSettings *settings;
    NMManager  *manager;

    NMNetns *netns;

    NMLldpListener *lldp_listener;

    NMConnectivity *concheck_mgr;
    CList           concheck_lst_head;
    struct {
        /* if periodic checks are enabled, this is the source id for the next check. */
        guint p_cur_id;

        /* the currently configured max periodic interval. */
        guint p_max_interval;

        /* the current interval. If we are probing, the interval might be lower
         * then the configured max interval. */
        guint p_cur_interval;

        /* the timestamp, when we last scheduled the timer p_cur_id with current interval
         * p_cur_interval. */
        gint64 p_cur_basetime_ns;

        NMConnectivityState state;
    } concheck_x[2];

    guint   check_delete_unrealized_id;
    guint32 interface_flags;

    guint32             port_detach_count;
    NMDeviceStateReason port_detach_reason;

    struct {
        SriovOp *pending; /* SR-IOV operation currently running */
        SriovOp *next;    /* next SR-IOV operation scheduled */
    } sriov;
    guint sriov_reset_pending;

    struct {
        GSource *timeout_source;
        guint    refresh_rate_ms;
        guint64  tx_bytes;
        guint64  rx_bytes;
    } stats;

    bool mtu_force_set_done : 1;

    bool needs_ip6_subnet : 1;

    NMOptionBool promisc_reset;

    GVariant *ports_variant; /* Array of port devices D-Bus path */
    char     *prop_ip_iface; /* IP interface D-Bus property */
} NMDevicePrivate;

G_DEFINE_ABSTRACT_TYPE(NMDevice, nm_device, NM_TYPE_DBUS_OBJECT)

#define NM_DEVICE_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMDevice, NM_IS_DEVICE)

/*****************************************************************************/

static const NMDBusInterfaceInfoExtended interface_info_device;
static const GDBusSignalInfo             signal_info_state_changed;

static void _dev_l3_cfg_commit(NMDevice *self, gboolean do_sync);

static void _dev_l3_cfg_commit_type_reset(NMDevice *self);

static gboolean nm_device_master_add_slave(NMDevice *self, NMDevice *slave, gboolean configure);
static void     nm_device_slave_notify_enslave(NMDevice *self, gboolean success);
static void     nm_device_slave_notify_release(NMDevice           *self,
                                               NMDeviceStateReason reason,
                                               ReleaseSlaveType    release_type);

static void _dev_ipll6_start(NMDevice *self);

static void _dev_ipac6_start_continue(NMDevice *self);
static void _dev_ipac6_ndisc_set_router_config(NMDevice *self);

static guint32 _dev_default_route_metric_penalty_get(NMDevice *self, int addr_family);

static guint32 _prop_get_ipv4_dad_timeout(NMDevice *self);

static void   _carrier_wait_check_queued_act_request(NMDevice *self);
static gint64 _get_carrier_wait_ms(NMDevice *self);

static GBytes *_prop_get_ipv6_dhcp_duid(NMDevice     *self,
                                        NMConnection *connection,
                                        GBytes       *hwaddr,
                                        gboolean     *out_enforce);

static const char *_activation_func_to_string(ActivationHandleFunc func);

static void
_set_state_full(NMDevice *self, NMDeviceState state, NMDeviceStateReason reason, gboolean quitting);
static void queued_state_clear(NMDevice *device);
static void ip_check_ping_watch_cb(GPid pid, int status, gpointer user_data);
static void nm_device_start_ip_check(NMDevice *self);
static void realize_start_setup(NMDevice             *self,
                                const NMPlatformLink *plink,
                                gboolean              assume_state_guess_assume,
                                const char           *assume_state_connection_uuid,
                                gboolean              set_nm_owned,
                                NMUnmanFlagOp         unmanaged_user_explicit,
                                gboolean              force_platform_init);
static void _set_mtu(NMDevice *self, guint32 mtu);
static void _commit_mtu(NMDevice *self);
static void _cancel_activation(NMDevice *self);

static void _dev_ipll4_notify_event(NMDevice *self);

static void _dev_ip_state_check(NMDevice *self, int addr_family);

static void _dev_ipmanual_check_ready(NMDevice *self);

static void
_dev_ipdhcpx_cleanup(NMDevice *self, int addr_family, gboolean reset_dhcp_config, gboolean release);

static void _dev_ip_state_check_async(NMDevice *self, int addr_family);

static void _dev_ipdhcpx_set_state(NMDevice *self, int addr_family, NMDeviceIPState state);

static void _dev_ipdhcpx_restart(NMDevice *self, int addr_family, gboolean release);

static gboolean
_dev_ipac6_grace_period_start(NMDevice *self, guint32 timeout_sec, gboolean force_restart);

static void _dev_ipac6_start(NMDevice *self);

static void _dev_ipac6_set_state(NMDevice *self, NMDeviceIPState state);

static void
_dev_unmanaged_check_external_down(NMDevice *self, gboolean only_if_unmanaged, gboolean now);

static void _dev_ipshared4_start(NMDevice *self);
static void _dev_ipshared4_spawn_dnsmasq(NMDevice *self);

static void _dev_ipshared6_start(NMDevice *self);

static void
_cleanup_ip_pre(NMDevice *self, int addr_family, CleanupType cleanup_type, gboolean preserve_dhcp);

static void concheck_update_state(NMDevice           *self,
                                  int                 addr_family,
                                  NMConnectivityState state,
                                  gboolean            is_periodic);

static void sriov_op_cb(GError *error, gpointer user_data);

static void device_ifindex_changed_cb(NMManager *manager, NMDevice *device_changed, NMDevice *self);
static gboolean device_link_changed(gpointer user_data);
static gboolean _get_maybe_ipv6_disabled(NMDevice *self);
static void     deactivate_ready(NMDevice *self, NMDeviceStateReason reason);

/*****************************************************************************/

#define _NMLOG_addr_family(level, prefix, addr_family, fmt, ...)                             \
    G_STMT_START                                                                             \
    {                                                                                        \
        const int _addr_family2 = (addr_family);                                             \
                                                                                             \
        _NMLOG(level,                                                                        \
               (_addr_family2 == AF_UNSPEC ? LOGD_IP : LOGD_IPX(NM_IS_IPv4(_addr_family2))), \
               "" prefix "%s: " fmt,                                                         \
               nm_utils_addr_family_to_str(_addr_family2),                                   \
               ##__VA_ARGS__);                                                               \
    }                                                                                        \
    G_STMT_END

#define _NMLOG_ip(level, ...) _NMLOG_addr_family(level, "ip", __VA_ARGS__)
#define _LOGT_ip(...)         _NMLOG_ip(LOGL_TRACE, __VA_ARGS__)
#define _LOGD_ip(...)         _NMLOG_ip(LOGL_DEBUG, __VA_ARGS__)
#define _LOGI_ip(...)         _NMLOG_ip(LOGL_INFO, __VA_ARGS__)
#define _LOGW_ip(...)         _NMLOG_ip(LOGL_WARN, __VA_ARGS__)

#define _NMLOG_ipll(level, ...) _NMLOG_addr_family(level, "ip:ll", __VA_ARGS__)
#define _LOGT_ipll(...)         _NMLOG_ipll(LOGL_TRACE, __VA_ARGS__)
#define _LOGD_ipll(...)         _NMLOG_ipll(LOGL_DEBUG, __VA_ARGS__)
#define _LOGI_ipll(...)         _NMLOG_ipll(LOGL_INFO, __VA_ARGS__)
#define _LOGW_ipll(...)         _NMLOG_ipll(LOGL_WARN, __VA_ARGS__)

#define _NMLOG_ipdev(level, ...) _NMLOG_addr_family(level, "ip:dev", __VA_ARGS__)
#define _LOGT_ipdev(...)         _NMLOG_ipdev(LOGL_TRACE, __VA_ARGS__)
#define _LOGD_ipdev(...)         _NMLOG_ipdev(LOGL_DEBUG, __VA_ARGS__)
#define _LOGI_ipdev(...)         _NMLOG_ipdev(LOGL_INFO, __VA_ARGS__)
#define _LOGW_ipdev(...)         _NMLOG_ipdev(LOGL_WARN, __VA_ARGS__)

#define _NMLOG_ipdhcp(level, ...) _NMLOG_addr_family(level, "ip:dhcp", __VA_ARGS__)
#define _LOGT_ipdhcp(...)         _NMLOG_ipdhcp(LOGL_TRACE, __VA_ARGS__)
#define _LOGD_ipdhcp(...)         _NMLOG_ipdhcp(LOGL_DEBUG, __VA_ARGS__)
#define _LOGI_ipdhcp(...)         _NMLOG_ipdhcp(LOGL_INFO, __VA_ARGS__)
#define _LOGW_ipdhcp(...)         _NMLOG_ipdhcp(LOGL_WARN, __VA_ARGS__)

#define _NMLOG_ipshared(level, ...) _NMLOG_addr_family(level, "ip:shared", __VA_ARGS__)
#define _LOGT_ipshared(...)         _NMLOG_ipshared(LOGL_TRACE, __VA_ARGS__)
#define _LOGD_ipshared(...)         _NMLOG_ipshared(LOGL_DEBUG, __VA_ARGS__)
#define _LOGI_ipshared(...)         _NMLOG_ipshared(LOGL_INFO, __VA_ARGS__)
#define _LOGW_ipshared(...)         _NMLOG_ipshared(LOGL_WARN, __VA_ARGS__)

#define _NMLOG_ipac6(level, ...) _NMLOG_addr_family(level, "ip:ac6", AF_UNSPEC, __VA_ARGS__)
#define _LOGT_ipac6(...)         _NMLOG_ipac6(LOGL_TRACE, __VA_ARGS__)
#define _LOGD_ipac6(...)         _NMLOG_ipac6(LOGL_DEBUG, __VA_ARGS__)
#define _LOGI_ipac6(...)         _NMLOG_ipac6(LOGL_INFO, __VA_ARGS__)
#define _LOGW_ipac6(...)         _NMLOG_ipac6(LOGL_WARN, __VA_ARGS__)

#define _NMLOG_ipmanual(level, ...) _NMLOG_addr_family(level, "ip:manual", __VA_ARGS__)
#define _LOGT_ipmanual(...)         _NMLOG_ipmanual(LOGL_TRACE, __VA_ARGS__)
#define _LOGD_ipmanual(...)         _NMLOG_ipmanual(LOGL_DEBUG, __VA_ARGS__)
#define _LOGI_ipmanual(...)         _NMLOG_ipmanual(LOGL_INFO, __VA_ARGS__)
#define _LOGW_ipmanual(...)         _NMLOG_ipmanual(LOGL_WARN, __VA_ARGS__)

/*****************************************************************************/

#define _CACHED_BOOL(cached_value, cmd)                  \
    ({                                                   \
        NMTernary *const _cached_value = (cached_value); \
                                                         \
        nm_assert(_cached_value);                        \
        nm_assert_is_ternary(*_cached_value);            \
                                                         \
        if (*_cached_value == NM_TERNARY_DEFAULT)        \
            *_cached_value = !!(cmd);                    \
                                                         \
        !!(*_cached_value);                              \
    })

/*****************************************************************************/

static void
_hostname_resolver_free(HostnameResolver *resolver)
{
    if (!resolver)
        return;

    nm_clear_g_source(&resolver->timeout_id);
    nm_clear_g_cancellable(&resolver->cancellable);
    nm_g_object_unref(resolver->address);
    g_free(resolver->hostname);
    nm_g_slice_free(resolver);
}

/*****************************************************************************/

/**
 * Update the "ip_iface" property when something changes (device
 * state, ifindex) and emit a notify signal if needed. Note that
 * the property must be NULL for devices without an ifindex and
 * when the device is not activated. This behavior is part of the
 * API and should not be changed.
 */
static void
update_prop_ip_iface(NMDevice *self)
{
    NMDevicePrivate *priv     = NM_DEVICE_GET_PRIVATE(self);
    const char      *ip_iface = NULL;
    gs_free char    *to_free  = NULL;

    if (nm_device_get_ip_ifindex(self) > 0
        && (priv->state == NM_DEVICE_STATE_UNMANAGED
            || (priv->state >= NM_DEVICE_STATE_IP_CHECK
                && priv->state <= NM_DEVICE_STATE_DEACTIVATING))) {
        ip_iface = nm_utils_str_utf8safe_escape(nm_device_get_ip_iface(self),
                                                NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL,
                                                &to_free);
    }

    if (!nm_streq0(priv->prop_ip_iface, ip_iface)) {
        g_free(priv->prop_ip_iface);
        priv->prop_ip_iface = to_free ? g_steal_pointer(&to_free) : g_strdup(ip_iface);
        _notify(self, PROP_IP_IFACE);
    }
}

/*****************************************************************************/

static NMSettingIP6ConfigPrivacy
_ip6_privacy_clamp(NMSettingIP6ConfigPrivacy use_tempaddr)
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

/*****************************************************************************/

static const char *
_prop_get_connection_stable_id(NMDevice          *self,
                               NMConnection      *connection,
                               NMUtilsStableType *out_stable_type)
{
    NMDevicePrivate *priv;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(NM_IS_CONNECTION(connection));
    nm_assert(out_stable_type);

    priv = NM_DEVICE_GET_PRIVATE(self);

    /* we cache the generated stable ID for the time of an activation.
     *
     * The reason is, that we don't want the stable-id to change as long
     * as the device is active.
     *
     * Especially with ${RANDOM} stable-id we want to generate *one* configuration
     * for each activation. */
    if (G_UNLIKELY(!priv->current_stable_id)) {
        gs_free char        *generated = NULL;
        NMUtilsStableType    stable_type;
        NMSettingConnection *s_con;
        gboolean             hwaddr_is_fake;
        const char          *hwaddr;
        const char          *stable_id;
        const char          *uuid;

        s_con = nm_connection_get_setting_connection(connection);

        stable_id = nm_setting_connection_get_stable_id(s_con);

        if (!stable_id) {
            stable_id =
                nm_config_data_get_connection_default(NM_CONFIG_GET_DATA,
                                                      NM_CON_DEFAULT("connection.stable-id"),
                                                      self);
        }

        uuid = nm_connection_get_uuid(connection);

        /* the cloned-mac-address may be generated based on the stable-id.
         * Thus, at this point, we can only use the permanent MAC address
         * as seed. */
        hwaddr = nm_device_get_permanent_hw_address_full(self, TRUE, &hwaddr_is_fake);

        stable_type = nm_utils_stable_id_parse(stable_id,
                                               nm_device_get_ip_iface(self),
                                               !hwaddr_is_fake ? hwaddr : NULL,
                                               nm_utils_boot_id_str(),
                                               uuid,
                                               &generated);

        /* current_stable_id_type is a bitfield! */
        priv->current_stable_id_type = stable_type;
        nm_assert(stable_type <= (NMUtilsStableType) 0x3);
        nm_assert(stable_type + (NMUtilsStableType) 1 > (NMUtilsStableType) 0);
        nm_assert(priv->current_stable_id_type == stable_type);

        if (stable_type == NM_UTILS_STABLE_TYPE_UUID)
            priv->current_stable_id = g_strdup(uuid);
        else if (stable_type == NM_UTILS_STABLE_TYPE_STABLE_ID)
            priv->current_stable_id = g_strdup(stable_id);
        else if (stable_type == NM_UTILS_STABLE_TYPE_GENERATED)
            priv->current_stable_id =
                nm_str_realloc(nm_utils_stable_id_generated_complete(generated));
        else {
            nm_assert(stable_type == NM_UTILS_STABLE_TYPE_RANDOM);
            priv->current_stable_id = nm_str_realloc(nm_utils_stable_id_random());
        }
        _LOGT(LOGD_DEVICE,
              "stable-id: type=%d, \"%s\""
              "%s%s%s",
              (int) priv->current_stable_id_type,
              priv->current_stable_id,
              NM_PRINT_FMT_QUOTED(stable_type == NM_UTILS_STABLE_TYPE_GENERATED,
                                  " from \"",
                                  generated,
                                  "\"",
                                  ""));
    }

    nm_assert(priv->current_stable_id);
    *out_stable_type = priv->current_stable_id_type;
    return priv->current_stable_id;
}

static GBytes *
_prop_get_ipv6_dhcp_duid(NMDevice     *self,
                         NMConnection *connection,
                         GBytes       *hwaddr,
                         gboolean     *out_enforce)
{
    NMSettingIPConfig *s_ip6;
    const char        *duid;
    const char        *duid_error;
    GBytes            *duid_out;
    gboolean           duid_enforce = TRUE;
    gs_free char      *logstr1      = NULL;
    const guint8      *hwaddr_bin;
    gsize              hwaddr_len;
    int                arp_type;

    s_ip6 = nm_connection_get_setting_ip6_config(connection);
    duid  = nm_setting_ip6_config_get_dhcp_duid(NM_SETTING_IP6_CONFIG(s_ip6));

    if (!duid) {
        duid = nm_config_data_get_connection_default(NM_CONFIG_GET_DATA,
                                                     NM_CON_DEFAULT("ipv6.dhcp-duid"),
                                                     self);
        if (!duid)
            duid = "lease";
    }

    if (nm_streq(duid, "lease")) {
        duid_enforce = FALSE;
        duid_out     = nm_utils_generate_duid_from_machine_id();
        goto out_good;
    }

    if (!_nm_utils_dhcp_duid_valid(duid, &duid_out)) {
        duid_error = "invalid duid";
        goto out_fail;
    }

    if (duid_out)
        goto out_good;

    if (NM_IN_STRSET(duid, "ll", "llt")) {
        if (!hwaddr) {
            duid_error = "missing link-layer address";
            goto out_fail;
        }

        hwaddr_bin = g_bytes_get_data(hwaddr, &hwaddr_len);
        arp_type   = nm_utils_arp_type_detect_from_hwaddrlen(hwaddr_len);
        if (arp_type < 0) {
            duid_error = "unsupported link-layer address";
            goto out_fail;
        }

        if (nm_streq(duid, "ll"))
            duid_out = nm_utils_generate_duid_ll(arp_type, hwaddr_bin, hwaddr_len);
        else {
            duid_out = nm_utils_generate_duid_llt(arp_type,
                                                  hwaddr_bin,
                                                  hwaddr_len,
                                                  nm_utils_host_id_get_timestamp_nsec()
                                                      / NM_UTILS_NSEC_PER_SEC);
        }

        goto out_good;
    }

    if (NM_IN_STRSET(duid, "stable-ll", "stable-llt", "stable-uuid")) {
        /* preferably, we would salt the checksum differently for each @duid type. We missed
         * to do that initially, so most types use the DEFAULT_SALT.
         *
         * Implementations that are added later, should use a distinct salt instead,
         * like "stable-ll"/"stable-llt" with ARPHRD_INFINIBAND below. */
        const guint32                    DEFAULT_SALT = 670531087u;
        nm_auto_free_checksum GChecksum *sum          = NULL;
        NMUtilsStableType                stable_type;
        const char                      *stable_id = NULL;
        guint32                          salted_header;
        const guint8                    *host_id;
        gsize                            host_id_len;
        union {
            guint8 sha256[NM_UTILS_CHECKSUM_LENGTH_SHA256];
            guint8 hwaddr_eth[ETH_ALEN];
            guint8 hwaddr_infiniband[INFINIBAND_ALEN];
            NMUuid uuid;
            struct _nm_packed {
                guint8  hwaddr[ETH_ALEN];
                guint32 timestamp;
            } llt_eth;
            struct _nm_packed {
                guint8  hwaddr[INFINIBAND_ALEN];
                guint32 timestamp;
            } llt_infiniband;
        } digest;

        stable_id = _prop_get_connection_stable_id(self, connection, &stable_type);

        if (NM_IN_STRSET(duid, "stable-ll", "stable-llt")) {
            /* for stable LL/LLT DUIDs, we still need a hardware address to detect
             * the arp-type. Alternatively, we would be able to detect it based on
             * other means (e.g. NMDevice type), but instead require the hardware
             * address to be present. This is at least consistent with the "ll"/"llt"
             * modes above. */
            if (!hwaddr) {
                duid_error = "missing link-layer address";
                goto out_fail;
            }
            if ((arp_type = nm_utils_arp_type_detect_from_hwaddrlen(g_bytes_get_size(hwaddr)))
                < 0) {
                duid_error = "unsupported link-layer address";
                goto out_fail;
            }

            if (arp_type == ARPHRD_ETHER)
                salted_header = DEFAULT_SALT;
            else {
                nm_assert(arp_type == ARPHRD_INFINIBAND);
                salted_header = 0x42492CEFu + ((guint32) arp_type);
            }
        } else {
            salted_header = DEFAULT_SALT;
            arp_type      = -1;
        }

        salted_header = htonl(salted_header + ((guint32) stable_type));

        nm_utils_host_id_get(&host_id, &host_id_len);

        sum = g_checksum_new(G_CHECKSUM_SHA256);
        g_checksum_update(sum, (const guchar *) &salted_header, sizeof(salted_header));
        g_checksum_update(sum, (const guchar *) stable_id, -1);
        g_checksum_update(sum, (const guchar *) host_id, host_id_len);
        nm_utils_checksum_get_digest(sum, digest.sha256);

        G_STATIC_ASSERT_EXPR(sizeof(digest) == sizeof(digest.sha256));

        if (nm_streq(duid, "stable-ll")) {
            switch (arp_type) {
            case ARPHRD_ETHER:
                duid_out = nm_utils_generate_duid_ll(arp_type,
                                                     digest.hwaddr_eth,
                                                     sizeof(digest.hwaddr_eth));
                break;
            case ARPHRD_INFINIBAND:
                duid_out = nm_utils_generate_duid_ll(arp_type,
                                                     digest.hwaddr_infiniband,
                                                     sizeof(digest.hwaddr_infiniband));
                break;
            default:
                g_return_val_if_reached(NULL);
            }
        } else if (nm_streq(duid, "stable-llt")) {
            gint64  time;
            guint32 timestamp;

#define EPOCH_DATETIME_THREE_YEARS (356 * 24 * 3600 * 3)

            /* We want a variable time between the host_id timestamp and three years
             * before. Let's compute the time (in seconds) from 0 to 3 years; then we'll
             * subtract it from the host_id timestamp.
             */
            time = nm_utils_host_id_get_timestamp_nsec() / NM_UTILS_NSEC_PER_SEC;

            /* don't use too old timestamps. They cannot be expressed in DUID-LLT and
             * would all be truncated to zero. */
            time = NM_MAX(time, NM_UTILS_EPOCH_DATETIME_200001010000 + EPOCH_DATETIME_THREE_YEARS);

            switch (arp_type) {
            case ARPHRD_ETHER:
                timestamp = unaligned_read_be32(&digest.llt_eth.timestamp);
                time -= timestamp % EPOCH_DATETIME_THREE_YEARS;
                duid_out = nm_utils_generate_duid_llt(arp_type,
                                                      digest.llt_eth.hwaddr,
                                                      sizeof(digest.llt_eth.hwaddr),
                                                      time);
                break;
            case ARPHRD_INFINIBAND:
                timestamp = unaligned_read_be32(&digest.llt_infiniband.timestamp);
                time -= timestamp % EPOCH_DATETIME_THREE_YEARS;
                duid_out = nm_utils_generate_duid_llt(arp_type,
                                                      digest.llt_infiniband.hwaddr,
                                                      sizeof(digest.llt_infiniband.hwaddr),
                                                      time);
                break;
            default:
                g_return_val_if_reached(NULL);
            }
        } else {
            nm_assert(nm_streq(duid, "stable-uuid"));
            duid_out = nm_utils_generate_duid_uuid(&digest.uuid);
        }

        goto out_good;
    }

    g_return_val_if_reached(NULL);

out_fail:
    nm_assert(!duid_out && duid_error);
    {
        NMUuid uuid;

        _LOGW(LOGD_IP6 | LOGD_DHCP6,
              "ipv6.dhcp-duid: failure to generate %s DUID: %s. Fallback to random DUID-UUID.",
              duid,
              duid_error);

        nm_random_get_bytes(&uuid, sizeof(uuid));
        duid_out = nm_utils_generate_duid_uuid(&uuid);
    }

out_good:
    nm_assert(duid_out);
    _LOGD(LOGD_IP6 | LOGD_DHCP6,
          "ipv6.dhcp-duid: generate %s DUID '%s' (%s)",
          duid,
          (logstr1 = nm_dhcp_utils_duid_to_string(duid_out)),
          duid_enforce ? "enforcing" : "prefer lease");

    NM_SET_OUT(out_enforce, duid_enforce);
    return duid_out;
}

static guint32
_prop_get_ipv6_ra_timeout(NMDevice *self)
{
    NMConnection *connection;
    gint32        timeout;

    G_STATIC_ASSERT_EXPR(NM_RA_TIMEOUT_DEFAULT == 0);
    G_STATIC_ASSERT_EXPR(NM_RA_TIMEOUT_INFINITY == G_MAXINT32);

    connection = nm_device_get_applied_connection(self);

    timeout = nm_setting_ip6_config_get_ra_timeout(
        NM_SETTING_IP6_CONFIG(nm_connection_get_setting_ip6_config(connection)));
    if (timeout > 0)
        return timeout;
    nm_assert(timeout == 0);

    return nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                       NM_CON_DEFAULT("ipv6.ra-timeout"),
                                                       self,
                                                       0,
                                                       G_MAXINT32,
                                                       0);
}

static NMSettingConnectionMdns
_prop_get_connection_mdns(NMDevice *self)
{
    NMConnection           *connection;
    NMSettingConnectionMdns mdns = NM_SETTING_CONNECTION_MDNS_DEFAULT;

    g_return_val_if_fail(NM_IS_DEVICE(self), NM_SETTING_CONNECTION_MDNS_DEFAULT);

    connection = nm_device_get_applied_connection(self);
    if (connection)
        mdns = nm_setting_connection_get_mdns(nm_connection_get_setting_connection(connection));
    if (mdns != NM_SETTING_CONNECTION_MDNS_DEFAULT)
        return mdns;

    return nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                       NM_CON_DEFAULT("connection.mdns"),
                                                       self,
                                                       NM_SETTING_CONNECTION_MDNS_NO,
                                                       NM_SETTING_CONNECTION_MDNS_YES,
                                                       NM_SETTING_CONNECTION_MDNS_DEFAULT);
}

static NMSettingConnectionLlmnr
_prop_get_connection_llmnr(NMDevice *self)
{
    NMConnection            *connection;
    NMSettingConnectionLlmnr llmnr = NM_SETTING_CONNECTION_LLMNR_DEFAULT;

    g_return_val_if_fail(NM_IS_DEVICE(self), NM_SETTING_CONNECTION_LLMNR_DEFAULT);

    connection = nm_device_get_applied_connection(self);
    if (connection)
        llmnr = nm_setting_connection_get_llmnr(nm_connection_get_setting_connection(connection));
    if (llmnr != NM_SETTING_CONNECTION_LLMNR_DEFAULT)
        return llmnr;

    return nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                       NM_CON_DEFAULT("connection.llmnr"),
                                                       self,
                                                       NM_SETTING_CONNECTION_LLMNR_NO,
                                                       NM_SETTING_CONNECTION_LLMNR_YES,
                                                       NM_SETTING_CONNECTION_LLMNR_DEFAULT);
}

static NMSettingConnectionDnsOverTls
_prop_get_connection_dns_over_tls(NMDevice *self)
{
    NMConnection                 *connection;
    NMSettingConnectionDnsOverTls dns_over_tls = NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT;

    g_return_val_if_fail(NM_IS_DEVICE(self), NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT);

    connection = nm_device_get_applied_connection(self);
    if (connection)
        dns_over_tls = nm_setting_connection_get_dns_over_tls(
            nm_connection_get_setting_connection(connection));
    if (dns_over_tls != NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT)
        return dns_over_tls;

    return nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                       NM_CON_DEFAULT("connection.dns-over-tls"),
                                                       self,
                                                       NM_SETTING_CONNECTION_DNS_OVER_TLS_NO,
                                                       NM_SETTING_CONNECTION_DNS_OVER_TLS_YES,
                                                       NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT);
}

static NMMptcpFlags
_prop_get_connection_mptcp_flags(NMDevice *self)
{
    NMConnection *connection;
    NMMptcpFlags  mptcp_flags = NM_MPTCP_FLAGS_NONE;

    g_return_val_if_fail(NM_IS_DEVICE(self), NM_MPTCP_FLAGS_DISABLED);

    connection = nm_device_get_applied_connection(self);
    if (connection) {
        mptcp_flags =
            nm_setting_connection_get_mptcp_flags(nm_connection_get_setting_connection(connection));
    }

    if (mptcp_flags == NM_MPTCP_FLAGS_NONE) {
        guint64 v;

        v = nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                        NM_CON_DEFAULT("connection.mptcp-flags"),
                                                        self,
                                                        0,
                                                        G_MAXINT64,
                                                        NM_MPTCP_FLAGS_NONE);
        if (v != NM_MPTCP_FLAGS_NONE) {
            /* We silently ignore all invalid flags (and will normalize them away below). */
            mptcp_flags = (NMMptcpFlags) v;
            if (mptcp_flags == NM_MPTCP_FLAGS_NONE)
                mptcp_flags = NM_MPTCP_FLAGS_ENABLED;
        }
    }

    if (mptcp_flags == NM_MPTCP_FLAGS_NONE)
        mptcp_flags = _NM_MPTCP_FLAGS_DEFAULT;

    mptcp_flags = nm_mptcp_flags_normalize(mptcp_flags);

    if (!NM_FLAGS_HAS(mptcp_flags, NM_MPTCP_FLAGS_DISABLED)) {
        if (!NM_FLAGS_HAS(mptcp_flags, NM_MPTCP_FLAGS_ALSO_WITHOUT_SYSCTL)) {
            guint32 v;

            /* If enabled, but without "also-without-sysctl", then MPTCP is still
             * disabled, if the sysctl says so...
             *
             * We evaluate this here. The point is that the decision is then cached
             * until deactivation/reapply. The user can toggle the sysctl any time,
             * but we only pick it up at certain moments (now). */
            v = nm_platform_sysctl_get_int32(
                nm_device_get_platform(self),
                NMP_SYSCTL_PATHID_ABSOLUTE("/proc/sys/net/mptcp/enabled"),
                -1);
            if (v <= 0)
                mptcp_flags = NM_MPTCP_FLAGS_DISABLED;
        } else
            mptcp_flags = NM_FLAGS_UNSET(mptcp_flags, NM_MPTCP_FLAGS_ALSO_WITHOUT_SYSCTL);
    }

    return mptcp_flags;
}

static guint32
_prop_get_ipvx_route_table(NMDevice *self, int addr_family)
{
    NMDevicePrivate     *priv = NM_DEVICE_GET_PRIVATE(self);
    NMDeviceClass       *klass;
    NMConnection        *connection;
    NMSettingIPConfig   *s_ip;
    guint32              route_table    = 0;
    gboolean             is_user_config = TRUE;
    NMSettingConnection *s_con;
    NMSettingVrf        *s_vrf;

    nm_assert_addr_family(addr_family);

    /* the route table setting affects how we sync routes. We shall
     * not change it while the device is active, hence, cache it. */
    if (NM_IS_IPv4(addr_family)) {
        if (priv->v4_route_table_initialized)
            return priv->v4_route_table;
    } else {
        if (priv->v6_route_table_initialized)
            return priv->v6_route_table;
    }

    connection = nm_device_get_applied_connection(self);
    if (connection) {
        s_ip = nm_connection_get_setting_ip_config(connection, addr_family);
        if (s_ip)
            route_table = nm_setting_ip_config_get_route_table(s_ip);
    }
    if (route_table == 0u) {
        gint64 v;

        v = nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                        NM_IS_IPv4(addr_family)
                                                            ? NM_CON_DEFAULT("ipv4.route-table")
                                                            : NM_CON_DEFAULT("ipv6.route-table"),
                                                        self,
                                                        0,
                                                        G_MAXUINT32,
                                                        -1);
        if (v != -1) {
            route_table    = v;
            is_user_config = FALSE;
        }
    }

    if (route_table == 0u && connection
        && (s_con = nm_connection_get_setting_connection(connection))
        && (nm_streq0(nm_setting_connection_get_slave_type(s_con), NM_SETTING_VRF_SETTING_NAME)
            && priv->master && nm_device_get_device_type(priv->master) == NM_DEVICE_TYPE_VRF)) {
        const NMPlatformLnkVrf *lnk;

        lnk = nm_platform_link_get_lnk_vrf(nm_device_get_platform(self),
                                           nm_device_get_ifindex(priv->master),
                                           NULL);

        if (lnk)
            route_table = lnk->table;
    }

    if (route_table == 0u && connection
        && (s_vrf = (NMSettingVrf *) nm_connection_get_setting(connection, NM_TYPE_SETTING_VRF))) {
        route_table = nm_setting_vrf_get_table(s_vrf);
    }

    klass = NM_DEVICE_GET_CLASS(self);
    if (klass->coerce_route_table)
        route_table = klass->coerce_route_table(self, addr_family, route_table, is_user_config);

    if (NM_IS_IPv4(addr_family)) {
        priv->v4_route_table_initialized = TRUE;
        priv->v4_route_table             = route_table;
    } else {
        priv->v6_route_table_initialized = TRUE;
        priv->v6_route_table             = route_table;
    }

    _LOGT(LOGD_DEVICE,
          "ipv%c.route-table = %u%s",
          nm_utils_addr_family_to_char(addr_family),
          (guint) (route_table ?: RT_TABLE_MAIN),
          route_table != 0u ? "" : " (policy routing not enabled)");

    return route_table;
}

static gboolean
_prop_get_connection_lldp(NMDevice *self)
{
    NMConnection           *connection;
    NMSettingConnection    *s_con;
    NMSettingConnectionLldp lldp = NM_SETTING_CONNECTION_LLDP_DEFAULT;

    connection = nm_device_get_applied_connection(self);
    g_return_val_if_fail(connection, FALSE);

    s_con = nm_connection_get_setting_connection(connection);
    g_return_val_if_fail(s_con, FALSE);

    lldp = nm_setting_connection_get_lldp(s_con);
    if (lldp == NM_SETTING_CONNECTION_LLDP_DEFAULT) {
        lldp = nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                           NM_CON_DEFAULT("connection.lldp"),
                                                           self,
                                                           NM_SETTING_CONNECTION_LLDP_DEFAULT,
                                                           NM_SETTING_CONNECTION_LLDP_ENABLE_RX,
                                                           NM_SETTING_CONNECTION_LLDP_DEFAULT);
        if (lldp == NM_SETTING_CONNECTION_LLDP_DEFAULT)
            lldp = NM_SETTING_CONNECTION_LLDP_DISABLE;
    }
    return lldp == NM_SETTING_CONNECTION_LLDP_ENABLE_RX;
}

static NMSettingIP4LinkLocal
_prop_get_ipv4_link_local(NMDevice *self)
{
    NMSettingIP4Config   *s_ip4;
    NMSettingIP4LinkLocal link_local;

    s_ip4 = nm_device_get_applied_setting(self, NM_TYPE_SETTING_IP4_CONFIG);
    if (!s_ip4)
        return NM_SETTING_IP4_LL_DISABLED;

    if (NM_IS_DEVICE_LOOPBACK(self))
        return NM_SETTING_IP4_LL_DISABLED;

    link_local = nm_setting_ip4_config_get_link_local(s_ip4);

    if (link_local == NM_SETTING_IP4_LL_DEFAULT) {
        /* For connections without a ipv4.link-local property configured the global configuration
           might defines the default value for ipv4.link-local. */
        link_local = nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                                 NM_CON_DEFAULT("ipv4.link-local"),
                                                                 self,
                                                                 NM_SETTING_IP4_LL_AUTO,
                                                                 NM_SETTING_IP4_LL_ENABLED,
                                                                 NM_SETTING_IP4_LL_DEFAULT);
        if (link_local == NM_SETTING_IP4_LL_DEFAULT) {
            /* If there is no global configuration for ipv4.link-local assume auto */
            link_local = NM_SETTING_IP4_LL_AUTO;
        } else if (link_local == NM_SETTING_IP4_LL_ENABLED
                   && nm_streq(nm_setting_ip_config_get_method((NMSettingIPConfig *) s_ip4),
                               NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
            /* ipv4.method=disabled has higher priority than the global ipv4.link-local=enabled */
            link_local = NM_SETTING_IP4_LL_DISABLED;
        } else if (link_local == NM_SETTING_IP4_LL_DISABLED
                   && nm_streq(nm_setting_ip_config_get_method((NMSettingIPConfig *) s_ip4),
                               NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)) {
            /* ipv4.method=link-local has higher priority than the global ipv4.link-local=disabled */
            link_local = NM_SETTING_IP4_LL_ENABLED;
        }
    }

    if (link_local == NM_SETTING_IP4_LL_AUTO) {
        link_local = nm_streq(nm_setting_ip_config_get_method((NMSettingIPConfig *) s_ip4),
                              NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)
                         ? NM_SETTING_IP4_LL_ENABLED
                         : NM_SETTING_IP4_LL_DISABLED;
    }

    return link_local;
}

static guint32
_prop_get_ipv4_dad_timeout(NMDevice *self)
{
    NMConnection      *connection;
    NMSettingIPConfig *s_ip4   = NULL;
    int                timeout = -1;

    connection = nm_device_get_applied_connection(self);
    if (connection)
        s_ip4 = nm_connection_get_setting_ip4_config(connection);
    if (s_ip4)
        timeout = nm_setting_ip_config_get_dad_timeout(s_ip4);

    nm_assert(timeout >= -1 && timeout <= NM_SETTING_IP_CONFIG_DAD_TIMEOUT_MAX);

    if (timeout >= 0)
        return timeout;

    return nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                       NM_CON_DEFAULT("ipv4.dad-timeout"),
                                                       self,
                                                       0,
                                                       NM_SETTING_IP_CONFIG_DAD_TIMEOUT_MAX,
                                                       0);
}

static guint32
_prop_get_ipvx_dhcp_timeout(NMDevice *self, int addr_family)
{
    NMDeviceClass *klass;
    NMConnection  *connection;
    guint32        timeout;
    int            timeout_i;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert_addr_family(addr_family);

    connection = nm_device_get_applied_connection(self);

    timeout_i = nm_setting_ip_config_get_dhcp_timeout(
        nm_connection_get_setting_ip_config(connection, addr_family));
    nm_assert(timeout_i >= 0 && timeout_i <= G_MAXINT32);

    timeout = (guint32) timeout_i;
    if (timeout)
        goto out;

    timeout = nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                          NM_IS_IPv4(addr_family)
                                                              ? NM_CON_DEFAULT("ipv4.dhcp-timeout")
                                                              : NM_CON_DEFAULT("ipv6.dhcp-timeout"),
                                                          self,
                                                          0,
                                                          G_MAXINT32,
                                                          0);
    if (timeout)
        goto out;

    klass = NM_DEVICE_GET_CLASS(self);
    if (klass->get_dhcp_timeout_for_device) {
        timeout = klass->get_dhcp_timeout_for_device(self, addr_family);
        if (timeout)
            goto out;
    }

    timeout = NM_DHCP_TIMEOUT_DEFAULT;

out:
    G_STATIC_ASSERT_EXPR(G_MAXINT32 == NM_DHCP_TIMEOUT_INFINITY);
    nm_assert(timeout > 0);
    nm_assert(timeout <= G_MAXINT32);
    return timeout;
}

static guint32
_prop_get_ipvx_dns_priority(NMDevice *self, int addr_family)
{
    NMConnection      *connection;
    NMSettingIPConfig *s_ip;
    int                prio = 0;

    connection = nm_device_get_applied_connection(self);
    s_ip       = nm_connection_get_setting_ip_config(connection, addr_family);
    if (s_ip)
        prio = nm_setting_ip_config_get_dns_priority(s_ip);

    if (prio == 0) {
        prio = nm_config_data_get_connection_default_int64(
            NM_CONFIG_GET_DATA,
            NM_IS_IPv4(addr_family) ? NM_CON_DEFAULT("ipv4.dns-priority")
                                    : NM_CON_DEFAULT("ipv6.dns-priority"),
            self,
            G_MININT32,
            G_MAXINT32,
            0);
        if (prio == 0) {
            prio = nm_device_is_vpn(self) ? NM_DNS_PRIORITY_DEFAULT_VPN
                                          : NM_DNS_PRIORITY_DEFAULT_NORMAL;
        }
    }

    nm_assert(prio != 0);
    return prio;
}

static guint32
_prop_get_ipvx_required_timeout(NMDevice *self, int addr_family)
{
    NMConnection      *connection;
    NMSettingIPConfig *s_ip;
    int                timeout;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert_addr_family(addr_family);

    connection = nm_device_get_applied_connection(self);
    if (!connection)
        return 0;

    s_ip = nm_connection_get_setting_ip_config(connection, addr_family);
    if (!s_ip)
        return 0;

    timeout = nm_setting_ip_config_get_required_timeout(s_ip);
    nm_assert(timeout >= -1);

    if (timeout > -1)
        return (guint32) timeout;

    return nm_config_data_get_connection_default_int64(
        NM_CONFIG_GET_DATA,
        NM_IS_IPv4(addr_family) ? NM_CON_DEFAULT("ipv4.required-timeout")
                                : NM_CON_DEFAULT("ipv6.required-timeout"),
        self,
        0,
        G_MAXINT32,
        0);
}

static gboolean
_prop_get_ipvx_may_fail(NMDevice *self, int addr_family)
{
    NMConnection      *connection;
    NMSettingIPConfig *s_ip = NULL;

    connection = nm_device_get_applied_connection(self);
    if (connection)
        s_ip = nm_connection_get_setting_ip_config(connection, addr_family);

    return !s_ip || nm_setting_ip_config_get_may_fail(s_ip);
}

static gboolean
_prop_get_ipvx_may_fail_cached(NMDevice *self, int addr_family, NMTernary *cache)
{
    return _CACHED_BOOL(cache, _prop_get_ipvx_may_fail(self, addr_family));
}

/**
 * _prop_get_ipvx_dhcp_iaid:
 * @self: the #NMDevice
 * @addr_family: the address family
 * @connection: the connection
 * @log_silent: whether to log the result.
 * @out_is_explicit: on return, %TRUE if the user set a valid IAID in
 *   the connection or in global configuration; %FALSE if the connection
 *   property was empty and no valid global configuration was provided.
 *
 * Returns: a IAID value for this device and the given connection.
 */
static guint32
_prop_get_ipvx_dhcp_iaid(NMDevice     *self,
                         int           addr_family,
                         NMConnection *connection,
                         gboolean      log_silent,
                         gboolean     *out_is_explicit)
{
    const int          IS_IPv4 = NM_IS_IPv4(addr_family);
    NMSettingIPConfig *s_ip;
    const char        *iaid_str;
    guint32            iaid;
    const char        *iface;
    const char        *fail_reason;
    gboolean           is_explicit = TRUE;
    gint64             i64;

    s_ip     = nm_connection_get_setting_ip_config(connection, addr_family);
    iaid_str = nm_setting_ip_config_get_dhcp_iaid(s_ip);
    if (!iaid_str) {
        iaid_str = nm_config_data_get_connection_default(NM_CONFIG_GET_DATA,
                                                         IS_IPv4 ? NM_CON_DEFAULT("ipv4.dhcp-iaid")
                                                                 : NM_CON_DEFAULT("ipv6.dhcp-iaid"),
                                                         self);
        if (!iaid_str) {
            iaid_str    = NM_IAID_IFNAME;
            is_explicit = FALSE;
        } else if (!_nm_utils_iaid_verify(iaid_str, NULL)) {
            if (!log_silent) {
                _LOGW(LOGD_DEVICE,
                      "invalid global default '%s' for ipv%c.dhcp-iaid",
                      iaid_str,
                      nm_utils_addr_family_to_char(addr_family));
            }
            iaid_str    = NM_IAID_IFNAME;
            is_explicit = FALSE;
        }
    }

    if (nm_streq0(iaid_str, NM_IAID_MAC)) {
        const NMPlatformLink *pllink;

        pllink = nm_platform_link_get(nm_device_get_platform(self), nm_device_get_ip_ifindex(self));
        if (!pllink || pllink->l_address.len < 4) {
            fail_reason = "invalid link-layer address";
            goto out_fail;
        }

        /* @iaid is in native endianness. Use unaligned_read_be32()
         * so that the IAID for a given MAC address is the same on
         * BE and LE machines. */
        iaid = unaligned_read_be32(&pllink->l_address.data[pllink->l_address.len - 4]);
        goto out_good;
    } else if (nm_streq0(iaid_str, NM_IAID_PERM_MAC)) {
        guint8      hwaddr_buf[_NM_UTILS_HWADDR_LEN_MAX];
        const char *hwaddr_str;
        gsize       hwaddr_len;

        hwaddr_str = nm_device_get_permanent_hw_address(self);
        if (!hwaddr_str) {
            fail_reason = "no permanent link-layer address";
            goto out_fail;
        }

        if (!_nm_utils_hwaddr_aton(hwaddr_str, hwaddr_buf, sizeof(hwaddr_buf), &hwaddr_len))
            g_return_val_if_reached(0);

        if (hwaddr_len < 4) {
            fail_reason = "invalid link-layer address";
            goto out_fail;
        }

        iaid = unaligned_read_be32(&hwaddr_buf[hwaddr_len - 4]);
        goto out_good;
    } else if (nm_streq(iaid_str, NM_IAID_STABLE)) {
        nm_auto_free_checksum GChecksum *sum = NULL;
        guint8                           digest[NM_UTILS_CHECKSUM_LENGTH_SHA1];
        NMUtilsStableType                stable_type;
        const char                      *stable_id;
        guint32                          salted_header;
        const guint8                    *host_id;
        gsize                            host_id_len;

        stable_id     = _prop_get_connection_stable_id(self, connection, &stable_type);
        salted_header = htonl(53390459 + stable_type);
        nm_utils_host_id_get(&host_id, &host_id_len);
        iface = nm_device_get_ip_iface(self);

        sum = g_checksum_new(G_CHECKSUM_SHA1);
        g_checksum_update(sum, (const guchar *) &salted_header, sizeof(salted_header));
        g_checksum_update(sum, (const guchar *) stable_id, strlen(stable_id) + 1);
        g_checksum_update(sum, (const guchar *) iface, strlen(iface) + 1);
        g_checksum_update(sum, (const guchar *) host_id, host_id_len);
        nm_utils_checksum_get_digest(sum, digest);

        iaid = unaligned_read_be32(digest);
        goto out_good;
    } else if (nm_streq(iaid_str, NM_IAID_IFNAME)) {
        iface = nm_device_get_ip_iface(self);
        iaid  = nm_utils_create_dhcp_iaid(TRUE, (const guint8 *) iface, strlen(iface));
        goto out_good;
    } else if (_nm_utils_iaid_verify(iaid_str, &i64)) {
        if (i64 < 0) {
            fail_reason = nm_assert_unreachable_val("bug handling iaid value");
            goto out_fail;
        }
        nm_assert(i64 <= G_MAXUINT32);
        iaid = (guint32) i64;
        goto out_good;
    }

    fail_reason = nm_assert_unreachable_val("bug handling iaid code");
out_fail:
    nm_assert(fail_reason);
    if (!log_silent) {
        _LOGW(LOGD_DEVICE | LOGD_DHCPX(IS_IPv4) | LOGD_IPX(IS_IPv4),
              "ipv%c.dhcp-iaid: failure to generate IAID: %s. Using interface-name based IAID",
              nm_utils_addr_family_to_char(addr_family),
              fail_reason);
    }
    is_explicit = FALSE;
    iface       = nm_device_get_ip_iface(self);
    iaid        = nm_utils_create_dhcp_iaid(TRUE, (const guint8 *) iface, strlen(iface));
out_good:
    if (!log_silent) {
        char buf[NM_DHCP_IAID_TO_HEXSTR_BUF_LEN];

        _LOGD(LOGD_DEVICE | LOGD_DHCPX(IS_IPv4) | LOGD_IPX(IS_IPv4),
              "ipv%c.dhcp-iaid: using %u (%s) IAID (str: '%s', explicit %d)",
              nm_utils_addr_family_to_char(addr_family),
              iaid,
              nm_dhcp_iaid_to_hexstr(iaid, buf),
              iaid_str,
              is_explicit);
    }
    NM_SET_OUT(out_is_explicit, is_explicit);
    return iaid;
}

static NMDhcpHostnameFlags
_prop_get_ipvx_dhcp_hostname_flags(NMDevice *self, int addr_family)
{
    NMConnection         *connection;
    NMSettingIPConfig    *s_ip;
    NMDhcpHostnameFlags   flags;
    gs_free_error GError *error = NULL;

    g_return_val_if_fail(NM_IS_DEVICE(self), NM_DHCP_HOSTNAME_FLAG_NONE);

    connection = nm_device_get_applied_connection(self);
    s_ip       = nm_connection_get_setting_ip_config(connection, addr_family);
    g_return_val_if_fail(s_ip, NM_DHCP_HOSTNAME_FLAG_NONE);

    if (!nm_setting_ip_config_get_dhcp_send_hostname(s_ip))
        return NM_DHCP_HOSTNAME_FLAG_NONE;

    flags = nm_setting_ip_config_get_dhcp_hostname_flags(s_ip);
    if (flags != NM_DHCP_HOSTNAME_FLAG_NONE)
        return flags;

    flags = nm_config_data_get_connection_default_int64(
        NM_CONFIG_GET_DATA,
        NM_IS_IPv4(addr_family) ? NM_CON_DEFAULT("ipv4.dhcp-hostname-flags")
                                : NM_CON_DEFAULT("ipv6.dhcp-hostname-flags"),
        self,
        0,
        NM_DHCP_HOSTNAME_FLAG_FQDN_CLEAR_FLAGS,
        0);

    if (!_nm_utils_validate_dhcp_hostname_flags(flags, addr_family, &error)) {
        _LOGW(LOGD_DEVICE,
              "invalid global default value 0x%x for ipv%c.%s: %s",
              (guint) flags,
              nm_utils_addr_family_to_char(addr_family),
              NM_SETTING_IP_CONFIG_DHCP_HOSTNAME_FLAGS,
              error->message);
        flags = NM_DHCP_HOSTNAME_FLAG_NONE;
    }

    if (flags != NM_DHCP_HOSTNAME_FLAG_NONE)
        return flags;

    if (NM_IS_IPv4(addr_family))
        return NM_DHCP_HOSTNAME_FLAGS_FQDN_DEFAULT_IP4;
    else
        return NM_DHCP_HOSTNAME_FLAGS_FQDN_DEFAULT_IP6;
}

static const char *
_prop_get_connection_mud_url(NMDevice *self, NMSettingConnection *s_con)
{
    const char *mud_url;
    const char *s;

    mud_url = nm_setting_connection_get_mud_url(s_con);

    if (mud_url) {
        if (nm_streq(mud_url, NM_CONNECTION_MUD_URL_NONE))
            return NULL;
        return mud_url;
    }

    s = nm_config_data_get_connection_default(NM_CONFIG_GET_DATA,
                                              NM_CON_DEFAULT("connection.mud-url"),
                                              self);
    if (s) {
        if (nm_streq(s, NM_CONNECTION_MUD_URL_NONE))
            return NULL;
        if (nm_sd_http_url_is_valid_https(s))
            return s;
    }

    return NULL;
}

static GBytes *
_prop_get_ipv4_dhcp_client_id(NMDevice *self, NMConnection *connection, GBytes *hwaddr)
{
    NMSettingIPConfig *s_ip4;
    const char        *client_id;
    guint8            *client_id_buf;
    const char        *fail_reason;
    guint8             hwaddr_bin_buf[_NM_UTILS_HWADDR_LEN_MAX];
    const guint8      *hwaddr_bin;
    int                arp_type;
    gsize              hwaddr_len;
    GBytes            *result;
    gs_free char      *logstr1 = NULL;

    s_ip4     = nm_connection_get_setting_ip4_config(connection);
    client_id = nm_setting_ip4_config_get_dhcp_client_id(NM_SETTING_IP4_CONFIG(s_ip4));

    if (!client_id) {
        client_id = nm_config_data_get_connection_default(NM_CONFIG_GET_DATA,
                                                          NM_CON_DEFAULT("ipv4.dhcp-client-id"),
                                                          self);
        if (client_id && !client_id[0]) {
            /* a non-empty client-id is always valid, see nm_dhcp_utils_client_id_string_to_bytes().  */
            client_id = NULL;
        }
    }

    if (!client_id) {
        _LOGD(LOGD_DEVICE | LOGD_DHCP4 | LOGD_IP4,
              "ipv4.dhcp-client-id: no explicit client-id configured");
        return NULL;
    }

    if (nm_streq(client_id, "mac")) {
        if (!hwaddr) {
            fail_reason = "missing link-layer address";
            goto out_fail;
        }

        hwaddr_bin = g_bytes_get_data(hwaddr, &hwaddr_len);
        arp_type   = nm_utils_arp_type_detect_from_hwaddrlen(hwaddr_len);
        if (arp_type < 0) {
            fail_reason = "unsupported link-layer address";
            goto out_fail;
        }

        result = nm_utils_dhcp_client_id_mac(arp_type, hwaddr_bin, hwaddr_len);
        goto out_good;
    }

    if (nm_streq(client_id, "perm-mac")) {
        const char *hwaddr_str;

        hwaddr_str = nm_device_get_permanent_hw_address(self);
        if (!hwaddr_str) {
            fail_reason = "missing permanent link-layer address";
            goto out_fail;
        }

        if (!_nm_utils_hwaddr_aton(hwaddr_str, hwaddr_bin_buf, sizeof(hwaddr_bin_buf), &hwaddr_len))
            g_return_val_if_reached(NULL);

        arp_type = nm_utils_arp_type_detect_from_hwaddrlen(hwaddr_len);
        if (arp_type < 0) {
            fail_reason = "unsupported permanent link-layer address";
            goto out_fail;
        }

        result = nm_utils_dhcp_client_id_mac(arp_type, hwaddr_bin_buf, hwaddr_len);
        goto out_good;
    }

    if (nm_streq(client_id, "duid")) {
        guint32 iaid = _prop_get_ipvx_dhcp_iaid(self, AF_INET, connection, FALSE, NULL);

        result = nm_utils_dhcp_client_id_systemd_node_specific(iaid);
        goto out_good;
    }

    if (nm_streq(client_id, "ipv6-duid")) {
        gs_unref_bytes GBytes *duid = NULL;
        gboolean               iaid_is_explicit;
        guint32                iaid;
        const guint8          *duid_arr;
        gsize                  duid_len;

        iaid = _prop_get_ipvx_dhcp_iaid(self, AF_INET, connection, FALSE, &iaid_is_explicit);
        if (!iaid_is_explicit)
            iaid = _prop_get_ipvx_dhcp_iaid(self, AF_INET6, connection, FALSE, &iaid_is_explicit);

        duid = _prop_get_ipv6_dhcp_duid(self, connection, hwaddr, NULL);

        nm_assert(duid);

        duid_arr = g_bytes_get_data(duid, &duid_len);

        nm_assert(duid_arr);
        nm_assert(duid_len >= 2u + 1u);
        nm_assert(duid_len <= 2u + 128u);

        result = nm_utils_dhcp_client_id_duid(iaid, duid_arr, duid_len);
        goto out_good;
    }

    if (nm_streq(client_id, "stable")) {
        nm_auto_free_checksum GChecksum *sum = NULL;
        guint8                           digest[NM_UTILS_CHECKSUM_LENGTH_SHA1];
        NMUtilsStableType                stable_type;
        const char                      *stable_id;
        guint32                          salted_header;
        const guint8                    *host_id;
        gsize                            host_id_len;

        stable_id     = _prop_get_connection_stable_id(self, connection, &stable_type);
        salted_header = htonl(2011610591 + stable_type);
        nm_utils_host_id_get(&host_id, &host_id_len);

        sum = g_checksum_new(G_CHECKSUM_SHA1);
        g_checksum_update(sum, (const guchar *) &salted_header, sizeof(salted_header));
        g_checksum_update(sum, (const guchar *) stable_id, strlen(stable_id) + 1);
        g_checksum_update(sum, (const guchar *) host_id, host_id_len);
        nm_utils_checksum_get_digest(sum, digest);

        client_id_buf    = g_malloc(1 + 15);
        client_id_buf[0] = 0;
        memcpy(&client_id_buf[1], digest, 15);
        result = g_bytes_new_take(client_id_buf, 1 + 15);
        goto out_good;
    }

    result = nm_dhcp_utils_client_id_string_to_bytes(client_id);
    goto out_good;

out_fail:
    nm_assert(fail_reason);
    _LOGW(LOGD_DEVICE | LOGD_DHCP4 | LOGD_IP4,
          "ipv4.dhcp-client-id: failure to generate client id (%s). Use random client id",
          fail_reason);
    client_id_buf    = g_malloc(1 + 15);
    client_id_buf[0] = 0;
    nm_random_get_bytes(&client_id_buf[1], 15);
    result = g_bytes_new_take(client_id_buf, 1 + 15);

out_good:
    nm_assert(result);
    _LOGD(LOGD_DEVICE | LOGD_DHCP4 | LOGD_IP4,
          "ipv4.dhcp-client-id: use \"%s\" client ID: %s",
          client_id,
          (logstr1 = nm_dhcp_utils_duid_to_string(result)));
    return result;
}

static GBytes *
_prop_get_ipv4_dhcp_vendor_class_identifier(NMDevice *self, NMSettingIP4Config *s_ip4)
{
    gs_free char *to_free = NULL;
    const char   *conn_prop;
    GBytes       *bytes = NULL;
    const char   *bin;
    gsize         len;

    conn_prop = nm_setting_ip4_config_get_dhcp_vendor_class_identifier(s_ip4);

    if (!conn_prop) {
        /* set in NetworkManager.conf ? */
        conn_prop = nm_config_data_get_connection_default(
            NM_CONFIG_GET_DATA,
            NM_CON_DEFAULT("ipv4.dhcp-vendor-class-identifier"),
            self);

        if (conn_prop && !nm_utils_validate_dhcp4_vendor_class_id(conn_prop, NULL))
            conn_prop = NULL;
    }

    if (conn_prop) {
        bin = nm_utils_buf_utf8safe_unescape(conn_prop,
                                             NM_UTILS_STR_UTF8_SAFE_FLAG_NONE,
                                             &len,
                                             (gpointer *) &to_free);
        if (to_free)
            bytes = g_bytes_new_take(g_steal_pointer(&to_free), len);
        else
            bytes = g_bytes_new(bin, len);
    }

    return bytes;
}

static NMSettingIP6ConfigPrivacy
_prop_get_ipv6_ip6_privacy(NMDevice *self)
{
    NMSettingIP6ConfigPrivacy ip6_privacy;
    NMConnection             *connection;

    g_return_val_if_fail(self, NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);

    /* 1.) First look at the per-connection setting. If it is not -1 (unknown),
     * use it. */
    connection = nm_device_get_applied_connection(self);
    if (connection) {
        NMSettingIPConfig *s_ip6 = nm_connection_get_setting_ip6_config(connection);

        if (s_ip6) {
            ip6_privacy = nm_setting_ip6_config_get_ip6_privacy(NM_SETTING_IP6_CONFIG(s_ip6));
            ip6_privacy = _ip6_privacy_clamp(ip6_privacy);
            if (ip6_privacy != NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN)
                return ip6_privacy;
        }
    }

    /* 2.) use the default value from the configuration. */
    ip6_privacy =
        nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                    NM_CON_DEFAULT("ipv6.ip6-privacy"),
                                                    self,
                                                    NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN,
                                                    NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR,
                                                    NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);
    if (ip6_privacy != NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN)
        return ip6_privacy;

    if (!nm_device_get_ip_ifindex(self))
        return NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;

    /* 3.) No valid default-value configured. Fallback to reading sysctl.
     *
     * Instead of reading static config files in /etc, just read the current sysctl value.
     * This works as NM only writes to "/proc/sys/net/ipv6/conf/IFNAME/use_tempaddr", but leaves
     * the "default" entry untouched. */
    ip6_privacy = nm_platform_sysctl_get_int32(
        nm_device_get_platform(self),
        NMP_SYSCTL_PATHID_ABSOLUTE("/proc/sys/net/ipv6/conf/default/use_tempaddr"),
        NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN);
    return _ip6_privacy_clamp(ip6_privacy);
}

static NMSettingIP6ConfigAddrGenMode
_prop_get_ipv6_addr_gen_mode(NMDevice *self)
{
    NMSettingIP6ConfigAddrGenMode addr_gen_mode;
    NMSettingIP6Config           *s_ip6;
    gint64                        c;

    g_return_val_if_fail(self, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY);

    s_ip6 = nm_device_get_applied_setting(self, NM_TYPE_SETTING_IP6_CONFIG);
    if (s_ip6) {
        addr_gen_mode = nm_setting_ip6_config_get_addr_gen_mode(s_ip6);
        if (NM_IN_SET(addr_gen_mode,
                      NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
                      NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY))
            return addr_gen_mode;
    } else
        addr_gen_mode = NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT;

    nm_assert(NM_IN_SET(addr_gen_mode,
                        NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT_OR_EUI64,
                        NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT));

    c = nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                    NM_CON_DEFAULT("ipv6.addr-gen-mode"),
                                                    self,
                                                    NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
                                                    NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT,
                                                    -1);
    if (c != -1)
        addr_gen_mode = c;

    if (addr_gen_mode == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT)
        addr_gen_mode = NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY;
    else if (addr_gen_mode == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_DEFAULT_OR_EUI64)
        addr_gen_mode = NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64;

    nm_assert(NM_IN_SET(addr_gen_mode,
                        NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
                        NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY));

    return addr_gen_mode;
}

static const char *
_prop_get_x_cloned_mac_address(NMDevice *self, NMConnection *connection, gboolean is_wifi)
{
    NMSetting  *setting;
    const char *addr = NULL;

    setting = nm_connection_get_setting(connection,
                                        is_wifi ? NM_TYPE_SETTING_WIRELESS : NM_TYPE_SETTING_WIRED);
    if (setting) {
        addr = is_wifi ? nm_setting_wireless_get_cloned_mac_address((NMSettingWireless *) setting)
                       : nm_setting_wired_get_cloned_mac_address((NMSettingWired *) setting);
    }

    if (!addr) {
        const char *a;

        a = nm_config_data_get_connection_default(
            NM_CONFIG_GET_DATA,
            is_wifi ? NM_CON_DEFAULT("wifi.cloned-mac-address")
                    : NM_CON_DEFAULT("ethernet.cloned-mac-address"),
            self);

        addr = NM_CLONED_MAC_PRESERVE;

        if (!a) {
            if (is_wifi) {
                NMSettingMacRandomization v;

                /* for backward compatibility, read the deprecated wifi.mac-address-randomization setting. */
                v = nm_config_data_get_connection_default_int64(
                    NM_CONFIG_GET_DATA,
                    NM_CON_DEFAULT("wifi.mac-address-randomization"),
                    self,
                    NM_SETTING_MAC_RANDOMIZATION_DEFAULT,
                    NM_SETTING_MAC_RANDOMIZATION_ALWAYS,
                    NM_SETTING_MAC_RANDOMIZATION_DEFAULT);
                if (v == NM_SETTING_MAC_RANDOMIZATION_ALWAYS)
                    addr = NM_CLONED_MAC_RANDOM;
            }
        } else if (NM_CLONED_MAC_IS_SPECIAL(a) || nm_utils_hwaddr_valid(a, ETH_ALEN))
            addr = a;
    }

    return addr;
}

static const char *
_prop_get_x_generate_mac_address_mask(NMDevice *self, NMConnection *connection, gboolean is_wifi)
{
    NMSetting  *setting;
    const char *value;

    setting = nm_connection_get_setting(connection,
                                        is_wifi ? NM_TYPE_SETTING_WIRELESS : NM_TYPE_SETTING_WIRED);
    if (setting) {
        value =
            is_wifi
                ? nm_setting_wireless_get_generate_mac_address_mask((NMSettingWireless *) setting)
                : nm_setting_wired_get_generate_mac_address_mask((NMSettingWired *) setting);
        if (value)
            return value;
    }

    return nm_config_data_get_connection_default(
        NM_CONFIG_GET_DATA,
        is_wifi ? NM_CON_DEFAULT("wifi.generate-mac-address-mask")
                : NM_CON_DEFAULT("ethernet.generate-mac-address-mask"),
        self);
}

/*****************************************************************************/

static void
_ethtool_features_reset(NMDevice *self, NMPlatform *platform, EthtoolState *ethtool_state)
{
    gs_free NMEthtoolFeatureStates *features = NULL;

    features = g_steal_pointer(&ethtool_state->features);

    if (!nm_platform_ethtool_set_features(platform,
                                          ethtool_state->ifindex,
                                          features,
                                          ethtool_state->requested,
                                          FALSE))
        _LOGW(LOGD_DEVICE, "ethtool: failure resetting one or more offload features");
    else
        _LOGD(LOGD_DEVICE, "ethtool: offload features successfully reset");
}

static void
_ethtool_features_set(NMDevice         *self,
                      NMPlatform       *platform,
                      EthtoolState     *ethtool_state,
                      NMSettingEthtool *s_ethtool)
{
    gs_free NMEthtoolFeatureStates *features = NULL;

    if (ethtool_state->features)
        _ethtool_features_reset(self, platform, ethtool_state);

    if (nm_setting_ethtool_init_features(s_ethtool, ethtool_state->requested) == 0)
        return;

    features = nm_platform_ethtool_get_link_features(platform, ethtool_state->ifindex);
    if (!features) {
        _LOGW(LOGD_DEVICE, "ethtool: failure setting offload features (cannot read features)");
        return;
    }

    if (!nm_platform_ethtool_set_features(platform,
                                          ethtool_state->ifindex,
                                          features,
                                          ethtool_state->requested,
                                          TRUE))
        _LOGW(LOGD_DEVICE, "ethtool: failure setting one or more offload features");
    else
        _LOGD(LOGD_DEVICE, "ethtool: offload features successfully set");

    ethtool_state->features = g_steal_pointer(&features);
}

static void
_ethtool_coalesce_reset(NMDevice *self, NMPlatform *platform, EthtoolState *ethtool_state)
{
    gs_free NMEthtoolCoalesceState *coalesce = NULL;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(NM_IS_PLATFORM(platform));
    nm_assert(ethtool_state);

    coalesce = g_steal_pointer(&ethtool_state->coalesce);
    if (!coalesce)
        return;

    if (!nm_platform_ethtool_set_coalesce(platform, ethtool_state->ifindex, coalesce))
        _LOGW(LOGD_DEVICE, "ethtool: failure resetting one or more coalesce settings");
    else
        _LOGD(LOGD_DEVICE, "ethtool: coalesce settings successfully reset");
}

static void
_ethtool_coalesce_set(NMDevice         *self,
                      NMPlatform       *platform,
                      EthtoolState     *ethtool_state,
                      NMSettingEthtool *s_ethtool)
{
    NMEthtoolCoalesceState coalesce_old;
    NMEthtoolCoalesceState coalesce_new;
    gboolean               has_old = FALSE;
    GHashTable            *hash;
    GHashTableIter         iter;
    const char            *name;
    GVariant              *variant;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(NM_IS_PLATFORM(platform));
    nm_assert(NM_IS_SETTING_ETHTOOL(s_ethtool));
    nm_assert(ethtool_state);
    nm_assert(!ethtool_state->coalesce);

    hash = _nm_setting_option_hash(NM_SETTING(s_ethtool), FALSE);
    if (!hash)
        return;

    g_hash_table_iter_init(&iter, hash);
    while (g_hash_table_iter_next(&iter, (gpointer *) &name, (gpointer *) &variant)) {
        NMEthtoolID ethtool_id = nm_ethtool_id_get_by_name(name);

        if (!nm_ethtool_id_is_coalesce(ethtool_id))
            continue;

        if (!has_old) {
            if (!nm_platform_ethtool_get_link_coalesce(platform,
                                                       ethtool_state->ifindex,
                                                       &coalesce_old)) {
                _LOGW(LOGD_DEVICE, "ethtool: failure getting coalesce settings (cannot read)");
                return;
            }
            has_old      = TRUE;
            coalesce_new = coalesce_old;
        }

        nm_assert(g_variant_is_of_type(variant, G_VARIANT_TYPE_UINT32));
        coalesce_new.s[_NM_ETHTOOL_ID_COALESCE_AS_IDX(ethtool_id)] = g_variant_get_uint32(variant);
    }

    if (!has_old)
        return;

    ethtool_state->coalesce = nm_memdup(&coalesce_old, sizeof(coalesce_old));

    if (!nm_platform_ethtool_set_coalesce(platform, ethtool_state->ifindex, &coalesce_new)) {
        _LOGW(LOGD_DEVICE, "ethtool: failure setting coalesce settings");
        return;
    }

    _LOGD(LOGD_DEVICE, "ethtool: coalesce settings successfully set");
}

static void
_ethtool_ring_reset(NMDevice *self, NMPlatform *platform, EthtoolState *ethtool_state)
{
    gs_free NMEthtoolRingState *ring = NULL;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(NM_IS_PLATFORM(platform));
    nm_assert(ethtool_state);

    ring = g_steal_pointer(&ethtool_state->ring);
    if (!ring)
        return;

    if (!nm_platform_ethtool_set_ring(platform, ethtool_state->ifindex, ring))
        _LOGW(LOGD_DEVICE, "ethtool: failure resetting one or more ring settings");
    else
        _LOGD(LOGD_DEVICE, "ethtool: ring settings successfully reset");
}

static void
_ethtool_ring_set(NMDevice         *self,
                  NMPlatform       *platform,
                  EthtoolState     *ethtool_state,
                  NMSettingEthtool *s_ethtool)
{
    NMEthtoolRingState ring_old;
    NMEthtoolRingState ring_new;
    GHashTable        *hash;
    GHashTableIter     iter;
    const char        *name;
    GVariant          *variant;
    gboolean           has_old = FALSE;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(NM_IS_PLATFORM(platform));
    nm_assert(NM_IS_SETTING_ETHTOOL(s_ethtool));
    nm_assert(ethtool_state);
    nm_assert(!ethtool_state->ring);

    hash = _nm_setting_option_hash(NM_SETTING(s_ethtool), FALSE);
    if (!hash)
        return;

    g_hash_table_iter_init(&iter, hash);
    while (g_hash_table_iter_next(&iter, (gpointer *) &name, (gpointer *) &variant)) {
        NMEthtoolID ethtool_id = nm_ethtool_id_get_by_name(name);
        guint32     u32;

        if (!nm_ethtool_id_is_ring(ethtool_id))
            continue;

        nm_assert(g_variant_is_of_type(variant, G_VARIANT_TYPE_UINT32));

        if (!has_old) {
            if (!nm_platform_ethtool_get_link_ring(platform, ethtool_state->ifindex, &ring_old)) {
                _LOGW(LOGD_DEVICE,
                      "ethtool: failure setting ring options (cannot read existing setting)");
                return;
            }
            has_old  = TRUE;
            ring_new = ring_old;
        }

        u32 = g_variant_get_uint32(variant);

        switch (ethtool_id) {
        case NM_ETHTOOL_ID_RING_RX:
            ring_new.rx_pending = u32;
            break;
        case NM_ETHTOOL_ID_RING_RX_JUMBO:
            ring_new.rx_jumbo_pending = u32;
            break;
        case NM_ETHTOOL_ID_RING_RX_MINI:
            ring_new.rx_mini_pending = u32;
            break;
        case NM_ETHTOOL_ID_RING_TX:
            ring_new.tx_pending = u32;
            break;
        default:
            nm_assert_not_reached();
        }
    }

    if (!has_old)
        return;

    ethtool_state->ring = nm_memdup(&ring_old, sizeof(ring_old));

    if (!nm_platform_ethtool_set_ring(platform, ethtool_state->ifindex, &ring_new)) {
        _LOGW(LOGD_DEVICE, "ethtool: failure setting ring settings");
        return;
    }

    _LOGD(LOGD_DEVICE, "ethtool: ring settings successfully set");
}

static void
_ethtool_pause_reset(NMDevice *self, NMPlatform *platform, EthtoolState *ethtool_state)
{
    gs_free NMEthtoolPauseState *pause = NULL;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(NM_IS_PLATFORM(platform));
    nm_assert(ethtool_state);

    pause = g_steal_pointer(&ethtool_state->pause);
    if (!pause)
        return;

    if (!nm_platform_ethtool_set_pause(platform, ethtool_state->ifindex, pause))
        _LOGW(LOGD_DEVICE, "ethtool: failure resetting one or more pause settings");
    else
        _LOGD(LOGD_DEVICE, "ethtool: pause settings successfully reset");
}

static void
_ethtool_pause_set(NMDevice         *self,
                   NMPlatform       *platform,
                   EthtoolState     *ethtool_state,
                   NMSettingEthtool *s_ethtool)
{
    NMEthtoolPauseState pause_old;
    NMEthtoolPauseState pause_new;
    GHashTable         *hash;
    GHashTableIter      iter;
    const char         *name;
    GVariant           *variant;
    gboolean            has_old       = FALSE;
    NMTernary           pause_autoneg = NM_TERNARY_DEFAULT;
    NMTernary           pause_rx      = NM_TERNARY_DEFAULT;
    NMTernary           pause_tx      = NM_TERNARY_DEFAULT;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(NM_IS_PLATFORM(platform));
    nm_assert(NM_IS_SETTING_ETHTOOL(s_ethtool));
    nm_assert(ethtool_state);
    nm_assert(!ethtool_state->pause);

    hash = _nm_setting_option_hash(NM_SETTING(s_ethtool), FALSE);
    if (!hash)
        return;

    g_hash_table_iter_init(&iter, hash);
    while (g_hash_table_iter_next(&iter, (gpointer *) &name, (gpointer *) &variant)) {
        NMEthtoolID ethtool_id = nm_ethtool_id_get_by_name(name);

        if (!nm_ethtool_id_is_pause(ethtool_id))
            continue;

        nm_assert(g_variant_is_of_type(variant, G_VARIANT_TYPE_BOOLEAN));

        if (!has_old) {
            if (!nm_platform_ethtool_get_link_pause(platform, ethtool_state->ifindex, &pause_old)) {
                _LOGW(LOGD_DEVICE,
                      "ethtool: failure setting pause options (cannot read "
                      "existing setting)");
                return;
            }
            has_old = TRUE;
        }

        switch (ethtool_id) {
        case NM_ETHTOOL_ID_PAUSE_AUTONEG:
            pause_autoneg = g_variant_get_boolean(variant);
            break;
        case NM_ETHTOOL_ID_PAUSE_RX:
            pause_rx = g_variant_get_boolean(variant);
            break;
        case NM_ETHTOOL_ID_PAUSE_TX:
            pause_tx = g_variant_get_boolean(variant);
            break;
        default:
            nm_assert_not_reached();
        }
    }

    if (!has_old)
        return;

    if (pause_rx != NM_TERNARY_DEFAULT || pause_tx != NM_TERNARY_DEFAULT) {
        /* this implies to explicitly disable autoneg. */
        nm_assert(pause_autoneg != NM_TERNARY_TRUE);
        pause_autoneg = NM_TERNARY_FALSE;
    }

    pause_new = pause_old;
    if (pause_autoneg != NM_TERNARY_DEFAULT)
        pause_new.autoneg = !!pause_autoneg;
    if (pause_rx != NM_TERNARY_DEFAULT)
        pause_new.rx = !!pause_rx;
    if (pause_tx != NM_TERNARY_DEFAULT)
        pause_new.tx = !!pause_tx;

    ethtool_state->pause = nm_memdup(&pause_old, sizeof(pause_old));

    if (!nm_platform_ethtool_set_pause(platform, ethtool_state->ifindex, &pause_new)) {
        _LOGW(LOGD_DEVICE, "ethtool: failure setting pause settings");
        return;
    }

    _LOGD(LOGD_DEVICE, "ethtool: pause settings successfully set");
}

static void
_ethtool_state_reset(NMDevice *self)
{
    NMPlatform           *platform      = nm_device_get_platform(self);
    NMDevicePrivate      *priv          = NM_DEVICE_GET_PRIVATE(self);
    gs_free EthtoolState *ethtool_state = g_steal_pointer(&priv->ethtool_state);

    if (!ethtool_state)
        return;

    if (ethtool_state->features)
        _ethtool_features_reset(self, platform, ethtool_state);
    if (ethtool_state->coalesce)
        _ethtool_coalesce_reset(self, platform, ethtool_state);
    if (ethtool_state->ring)
        _ethtool_ring_reset(self, platform, ethtool_state);
    if (ethtool_state->pause)
        _ethtool_pause_reset(self, platform, ethtool_state);
}

static void
_ethtool_state_set(NMDevice *self)
{
    int                   ifindex;
    NMPlatform           *platform;
    NMConnection         *connection;
    NMSettingEthtool     *s_ethtool;
    gs_free EthtoolState *ethtool_state = NULL;
    NMDevicePrivate      *priv          = NM_DEVICE_GET_PRIVATE(self);

    ifindex = nm_device_get_ip_ifindex(self);
    if (ifindex <= 0)
        return;

    platform = nm_device_get_platform(self);
    nm_assert(platform);

    connection = nm_device_get_applied_connection(self);
    if (!connection)
        return;

    s_ethtool = NM_SETTING_ETHTOOL(nm_connection_get_setting(connection, NM_TYPE_SETTING_ETHTOOL));
    if (!s_ethtool)
        return;

    ethtool_state          = g_new0(EthtoolState, 1);
    ethtool_state->ifindex = ifindex;

    _ethtool_features_set(self, platform, ethtool_state, s_ethtool);
    _ethtool_coalesce_set(self, platform, ethtool_state, s_ethtool);
    _ethtool_ring_set(self, platform, ethtool_state, s_ethtool);
    _ethtool_pause_set(self, platform, ethtool_state, s_ethtool);

    if (ethtool_state->features || ethtool_state->coalesce || ethtool_state->ring
        || ethtool_state->pause)
        priv->ethtool_state = g_steal_pointer(&ethtool_state);
}

static NMPlatformLinkChangeFlags
link_properties_fill_from_setting(NMDevice *self, NMPlatformLinkProps *props)
{
    NMPlatformLinkChangeFlags flags = NM_PLATFORM_LINK_CHANGE_NONE;
    NMSettingLink            *s_link;
    gint64                    v;

    *props = (NMPlatformLinkProps){};

    s_link = nm_device_get_applied_setting(self, NM_TYPE_SETTING_LINK);
    if (!s_link)
        return 0;

    v = nm_setting_link_get_tx_queue_length(s_link);
    if (v != -1) {
        props->tx_queue_length = (guint32) v;
        flags |= NM_PLATFORM_LINK_CHANGE_TX_QUEUE_LENGTH;
    }

    v = nm_setting_link_get_gso_max_size(s_link);
    if (v != -1) {
        props->gso_max_size = (guint32) v;
        flags |= NM_PLATFORM_LINK_CHANGE_GSO_MAX_SIZE;
    }

    v = nm_setting_link_get_gso_max_segments(s_link);
    if (v != -1) {
        props->gso_max_segments = (guint32) v;
        flags |= NM_PLATFORM_LINK_CHANGE_GSO_MAX_SEGMENTS;
    }

    v = nm_setting_link_get_gro_max_size(s_link);
    if (v != -1) {
        props->gro_max_size = (guint32) v;
        flags |= NM_PLATFORM_LINK_CHANGE_GRO_MAX_SIZE;
    }

    return flags;
}

void
nm_device_link_properties_set(NMDevice *self, gboolean reapply)
{
    NMDevicePrivate          *priv = NM_DEVICE_GET_PRIVATE(self);
    NMPlatformLinkProps       props;
    NMPlatformLinkChangeFlags flags;
    NMPlatform               *platform;
    const NMPlatformLink     *plink;
    int                       ifindex;

    ifindex = nm_device_get_ip_ifindex(self);
    if (ifindex <= 0)
        return;

    if (priv->link_props_set && !reapply)
        return;

    priv->link_props_set = TRUE;

    flags = link_properties_fill_from_setting(self, &props);

    if (flags == NM_PLATFORM_LINK_CHANGE_NONE
        && priv->link_props_state.flags == NM_PLATFORM_LINK_CHANGE_NONE) {
        /* Nothing to set now, and nothing was set previously. */
        return;
    }

    platform = nm_device_get_platform(self);

    if (priv->link_props_state.flags == NM_PLATFORM_LINK_CHANGE_NONE) {
        /* It's the first time we reach here. Try to fetch the current
         * link settings (reset them later). */
        plink = nm_platform_link_get(platform, ifindex);
        if (plink) {
            priv->link_props_state.props = plink->link_props;
            priv->link_props_state.flags = flags;
        } else {
            /* Unknown properties. The "priv->link_props_state.flags" stays unset.
             * It indicates that "priv->link_props_state.props" is unknown. */
        }

    } else {
        /* From a previous call we have some "priv->link_props_state.flags"
         * flags, which indicates that all link props are cached. Also add
         * "flags" which are are going to set, to indicate that those flags
         * will need to be reset later. */
        priv->link_props_state.flags |= flags;
    }

#define _RESET(_f, _field)                                                                \
    if (!NM_FLAGS_HAS(flags, (_f)) && NM_FLAGS_HAS(priv->link_props_state.flags, (_f))) { \
        props._field = priv->link_props_state.props._field;                               \
        priv->link_props_state.flags &= ~(_f);                                            \
        flags |= (_f);                                                                    \
    }

    /* During reapply, if we previously set some "priv->link_props_state.flags"
     * but now not anymore (according to "flags"), then we reset the value now.
     *
     * We do this by copying the props field from "priv->link_props_state" to
     * "props", reset the flag in "priv->link_props_state.flags" and set the
     * flag in "flags" (for changing it). */
    _RESET(NM_PLATFORM_LINK_CHANGE_TX_QUEUE_LENGTH, tx_queue_length);
    _RESET(NM_PLATFORM_LINK_CHANGE_GSO_MAX_SIZE, gso_max_size);
    _RESET(NM_PLATFORM_LINK_CHANGE_GSO_MAX_SEGMENTS, gso_max_segments);
    _RESET(NM_PLATFORM_LINK_CHANGE_GRO_MAX_SIZE, gro_max_size);

    if (nm_platform_link_change(platform, ifindex, &props, NULL, flags)) {
        _LOGD(LOGD_DEVICE, "link properties successfully set");
    } else {
        _LOGW(LOGD_DEVICE, "failure setting link properties");
    }
}

static void
link_properties_reset(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    NMPlatform      *platform;
    int              ifindex;

    if (priv->link_props_state.flags == 0)
        goto out;

    ifindex = nm_device_get_ip_ifindex(self);
    if (ifindex <= 0)
        goto out;

    platform = nm_device_get_platform(self);
    nm_assert(platform);

    if (nm_platform_link_change(platform,
                                ifindex,
                                &priv->link_props_state.props,
                                NULL,
                                priv->link_props_state.flags)) {
        _LOGD(LOGD_DEVICE, "link properties successfully reset");
    } else {
        _LOGW(LOGD_DEVICE, "failure resetting link properties");
    }

out:
    priv->link_props_set         = FALSE;
    priv->link_props_state.flags = 0;
}

/*****************************************************************************/

gboolean
nm_device_is_vpn(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    /* NetworkManager currently treats VPN connections (loaded from NetworkManager VPN plugins)
     * differently. Those are considered VPNs.
     * However, some native device types may also be considered VPNs...
     *
     * We should avoid distinguishing between is-vpn and "regular" devices. Is an (unencrypted)
     * IP tunnel a VPN? Is MACSec on top of an IP tunnel a VPN?
     * Sometimes we differentiate, but avoid unless reasonable. */

    return NM_IS_DEVICE_WIREGUARD(self);
}

NMSettings *
nm_device_get_settings(NMDevice *self)
{
    return NM_DEVICE_GET_PRIVATE(self)->settings;
}

NMManager *
nm_device_get_manager(NMDevice *self)
{
    return NM_DEVICE_GET_PRIVATE(self)->manager;
}

NMNetns *
nm_device_get_netns(NMDevice *self)
{
    return NM_DEVICE_GET_PRIVATE(self)->netns;
}

NMDedupMultiIndex *
nm_device_get_multi_index(NMDevice *self)
{
    return nm_netns_get_multi_idx(nm_device_get_netns(self));
}

NMPlatform *
nm_device_get_platform(NMDevice *self)
{
    return nm_netns_get_platform(nm_device_get_netns(self));
}

static NMConnectivity *
concheck_get_mgr(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (G_UNLIKELY(!priv->concheck_mgr))
        priv->concheck_mgr = g_object_ref(nm_connectivity_get());
    return priv->concheck_mgr;
}

NML3ConfigData *
nm_device_create_l3_config_data(NMDevice *self, NMIPConfigSource source)
{
    int ifindex;

    nm_assert(NM_IS_DEVICE(self));

    ifindex = nm_device_get_ip_ifindex(self);
    if (ifindex <= 0)
        g_return_val_if_reached(NULL);

    return nm_l3_config_data_new(nm_device_get_multi_index(self), ifindex, source);
}

const NML3ConfigData *
nm_device_create_l3_config_data_from_connection(NMDevice *self, NMConnection *connection)
{
    NML3ConfigData *l3cd;
    int             ifindex;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(!connection || NM_IS_CONNECTION(connection));

    if (!connection)
        return NULL;

    ifindex = nm_device_get_ip_ifindex(self);
    if (ifindex <= 0)
        g_return_val_if_reached(NULL);

    l3cd =
        nm_l3_config_data_new_from_connection(nm_device_get_multi_index(self), ifindex, connection);
    nm_l3_config_data_set_mdns(l3cd, _prop_get_connection_mdns(self));
    nm_l3_config_data_set_llmnr(l3cd, _prop_get_connection_llmnr(self));
    nm_l3_config_data_set_dns_over_tls(l3cd, _prop_get_connection_dns_over_tls(self));
    nm_l3_config_data_set_ip6_privacy(l3cd, _prop_get_ipv6_ip6_privacy(self));
    nm_l3_config_data_set_mptcp_flags(l3cd, _prop_get_connection_mptcp_flags(self));
    return l3cd;
}

/*****************************************************************************/

NMDeviceSysIfaceState
nm_device_sys_iface_state_get(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), NM_DEVICE_SYS_IFACE_STATE_EXTERNAL);

    return NM_DEVICE_GET_PRIVATE(self)->sys_iface_state;
}

gboolean
nm_device_sys_iface_state_is_external(NMDevice *self)
{
    return NM_IN_SET(nm_device_sys_iface_state_get(self), NM_DEVICE_SYS_IFACE_STATE_EXTERNAL);
}

gboolean
nm_device_sys_iface_state_is_external_or_assume(NMDevice *self)
{
    return NM_IN_SET(nm_device_sys_iface_state_get(self),
                     NM_DEVICE_SYS_IFACE_STATE_EXTERNAL,
                     NM_DEVICE_SYS_IFACE_STATE_ASSUME);
}

void
nm_device_sys_iface_state_set(NMDevice *self, NMDeviceSysIfaceState sys_iface_state)
{
    NMDevicePrivate *priv;

    g_return_if_fail(NM_IS_DEVICE(self));
    g_return_if_fail(NM_IN_SET(sys_iface_state,
                               NM_DEVICE_SYS_IFACE_STATE_EXTERNAL,
                               NM_DEVICE_SYS_IFACE_STATE_ASSUME,
                               NM_DEVICE_SYS_IFACE_STATE_MANAGED,
                               NM_DEVICE_SYS_IFACE_STATE_REMOVED));

    priv = NM_DEVICE_GET_PRIVATE(self);
    if (priv->sys_iface_state != sys_iface_state) {
        _LOGT(LOGD_DEVICE,
              "sys-iface-state: %s -> %s",
              nm_device_sys_iface_state_to_string(priv->sys_iface_state),
              nm_device_sys_iface_state_to_string(sys_iface_state));
        priv->sys_iface_state_ = sys_iface_state;
        _dev_l3_cfg_commit_type_reset(self);
        nm_device_l3cfg_commit(self, NM_L3_CFG_COMMIT_TYPE_AUTO, FALSE);
    }

    /* this function only sets a flag, no immediate actions are initiated.
     *
     * If you change this, make sure that all callers are fine with such actions. */

    nm_assert(priv->sys_iface_state == sys_iface_state);
}

void
nm_device_notify_sleeping(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    priv->sys_iface_state_before_sleep = priv->sys_iface_state;
}

NMDeviceSysIfaceState
nm_device_get_sys_iface_state_before_sleep(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    return priv->sys_iface_state_before_sleep;
}

static void
_active_connection_set_state_flags_full(NMDevice              *self,
                                        NMActivationStateFlags flags,
                                        NMActivationStateFlags mask)
{
    NMActiveConnection *ac;

    ac = NM_ACTIVE_CONNECTION(nm_device_get_act_request(self));
    if (ac)
        nm_active_connection_set_state_flags_full(ac, flags, mask);
}

static void
_active_connection_set_state_flags(NMDevice *self, NMActivationStateFlags flags)
{
    _active_connection_set_state_flags_full(self, flags, flags);
}

/*****************************************************************************/

static gboolean
set_interface_flags_full(NMDevice              *self,
                         NMDeviceInterfaceFlags mask,
                         NMDeviceInterfaceFlags interface_flags,
                         gboolean               notify)
{
    NMDevicePrivate       *priv = NM_DEVICE_GET_PRIVATE(self);
    NMDeviceInterfaceFlags f;

    nm_assert(!!mask);
    nm_assert(!NM_FLAGS_ANY(mask, ~_NM_DEVICE_INTERFACE_FLAG_ALL));
    nm_assert(!NM_FLAGS_ANY(interface_flags, ~mask));

    f = (priv->interface_flags & ~mask) | (interface_flags & mask);

    if (f == priv->interface_flags)
        return FALSE;

    priv->interface_flags = f;
    if (notify)
        _notify(self, PROP_INTERFACE_FLAGS);
    return TRUE;
}

static gboolean
set_interface_flags(NMDevice              *self,
                    NMDeviceInterfaceFlags interface_flags,
                    gboolean               set,
                    gboolean               notify)
{
    return set_interface_flags_full(self,
                                    interface_flags,
                                    set ? interface_flags : NM_DEVICE_INTERFACE_FLAG_NONE,
                                    notify);
}

void
nm_device_assume_state_get(NMDevice    *self,
                           gboolean    *out_assume_state_guess_assume,
                           const char **out_assume_state_connection_uuid)
{
    NMDevicePrivate *priv;

    g_return_if_fail(NM_IS_DEVICE(self));

    priv = NM_DEVICE_GET_PRIVATE(self);
    NM_SET_OUT(out_assume_state_guess_assume, priv->assume_state_guess_assume);
    NM_SET_OUT(out_assume_state_connection_uuid, priv->assume_state_connection_uuid);
}

static void
_assume_state_set(NMDevice   *self,
                  gboolean    assume_state_guess_assume,
                  const char *assume_state_connection_uuid)
{
    NMDevicePrivate *priv;

    nm_assert(NM_IS_DEVICE(self));

    priv = NM_DEVICE_GET_PRIVATE(self);
    if (priv->assume_state_guess_assume == !!assume_state_guess_assume
        && nm_streq0(priv->assume_state_connection_uuid, assume_state_connection_uuid))
        return;

    _LOGD(LOGD_DEVICE,
          "assume-state: set guess-assume=%c, connection=%s%s%s",
          assume_state_guess_assume ? '1' : '0',
          NM_PRINT_FMT_QUOTE_STRING(assume_state_connection_uuid));
    priv->assume_state_guess_assume = assume_state_guess_assume;
    g_free(priv->assume_state_connection_uuid);
    priv->assume_state_connection_uuid = g_strdup(assume_state_connection_uuid);
}

void
nm_device_assume_state_reset(NMDevice *self)
{
    g_return_if_fail(NM_IS_DEVICE(self));

    _assume_state_set(self, FALSE, NULL);
}

/*****************************************************************************/

static char *
nm_device_sysctl_ip_conf_get(NMDevice *self, int addr_family, const char *property)
{
    const char *ifname;

    nm_assert_addr_family(addr_family);

    ifname = nm_device_get_ip_iface_from_platform(self);
    if (!ifname)
        return NULL;
    return nm_platform_sysctl_ip_conf_get(nm_device_get_platform(self),
                                          addr_family,
                                          ifname,
                                          property);
}

static gint64
nm_device_sysctl_ip_conf_get_int_checked(NMDevice   *self,
                                         int         addr_family,
                                         const char *property,
                                         guint       base,
                                         gint64      min,
                                         gint64      max,
                                         gint64      fallback)
{
    const char *ifname;

    nm_assert_addr_family(addr_family);

    ifname = nm_device_get_ip_iface_from_platform(self);
    if (!ifname) {
        errno = EINVAL;
        return fallback;
    }
    return nm_platform_sysctl_ip_conf_get_int_checked(nm_device_get_platform(self),
                                                      addr_family,
                                                      ifname,
                                                      property,
                                                      base,
                                                      min,
                                                      max,
                                                      fallback);
}

gboolean
nm_device_sysctl_ip_conf_set(NMDevice   *self,
                             int         addr_family,
                             const char *property,
                             const char *value)
{
    NMPlatform   *platform      = nm_device_get_platform(self);
    gs_free char *value_to_free = NULL;
    const char   *ifname;

    nm_assert_addr_family(addr_family);

    ifname = nm_device_get_ip_iface_from_platform(self);
    if (!ifname)
        return FALSE;

    if (!value) {
        /* Set to a default value when we've got a NULL @value. */
        value_to_free = nm_platform_sysctl_ip_conf_get(platform, addr_family, "default", property);
        value         = value_to_free;
        if (!value)
            return FALSE;
    }

    return nm_platform_sysctl_ip_conf_set(platform, addr_family, ifname, property, value);
}

/*****************************************************************************/

gboolean
nm_device_has_capability(NMDevice *self, NMDeviceCapabilities caps)
{
    return NM_FLAGS_ANY(NM_DEVICE_GET_PRIVATE(self)->capabilities, caps);
}

static void
_add_capabilities(NMDevice *self, NMDeviceCapabilities capabilities)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (!NM_FLAGS_ALL(priv->capabilities, capabilities)) {
        priv->capabilities |= capabilities;
        _notify(self, PROP_CAPABILITIES);
    }
}

/*****************************************************************************/

static void
_dev_ip_state_dnsmgr_update_pending_changed(NMDnsManager *dnsmgr, GParamSpec *pspec, NMDevice *self)
{
    _dev_ip_state_check(self, AF_INET);
    _dev_ip_state_check(self, AF_INET6);
}

static void
_dev_ip_state_req_timeout_cancel(NMDevice *self, int addr_family)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (addr_family == AF_UNSPEC) {
        _dev_ip_state_req_timeout_cancel(self, AF_INET);
        _dev_ip_state_req_timeout_cancel(self, AF_INET6);
        return;
    }

    if (nm_clear_g_source_inst(&priv->ip_data_x[NM_IS_IPv4(addr_family)].req_timeout_source))
        _LOGD_ip(addr_family, "required-timeout: cancelled");
}

static gboolean
_dev_ip_state_req_timeout_cb_x(NMDevice *self, int addr_family)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    _LOGD_ip(addr_family, "required-timeout: expired");
    nm_clear_g_source_inst(&priv->ip_data_x[NM_IS_IPv4(addr_family)].req_timeout_source);
    _dev_ip_state_check(self, nm_utils_addr_family_other(addr_family));
    return G_SOURCE_CONTINUE;
}

static gboolean
_dev_ip_state_req_timeout_cb_4(gpointer user_data)
{
    return _dev_ip_state_req_timeout_cb_x(user_data, AF_INET);
}

static gboolean
_dev_ip_state_req_timeout_cb_6(gpointer user_data)
{
    return _dev_ip_state_req_timeout_cb_x(user_data, AF_INET6);
}

static void
_dev_ip_state_req_timeout_schedule(NMDevice *self, int addr_family)
{
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);
    guint32          timeout_msec;
    char             buf[32];

    nm_assert(!priv->ip_data_x[IS_IPv4].req_timeout_source);

    timeout_msec = _prop_get_ipvx_required_timeout(self, addr_family);
    if (timeout_msec == 0) {
        _LOGD_ip(addr_family, "required-timeout: disabled");
        return;
    }

    _LOGD_ip(addr_family,
             "required-timeout: started (%s msec)",
             timeout_msec == G_MAXINT32 ? "∞" : nm_sprintf_buf(buf, "%u", timeout_msec));

    if (timeout_msec == G_MAXINT32) {
        priv->ip_data_x[IS_IPv4].req_timeout_source = g_source_ref(nm_g_source_sentinel_get(0));
    } else {
        priv->ip_data_x[IS_IPv4].req_timeout_source = nm_g_timeout_add_source(
            timeout_msec,
            IS_IPv4 ? _dev_ip_state_req_timeout_cb_4 : _dev_ip_state_req_timeout_cb_6,
            self);
    }
}

static gboolean
_dev_ip_state_set_state(NMDevice       *self,
                        int             addr_family,
                        NMDeviceIPState ip_state,
                        const char     *reason)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    int              IS_IPv4;

    if (addr_family == AF_UNSPEC) {
        if (priv->ip_data.state == ip_state)
            return FALSE;
        _LOGD_ip(addr_family,
                 "set (combined) state %s (was %s, reason: %s)",
                 nm_device_ip_state_to_string(ip_state),
                 nm_device_ip_state_to_string(priv->ip_data.state),
                 reason);
        priv->ip_data.state_ = ip_state;
        return TRUE;
    }

    IS_IPv4 = NM_IS_IPv4(addr_family);

    if (priv->ip_data_x[IS_IPv4].state_ == ip_state)
        return FALSE;

    _LOGD_ip(addr_family,
             "set state %s (was %s, reason: %s)",
             nm_device_ip_state_to_string(ip_state),
             nm_device_ip_state_to_string(priv->ip_data_x[IS_IPv4].state),
             reason);
    priv->ip_data_x[IS_IPv4].state_ = ip_state;
    return TRUE;
}

static void
_device_ip_state_accumulate(NMDeviceIPState state,
                            gboolean       *out_is_started,
                            gboolean       *out_is_pending,
                            gboolean       *out_is_failed)
{
    switch (state) {
    case NM_DEVICE_IP_STATE_NONE:
        return;
    case NM_DEVICE_IP_STATE_PENDING:
        *out_is_started = TRUE;
        *out_is_pending = TRUE;
        return;
    case NM_DEVICE_IP_STATE_READY:
        *out_is_started = TRUE;
        return;
    case NM_DEVICE_IP_STATE_FAILED:
        *out_is_started = TRUE;
        *out_is_failed  = TRUE;
        return;
    }
    nm_assert_not_reached();
    return;
}

static void
_dev_ip_state_check(NMDevice *self, int addr_family)
{
    NMDevicePrivate *priv         = NM_DEVICE_GET_PRIVATE(self);
    const int        IS_IPv4      = NM_IS_IPv4(addr_family);
    gboolean         s_is_started = FALSE;
    gboolean         s_is_failed  = FALSE;
    gboolean         s_is_pending = FALSE;
    gboolean         has_tna      = FALSE;
    gboolean         v_bool;
    NMDeviceIPState  ip_state;
    NMDeviceIPState  ip_state_other;
    NMDeviceIPState  combinedip_state;
    NMTernary        may_fail                 = NM_TERNARY_DEFAULT;
    NMTernary        may_fail_other           = NM_TERNARY_DEFAULT;
    gboolean         disabled_or_ignore       = FALSE;
    gboolean         disabled_or_ignore_other = FALSE;

    if (priv->ip_data_x[IS_IPv4].is_disabled || priv->ip_data_x[IS_IPv4].is_ignore)
        disabled_or_ignore = TRUE;
    if (priv->ip_data_x[!IS_IPv4].is_disabled || priv->ip_data_x[!IS_IPv4].is_ignore)
        disabled_or_ignore_other = TRUE;

    /* State handling in NMDevice:
     *
     * NMDevice manages a lot of state, that is for the various IP addressing methods, the state
     * of the interface (controller/port), and a overall nm_device_get_state().
     *
     * The idea is to compartmentalize these states into smaller units, and combine them as appropriate.
     *
     * For example, NMDhcpClient already provides an API that hides most of the complexity. But it still
     * needs to expose some state, like whether we are still trying to get a lease (PENDING), whether there
     * was a critical failure (FAILED) or we have a lease (READY). This state is grouped in NMDevice
     * under priv->ipdhcp_data_x. Most important is priv->ipdhcp_data_x[].state, which distills all of this
     * into 4 values of type NMDeviceIPState. This state is cached, so whenever something changes (e.g.
     * an event from NMDhcpClient), we determine the new state and compare it with what is cached. If
     * the cached state is as the new state, we are done. Otherwise, the change gets escalated (which
     * means to call _dev_ip_state_check_async()).
     *
     * Then, the various sub-states escalate their changes to this function (_dev_ip_state_check). This
     * function first takes the sub-states related to one IP address family, and combines them into
     * priv->ip_data_x[] (and in particular priv->ip_data_x[].state). The same repeats. The current
     * state is cached in priv->ip_data_x[].state, and _dev_ip_state_check() determines the new state.
     * If there is no change, it ends here. Otherwise, it gets escalated. In this case, the escaplation
     * happens in _dev_ip_state_check() below by combining the combined per-address-family into
     * priv->ip_data. In particular this step needs to take into account settings like "may-fail"
     * and "required-timeout".
     *
     * The escalation and compartmentalization priv->ip_data repeats. This time it escalates
     * to the overall device state (nm_device_state_changed() and nm_device_get_state()), which then
     * triggers larger state changes (e.g. the activation might fail).
     */

    if (priv->l3cfg && nm_l3cfg_commit_on_idle_is_scheduled(priv->l3cfg)) {
        /* we have an update on NML3Cfg scheduled. We first process that, before
         * progressing the IP state. When that's done, we will be called again. */
        _dev_ip_state_check_async(self, addr_family);
        return;
    }

    if (priv->ip_data_x[IS_IPv4].state == NM_DEVICE_IP_STATE_NONE) {
        ip_state = NM_DEVICE_IP_STATE_NONE;
        goto got_ip_state;
    }

    if (nm_device_sys_iface_state_is_external(self)) {
        ip_state = NM_DEVICE_IP_STATE_READY;
        goto got_ip_state;
    }

    if (priv->ip_data_x[IS_IPv4].state == NM_DEVICE_IP_STATE_PENDING
        && (priv->state < NM_DEVICE_STATE_IP_CONFIG || priv->state > NM_DEVICE_STATE_ACTIVATED)) {
        /* we can only leave pending state, if we are between (including) IP_CONFIG and ACTIVATED states. */
        ip_state = NM_DEVICE_IP_STATE_PENDING;
        goto got_ip_state;
    }

    if (priv->ip_data_x[IS_IPv4].state == NM_DEVICE_IP_STATE_PENDING
        && nm_active_connection_get_master(NM_ACTIVE_CONNECTION(priv->act_request.obj))
        && !priv->is_enslaved) {
        /* Don't progress into IP_CHECK or SECONDARIES if we're waiting for the
         * master to enslave us. */
        ip_state = NM_DEVICE_IP_STATE_PENDING;
        goto got_ip_state;
    }

    if (priv->ip_data_x[IS_IPv4].wait_for_carrier || priv->ip_data_x[IS_IPv4].wait_for_ports) {
        ip_state = NM_DEVICE_IP_STATE_PENDING;
        goto got_ip_state;
    }

    if (disabled_or_ignore) {
        ip_state = NM_DEVICE_IP_STATE_READY;
        goto got_ip_state;
    }

    _device_ip_state_accumulate(priv->ipmanual_data.state_x[IS_IPv4],
                                &s_is_started,
                                &s_is_pending,
                                &s_is_failed);

    _device_ip_state_accumulate(priv->ipll_data_x[IS_IPv4].state,
                                &s_is_started,
                                &s_is_pending,
                                &s_is_failed);

    if (!IS_IPv4) {
        _device_ip_state_accumulate(priv->ipac6_data.state,
                                    &s_is_started,
                                    &s_is_pending,
                                    &s_is_failed);
    }

    v_bool = FALSE;
    _device_ip_state_accumulate(priv->ipdhcp_data_x[IS_IPv4].state,
                                &s_is_started,
                                &s_is_pending,
                                &v_bool);
    if (v_bool) {
        if (!IS_IPv4 && priv->ipdhcp_data_6.v6.mode == NM_NDISC_DHCP_LEVEL_OTHERCONF) {
            /* DHCPv6 is best-effort and not required. */
        } else
            s_is_failed = TRUE;
    }

    _device_ip_state_accumulate(priv->ipshared_data_x[IS_IPv4].state,
                                &s_is_started,
                                &s_is_pending,
                                &s_is_failed);

    _device_ip_state_accumulate(priv->ipdev_data_x[IS_IPv4].state,
                                &s_is_started,
                                &s_is_pending,
                                &s_is_failed);

    _device_ip_state_accumulate(priv->ipdev_data_unspec.state,
                                &s_is_started,
                                &s_is_pending,
                                &s_is_failed);

    has_tna = priv->l3cfg && nm_l3cfg_has_failedobj_pending(priv->l3cfg, addr_family);
    if (has_tna)
        s_is_pending = TRUE;

    if (s_is_failed)
        ip_state = NM_DEVICE_IP_STATE_FAILED;
    else if (s_is_pending)
        ip_state = NM_DEVICE_IP_STATE_PENDING;
    else if (s_is_started)
        ip_state = NM_DEVICE_IP_STATE_READY;
    else
        ip_state = NM_DEVICE_IP_STATE_PENDING;

got_ip_state:

#define _state_str_a(state, name)                                       \
    ({                                                                  \
        const NMDeviceIPState _state = (state);                         \
        char                 *_s     = "";                              \
                                                                        \
        if (_state != NM_DEVICE_IP_STATE_NONE) {                        \
            _s = nm_sprintf_bufa(NM_STRLEN(name) + 11,                  \
                                 " " name "=%s",                        \
                                 nm_device_ip_state_to_string(_state)); \
        }                                                               \
        _s;                                                             \
    })

    nm_assert(!priv->ip_data_4.is_ignore);

    _LOGT_ip(addr_family,
             "check-state: state %s => %s, is_failed=%d, is_pending=%d, is_started=%d temp_na=%d, "
             "may-fail-4=%d, may-fail-6=%d;"
             "%s;%s%s%s%s%s%s;%s%s%s%s%s%s%s%s",
             nm_device_ip_state_to_string(priv->ip_data_x[IS_IPv4].state),
             nm_device_ip_state_to_string(ip_state),
             s_is_failed,
             s_is_pending,
             s_is_started,
             has_tna,
             _prop_get_ipvx_may_fail_cached(self, AF_INET, IS_IPv4 ? &may_fail : &may_fail_other),
             _prop_get_ipvx_may_fail_cached(self, AF_INET6, !IS_IPv4 ? &may_fail : &may_fail_other),
             priv->ip_data_4.is_disabled ? " disabled4" : "",
             _state_str_a(priv->ipmanual_data.state_4, "manualip4"),
             _state_str_a(priv->ipdev_data_unspec.state, "dev"),
             _state_str_a(priv->ipll_data_4.state, "ll4"),
             _state_str_a(priv->ipdhcp_data_4.state, "dhcp4"),
             _state_str_a(priv->ipdev_data_4.state, "dev4"),
             _state_str_a(priv->ipshared_data_4.state, "shared4"),
             priv->ip_data_6.is_disabled ? " disabled6" : "",
             priv->ip_data_6.is_ignore ? " ignore6" : "",
             _state_str_a(priv->ipmanual_data.state_6, "manualip6"),
             _state_str_a(priv->ipll_data_6.state, "ll6"),
             _state_str_a(priv->ipac6_data.state, "ac6"),
             _state_str_a(priv->ipdhcp_data_6.state, "dhcp6"),
             _state_str_a(priv->ipdev_data_6.state, "dev6"),
             _state_str_a(priv->ipshared_data_6.state, "shared6"));

    if (priv->ip_data_x[IS_IPv4].state == ip_state) {
        /* no change. We can stop here. However, we also cancel the pending check, if any,
         * because we just determined that there is no change. */
    } else {
        _dev_ip_state_set_state(self, addr_family, ip_state, "check-ip-state");
    }

    if (ip_state == NM_DEVICE_IP_STATE_NONE) {
        /* Nothing to do. This almost cannot happen, and there is probably nothing
         * to do about this case. */
        goto out_done;
    }

    ip_state_other = priv->ip_data_x[!IS_IPv4].state;

    if (ip_state == NM_DEVICE_IP_STATE_READY) {
        /* we only set NM_ACTIVATION_STATE_FLAG_IP_READY_X() flag once we reach NM_DEVICE_IP_STATE_READY state.
         * We don't ever clear it, even if we later enter NM_DEVICE_IP_STATE_FAILED state.
         *
         * This is not documented/guaranteed behavior, but seems to make sense for now. */
        _active_connection_set_state_flags(self, NM_ACTIVATION_STATE_FLAG_IP_READY_X(IS_IPv4));
    }

    if (ip_state == NM_DEVICE_IP_STATE_READY && ip_state_other == NM_DEVICE_IP_STATE_READY)
        combinedip_state = NM_DEVICE_IP_STATE_READY;
    else if (ip_state == NM_DEVICE_IP_STATE_READY && ip_state_other == NM_DEVICE_IP_STATE_PENDING
             && disabled_or_ignore) {
        /* This IP method is disabled/ignore, but the other family is still pending.
         * Regardless of ipvx.may-fail, this means that we always require the other IP family
         * to get ready too. */
        combinedip_state = NM_DEVICE_IP_STATE_PENDING;
    } else if (ip_state == NM_DEVICE_IP_STATE_READY && ip_state_other == NM_DEVICE_IP_STATE_PENDING
               && (priv->ip_data_x[!IS_IPv4].req_timeout_source
                   || !_prop_get_ipvx_may_fail_cached(self,
                                                      nm_utils_addr_family_other(addr_family),
                                                      &may_fail_other)))
        combinedip_state = NM_DEVICE_IP_STATE_PENDING;
    else if (ip_state == NM_DEVICE_IP_STATE_READY
             && _prop_get_ipvx_may_fail_cached(self,
                                               nm_utils_addr_family_other(addr_family),
                                               &may_fail_other))
        combinedip_state = NM_DEVICE_IP_STATE_READY;
    else if (ip_state == NM_DEVICE_IP_STATE_FAILED
             && !_prop_get_ipvx_may_fail_cached(self, addr_family, &may_fail))
        combinedip_state = NM_DEVICE_IP_STATE_FAILED;
    else if ((ip_state == NM_DEVICE_IP_STATE_FAILED
              || (ip_state == NM_DEVICE_IP_STATE_READY && disabled_or_ignore))
             && (ip_state_other == NM_DEVICE_IP_STATE_FAILED
                 || (ip_state_other == NM_DEVICE_IP_STATE_READY && disabled_or_ignore_other))) {
        /* If both IP states failed, or one failed and the other is disabled
         * then it's a failure. may-fail does not mean that both families may
         * fail, instead it means that at least one family must succeed. */
        if (nm_device_sys_iface_state_is_external_or_assume(self)) {
            _dev_ip_state_set_state(self, AF_INET, NM_DEVICE_IP_STATE_READY, "assumed");
            _dev_ip_state_set_state(self, AF_INET6, NM_DEVICE_IP_STATE_READY, "assumed");
            combinedip_state = NM_DEVICE_IP_STATE_READY;
        } else {
            combinedip_state = NM_DEVICE_IP_STATE_FAILED;
        }
    } else {
        if (priv->ip_data.state == NM_DEVICE_IP_STATE_NONE)
            combinedip_state = NM_DEVICE_IP_STATE_PENDING;
        else
            combinedip_state = priv->ip_data.state;
    }

    if (combinedip_state == NM_DEVICE_IP_STATE_READY
        && priv->ip_data.state <= NM_DEVICE_IP_STATE_PENDING
        && nm_dns_manager_get_update_pending(nm_manager_get_dns_manager(priv->manager))) {
        /* We would be ready, but a DNS update is pending. That prevents us from getting fully ready. */
        if (priv->ip_data.dnsmgr_update_pending_signal_id == 0) {
            priv->ip_data.dnsmgr_update_pending_signal_id =
                g_signal_connect(nm_manager_get_dns_manager(priv->manager),
                                 "notify::" NM_DNS_MANAGER_UPDATE_PENDING,
                                 G_CALLBACK(_dev_ip_state_dnsmgr_update_pending_changed),
                                 self);
            _LOGT_ip(AF_UNSPEC,
                     "check-state: (combined) state: wait for DNS before becoming ready");
        }
        combinedip_state = NM_DEVICE_IP_STATE_PENDING;
    }
    if (combinedip_state != NM_DEVICE_IP_STATE_PENDING
        && priv->ip_data.dnsmgr_update_pending_signal_id != 0) {
        nm_clear_g_signal_handler(nm_manager_get_dns_manager(priv->manager),
                                  &priv->ip_data.dnsmgr_update_pending_signal_id);
    }

    _LOGT_ip(AF_UNSPEC,
             "check-state: (combined) state %s => %s",
             nm_device_ip_state_to_string(priv->ip_data.state),
             nm_device_ip_state_to_string(combinedip_state));

    if (!_dev_ip_state_set_state(self, AF_UNSPEC, combinedip_state, "check-ip-state"))
        goto out_done;

    switch (combinedip_state) {
    case NM_DEVICE_IP_STATE_PENDING:
        break;
    case NM_DEVICE_IP_STATE_READY:
        _dev_ip_state_req_timeout_cancel(self, AF_UNSPEC);
        if (priv->state == NM_DEVICE_STATE_IP_CONFIG) {
            nm_device_state_changed(self, NM_DEVICE_STATE_IP_CHECK, NM_DEVICE_STATE_REASON_NONE);
        }
        break;
    case NM_DEVICE_IP_STATE_FAILED:
        nm_device_state_changed(self,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
        break;
    case NM_DEVICE_IP_STATE_NONE:
    default:
        nm_assert_not_reached();
    }

out_done:
    /* we just checked the state. We can cancel the pending async check. */
    nm_clear_g_source_inst(&priv->ip_data_x[IS_IPv4].check_async_source);
}

static gboolean
_dev_ip_state_check_async_cb(NMDevice *self, int addr_family)
{
    _dev_ip_state_check(self, addr_family);
    return G_SOURCE_CONTINUE;
}

static gboolean
_dev_ip_state_check_async_cb_4(gpointer user_data)
{
    return _dev_ip_state_check_async_cb(user_data, AF_INET);
}

static gboolean
_dev_ip_state_check_async_cb_6(gpointer user_data)
{
    return _dev_ip_state_check_async_cb(user_data, AF_INET6);
}

static void
_dev_ip_state_check_async(NMDevice *self, int addr_family)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    int              IS_IPv4;

    if (addr_family == AF_UNSPEC) {
        _dev_ip_state_check_async(self, AF_INET);
        _dev_ip_state_check_async(self, AF_INET6);
        return;
    }

    IS_IPv4 = NM_IS_IPv4(addr_family);
    if (!priv->ip_data_x[IS_IPv4].check_async_source) {
        priv->ip_data_x[IS_IPv4].check_async_source = nm_g_idle_add_source(
            (IS_IPv4 ? _dev_ip_state_check_async_cb_4 : _dev_ip_state_check_async_cb_6),
            self);
    }
}

static void
_dev_ip_state_cleanup(NMDevice *self, int addr_family, gboolean keep_reapply)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    int              IS_IPv4;

    if (addr_family == AF_UNSPEC) {
        _dev_ip_state_set_state(self,
                                addr_family,
                                keep_reapply ? NM_DEVICE_IP_STATE_PENDING : NM_DEVICE_IP_STATE_NONE,
                                "ip-state-clear");
        return;
    }

    IS_IPv4 = NM_IS_IPv4(addr_family);

    nm_clear_g_source_inst(&priv->ip_data_x[IS_IPv4].check_async_source);
    nm_clear_g_source_inst(&priv->ip_data_x[IS_IPv4].req_timeout_source);
    _dev_ip_state_set_state(self,
                            addr_family,
                            keep_reapply ? NM_DEVICE_IP_STATE_PENDING : NM_DEVICE_IP_STATE_NONE,
                            "ip-state-clear");
    priv->ip_data_x[IS_IPv4].wait_for_carrier = FALSE;
    priv->ip_data_x[IS_IPv4].wait_for_ports   = FALSE;
    priv->ip_data_x[IS_IPv4].is_disabled      = FALSE;
    priv->ip_data_x[IS_IPv4].is_ignore        = FALSE;
    priv->ip_data_x[IS_IPv4].do_reapply       = FALSE;
}

/*****************************************************************************/

static gpointer
_dev_l3_config_data_tag_get(NMDevicePrivate *priv, L3ConfigDataType l3cd_type)
{
    nm_assert(_NM_INT_NOT_NEGATIVE(l3cd_type) && l3cd_type < G_N_ELEMENTS(priv->l3cds));

    return &priv->l3cds[l3cd_type];
}

static L3ConfigDataType
_dev_l3_config_data_tag_to_type(NMDevice *self, gconstpointer tag)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    int              d;

    /* In C it is undefined behavior to compare unrelated pointers.
     * Work around that by using nm_ptr_to_uintptr(), which casts the pointers
     * to integers.
     *
     * I guess, theoretically it's still a problem to assume that if tag pointers
     * somewhere inside priv->l3cds, that the uintptr_t case would also yield
     * a value in that range. In practice, I couldn't imaging this not not work
     * reliably. */

    if (nm_ptr_to_uintptr(tag) < nm_ptr_to_uintptr(&priv->l3cds[0])
        || nm_ptr_to_uintptr(tag) >= nm_ptr_to_uintptr(&priv->l3cds[G_N_ELEMENTS(priv->l3cds)]))
        return _L3_CONFIG_DATA_TYPE_NONE;

    d = ((typeof(priv->l3cds[0]) *) tag) - (&priv->l3cds[0]);

    nm_assert(d >= 0);
    nm_assert(d < _L3_CONFIG_DATA_TYPE_NUM);
    nm_assert(tag == &priv->l3cds[d]);
    nm_assert(tag == _dev_l3_config_data_tag_get(priv, d));
    return d;
}

static L3ConfigDataType
_dev_l3_config_data_acd_addr_info_to_type(NMDevice              *self,
                                          const NML3AcdAddrInfo *addr_info,
                                          guint                  i_track_infos)
{
    nm_assert(NM_IS_DEVICE(self));
    nm_assert(addr_info);
    nm_assert(i_track_infos < addr_info->n_track_infos);

    return _dev_l3_config_data_tag_to_type(self, addr_info->track_infos[i_track_infos].tag);
}

// FIXME(l3cfg): unused function??
_nm_unused static const NML3AcdAddrTrackInfo *
_dev_l3_config_data_acd_addr_info_has_by_type(NMDevice              *self,
                                              const NML3AcdAddrInfo *addr_info,
                                              L3ConfigDataType       l3cd_type)
{
    guint i;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(addr_info);
    nm_assert(_NM_INT_NOT_NEGATIVE(l3cd_type) && l3cd_type < _L3_CONFIG_DATA_TYPE_NUM);

    for (i = 0; i < addr_info->n_track_infos; i++) {
        if (l3cd_type == _dev_l3_config_data_acd_addr_info_to_type(self, addr_info, i))
            return &addr_info->track_infos[i];
    }
    return NULL;
}

static void
_dev_l3_get_config_settings(NMDevice             *self,
                            L3ConfigDataType      type,
                            NML3ConfigMergeFlags *out_merge_flags,
                            NML3AcdDefendType    *out_acd_defend_type,
                            guint32              *out_acd_timeout_msec)
{
    NMDevicePrivate     *priv = NM_DEVICE_GET_PRIVATE(self);
    NML3ConfigMergeFlags flags;
    NMConnection        *connection;
    NMSettingIPConfig   *s_ip;

    nm_assert(_NM_INT_NOT_NEGATIVE(type) && type < _L3_CONFIG_DATA_TYPE_NUM);

    if (G_UNLIKELY(!priv->l3config_merge_flags_has)) {
        int IS_IPv4;

        connection = nm_device_get_applied_connection(self);

        for (IS_IPv4 = 0; IS_IPv4 < 2; IS_IPv4++) {
            flags = NM_L3_CONFIG_MERGE_FLAGS_NONE;

            if (connection
                && (s_ip = nm_connection_get_setting_ip_config(connection,
                                                               IS_IPv4 ? AF_INET : AF_INET6))) {
                if (nm_setting_ip_config_get_ignore_auto_routes(s_ip))
                    flags |= NM_L3_CONFIG_MERGE_FLAGS_NO_ROUTES;

                if (nm_setting_ip_config_get_ignore_auto_dns(s_ip))
                    flags |= NM_L3_CONFIG_MERGE_FLAGS_NO_DNS;

                if (nm_setting_ip_config_get_never_default(s_ip)
                    || nm_setting_ip_config_get_gateway(s_ip)) {
                    /* if the connection has an explicit gateway, we also ignore
                     * the default routes from other sources. */
                    flags |= NM_L3_CONFIG_MERGE_FLAGS_NO_DEFAULT_ROUTES;
                }
            }

            priv->l3config_merge_flags_x[IS_IPv4] = flags;
        }
        priv->l3config_merge_flags_has = TRUE;
    }

    switch (type) {
    case L3_CONFIG_DATA_TYPE_DEVIP_UNSPEC:
    case L3_CONFIG_DATA_TYPE_MANUALIP:
    case L3_CONFIG_DATA_TYPE_LL_4:
    case L3_CONFIG_DATA_TYPE_LL_6:
    case L3_CONFIG_DATA_TYPE_PD_6:
    case L3_CONFIG_DATA_TYPE_SHARED_4:
    case L3_CONFIG_DATA_TYPE_DEVIP_4:
    case L3_CONFIG_DATA_TYPE_AC_6:
    case L3_CONFIG_DATA_TYPE_DHCP_6:
    case L3_CONFIG_DATA_TYPE_DEVIP_6:
        *out_acd_timeout_msec = _prop_get_ipv4_dad_timeout(self);
        goto after_acd_timeout;

    case L3_CONFIG_DATA_TYPE_DHCP_4:
        /* For DHCP, we perform ACD separately, because we want to decline the
         * lease in case of a conflict. */
        *out_acd_timeout_msec = 0;
        goto after_acd_timeout;

    case _L3_CONFIG_DATA_TYPE_NUM:
    case _L3_CONFIG_DATA_TYPE_NONE:
    case _L3_CONFIG_DATA_TYPE_ACD_ONLY:
        break;
    }
    *out_acd_timeout_msec = nm_assert_unreachable_val(0);

after_acd_timeout:
    switch (type) {
    case L3_CONFIG_DATA_TYPE_LL_4:
        *out_acd_defend_type = NM_L3_ACD_DEFEND_TYPE_ONCE;
        goto after_acd_defend_type;

    case L3_CONFIG_DATA_TYPE_DEVIP_UNSPEC:
    case L3_CONFIG_DATA_TYPE_MANUALIP:
    case L3_CONFIG_DATA_TYPE_LL_6:
    case L3_CONFIG_DATA_TYPE_PD_6:
    case L3_CONFIG_DATA_TYPE_SHARED_4:
    case L3_CONFIG_DATA_TYPE_DHCP_4:
    case L3_CONFIG_DATA_TYPE_DEVIP_4:
    case L3_CONFIG_DATA_TYPE_AC_6:
    case L3_CONFIG_DATA_TYPE_DHCP_6:
    case L3_CONFIG_DATA_TYPE_DEVIP_6:
        *out_acd_defend_type = NM_L3_ACD_DEFEND_TYPE_ALWAYS;
        goto after_acd_defend_type;

    case _L3_CONFIG_DATA_TYPE_NUM:
    case _L3_CONFIG_DATA_TYPE_NONE:
    case _L3_CONFIG_DATA_TYPE_ACD_ONLY:
        break;
    }
    *out_acd_defend_type = nm_assert_unreachable_val(NM_L3_ACD_DEFEND_TYPE_ALWAYS);

after_acd_defend_type:
    switch (type) {
    case L3_CONFIG_DATA_TYPE_DEVIP_UNSPEC:
    case L3_CONFIG_DATA_TYPE_MANUALIP:
    case L3_CONFIG_DATA_TYPE_LL_4:
    case L3_CONFIG_DATA_TYPE_LL_6:
    case L3_CONFIG_DATA_TYPE_PD_6:
    case L3_CONFIG_DATA_TYPE_SHARED_4:
        *out_merge_flags = NM_L3_CONFIG_MERGE_FLAGS_NONE;
        goto after_merge_flags;

    case L3_CONFIG_DATA_TYPE_DHCP_4:
    case L3_CONFIG_DATA_TYPE_DEVIP_4:
        *out_merge_flags = priv->l3config_merge_flags_4;
        goto after_merge_flags;

    case L3_CONFIG_DATA_TYPE_AC_6:
    case L3_CONFIG_DATA_TYPE_DHCP_6:
    case L3_CONFIG_DATA_TYPE_DEVIP_6:
        *out_merge_flags = priv->l3config_merge_flags_6;
        goto after_merge_flags;

    case _L3_CONFIG_DATA_TYPE_NUM:
    case _L3_CONFIG_DATA_TYPE_NONE:
    case _L3_CONFIG_DATA_TYPE_ACD_ONLY:
        break;
    }
    *out_merge_flags = nm_assert_unreachable_val(NM_L3_CONFIG_MERGE_FLAGS_NONE);

after_merge_flags:
    return;
}

static gboolean
_dev_l3_register_l3cds_add_config(NMDevice *self, L3ConfigDataType l3cd_type)
{
    NMDevicePrivate     *priv = NM_DEVICE_GET_PRIVATE(self);
    NML3ConfigMergeFlags merge_flags;
    NML3AcdDefendType    acd_defend_type;
    guint32              acd_timeout_msec;

    _dev_l3_get_config_settings(self, l3cd_type, &merge_flags, &acd_defend_type, &acd_timeout_msec);
    return nm_l3cfg_add_config(priv->l3cfg,
                               _dev_l3_config_data_tag_get(priv, l3cd_type),
                               FALSE,
                               priv->l3cds[l3cd_type].d,
                               l3cd_type,
                               nm_device_get_route_table(self, AF_INET),
                               nm_device_get_route_table(self, AF_INET6),
                               nm_device_get_route_metric(self, AF_INET),
                               nm_device_get_route_metric(self, AF_INET6),
                               _dev_default_route_metric_penalty_get(self, AF_INET),
                               _dev_default_route_metric_penalty_get(self, AF_INET6),
                               _prop_get_ipvx_dns_priority(self, AF_INET),
                               _prop_get_ipvx_dns_priority(self, AF_INET6),
                               acd_defend_type,
                               acd_timeout_msec,
                               NM_L3CFG_CONFIG_FLAGS_NONE,
                               merge_flags);
}

static gboolean
_dev_l3_register_l3cds_set_one_full(NMDevice             *self,
                                    L3ConfigDataType      l3cd_type,
                                    const NML3ConfigData *l3cd,
                                    NMTernary             commit_sync)
{
    NMDevicePrivate                         *priv     = NM_DEVICE_GET_PRIVATE(self);
    nm_auto_unref_l3cd const NML3ConfigData *l3cd_old = NULL;
    gboolean                                 changed  = FALSE;

    if (priv->l3cds[l3cd_type].d != l3cd) {
        if (nm_l3_config_data_equal(priv->l3cds[l3cd_type].d, l3cd)) {
            /* we would set to a different instance, but the same content!
             * We keep the previous one and ignore the new @l3cd.
             *
             * Warning: this means, that after calling this function,
             * priv->l3cds[l3cd_type].d still might point to a different
             * (though semantically equal) l3cd instance. */
        } else {
            l3cd_old = g_steal_pointer(&priv->l3cds[l3cd_type].d);
            if (l3cd)
                priv->l3cds[l3cd_type].d = nm_l3_config_data_ref_and_seal(l3cd);
        }
    }

    if (priv->l3cfg) {
        if (priv->l3cds[l3cd_type].d) {
            if (_dev_l3_register_l3cds_add_config(self, l3cd_type))
                changed = TRUE;
        }

        if (l3cd_old) {
            if (nm_l3cfg_remove_config(priv->l3cfg,
                                       _dev_l3_config_data_tag_get(priv, l3cd_type),
                                       l3cd_old))
                changed = TRUE;
        }
    }

    if (changed && commit_sync != NM_TERNARY_DEFAULT)
        _dev_l3_cfg_commit(self, !!commit_sync);

    return changed;
}

static gboolean
_dev_l3_register_l3cds_set_one(NMDevice             *self,
                               L3ConfigDataType      l3cd_type,
                               const NML3ConfigData *l3cd,
                               NMTernary             commit_sync)
{
    return _dev_l3_register_l3cds_set_one_full(self, l3cd_type, l3cd, commit_sync);
}

static void
_dev_l3_update_l3cds_ifindex(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    int              ip_ifindex;
    int              i;

    ip_ifindex = nm_device_get_ip_ifindex(self);
    if (ip_ifindex <= 0)
        return;

    for (i = 0; i < (int) G_N_ELEMENTS(priv->l3cds); i++) {
        if (priv->l3cds[i].d && nm_l3_config_data_get_ifindex(priv->l3cds[i].d) != ip_ifindex) {
            nm_auto_unref_l3cd const NML3ConfigData *l3cd_old = NULL;

            l3cd_old = g_steal_pointer(&priv->l3cds[i].d);

            priv->l3cds[i].d =
                nm_l3_config_data_seal(nm_l3_config_data_new_clone(l3cd_old, ip_ifindex));
        }
    }
}

static gboolean
_dev_l3_register_l3cds(NMDevice *self,
                       NML3Cfg  *l3cfg,
                       gboolean  do_add /* else remove */,
                       NMTernary do_commit)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    gboolean         is_external;
    gboolean         changed;
    int              i;

    if (!l3cfg)
        return FALSE;

    is_external = nm_device_sys_iface_state_is_external(self);

    changed = FALSE;
    for (i = 0; i < (int) G_N_ELEMENTS(priv->l3cds); i++) {
        if (!priv->l3cds[i].d)
            continue;
        if (!do_add) {
            if (nm_l3cfg_remove_config(l3cfg,
                                       _dev_l3_config_data_tag_get(priv, i),
                                       priv->l3cds[i].d))
                changed = TRUE;
            continue;
        }
        if (is_external)
            continue;
        if (_dev_l3_register_l3cds_add_config(self, i))
            changed = TRUE;
    }

    if (do_commit == NM_TERNARY_DEFAULT)
        do_commit = changed;
    if (do_commit)
        _dev_l3_cfg_commit(self, TRUE);

    return changed;
}

/*****************************************************************************/

void
nm_device_l3cfg_commit(NMDevice *self, NML3CfgCommitType commit_type, gboolean commit_sync)
{
    NMDevicePrivate *priv;

    g_return_if_fail(NM_IS_DEVICE(self));

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (!priv->l3cfg)
        return;

    /* FIXME(l3cfg): commit_sync should go away and not be used. The reason is that
     * a commit does *a lot* of things which are outside the control of the caller,
     * which makes it unsuitable to call in most cases. */
    if (!commit_sync) {
        nm_l3cfg_commit_on_idle_schedule(priv->l3cfg, commit_type);
        return;
    }

    nm_l3cfg_commit(priv->l3cfg, commit_type);
}

static void
_dev_l3_cfg_commit(NMDevice *self, gboolean commit_sync)
{
    nm_device_l3cfg_commit(self, NM_L3_CFG_COMMIT_TYPE_AUTO, commit_sync);
}

static void
update_external_connection(NMDevice *self)
{
    NMDevicePrivate              *priv = NM_DEVICE_GET_PRIVATE(self);
    NMSettingsConnection         *settings_connection;
    gs_unref_object NMConnection *connection_new = NULL;
    NMConnection                 *connection_old;
    gs_unref_object NMSetting    *s_ip4_new = NULL;
    gs_unref_object NMSetting    *s_ip6_new = NULL;
    NMSetting                    *s_ip4_old;
    NMSetting                    *s_ip6_old;

    /* Update external connections with configuration from platform */

    if (!nm_device_sys_iface_state_is_external(self))
        return;

    settings_connection = nm_device_get_settings_connection(self);
    if (!settings_connection)
        return;

    if (!NM_FLAGS_HAS(nm_settings_connection_get_flags(settings_connection),
                      NM_SETTINGS_CONNECTION_INT_FLAGS_EXTERNAL))
        return;

    if (nm_active_connection_get_activation_type(NM_ACTIVE_CONNECTION(priv->act_request.obj))
        != NM_ACTIVATION_TYPE_EXTERNAL)
        return;

    connection_old = nm_settings_connection_get_connection(settings_connection);
    s_ip4_old      = nm_connection_get_setting(connection_old, NM_TYPE_SETTING_IP4_CONFIG);
    s_ip6_old      = nm_connection_get_setting(connection_old, NM_TYPE_SETTING_IP6_CONFIG);

    s_ip4_new = nm_utils_platform_capture_ip_setting(nm_device_get_platform(self),
                                                     AF_INET,
                                                     nm_device_get_ip_ifindex(self),
                                                     FALSE);
    s_ip6_new = nm_utils_platform_capture_ip_setting(nm_device_get_platform(self),
                                                     AF_INET6,
                                                     nm_device_get_ip_ifindex(self),
                                                     _get_maybe_ipv6_disabled(self));

    if (!s_ip4_old || !nm_setting_compare(s_ip4_new, s_ip4_old, NM_SETTING_COMPARE_FLAG_EXACT)) {
        connection_new = nm_simple_connection_new_clone(connection_old);
        nm_connection_add_setting(connection_new, g_steal_pointer(&s_ip4_new));
    }

    if (!s_ip6_old || !nm_setting_compare(s_ip6_new, s_ip6_old, NM_SETTING_COMPARE_FLAG_EXACT)) {
        if (!connection_new)
            connection_new = nm_simple_connection_new_clone(connection_old);
        nm_connection_add_setting(connection_new, g_steal_pointer(&s_ip6_new));
    }

    if (connection_new) {
        nm_settings_connection_update(settings_connection,
                                      NULL,
                                      connection_new,
                                      NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY,
                                      NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                      NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                      NM_SETTINGS_CONNECTION_UPDATE_REASON_UPDATE_NON_SECRET,
                                      "update-external",
                                      NULL);
    }
}

static void
_dev_l3_cfg_notify_cb(NML3Cfg *l3cfg, const NML3ConfigNotifyData *notify_data, NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_assert(l3cfg == priv->l3cfg);

    switch (notify_data->notify_type) {
    case NM_L3_CONFIG_NOTIFY_TYPE_L3CD_CHANGED:
        if (notify_data->l3cd_changed.commited) {
            g_signal_emit(self,
                          signals[L3CD_CHANGED],
                          0,
                          notify_data->l3cd_changed.l3cd_old,
                          notify_data->l3cd_changed.l3cd_new);
        }
        return;
    case NM_L3_CONFIG_NOTIFY_TYPE_ACD_EVENT:
    {
        const NML3AcdAddrInfo *addr_info = &notify_data->acd_event.info;
        char                   buf_addr[NM_INET_ADDRSTRLEN];

        if (addr_info->state == NM_L3_ACD_ADDR_STATE_USED) {
            _LOGI(LOGD_DEVICE,
                  "IP address %s cannot be configured because it is already in use in the "
                  "network by host %s",
                  nm_inet4_ntop(addr_info->addr, buf_addr),
                  nm_ether_addr_to_string_a(&addr_info->last_conflict_addr));
        } else if (addr_info->state == NM_L3_ACD_ADDR_STATE_CONFLICT) {
            _LOGI(LOGD_DEVICE,
                  "conflict detected for IP address %s with host %s",
                  nm_inet4_ntop(addr_info->addr, buf_addr),
                  nm_ether_addr_to_string_a(&addr_info->last_conflict_addr));
        }

        if (addr_info->state > NM_L3_ACD_ADDR_STATE_PROBING)
            _dev_ipmanual_check_ready(self);
        return;
    }
    case NM_L3_CONFIG_NOTIFY_TYPE_PRE_COMMIT:
    {
        const NML3ConfigData *l3cd;
        NMDeviceState         state = nm_device_get_state(self);

        if (state >= NM_DEVICE_STATE_IP_CONFIG && state < NM_DEVICE_STATE_DEACTIVATING) {
            /* FIXME(l3cfg): MTU handling should be moved to l3cfg. */
            l3cd = nm_l3cfg_get_combined_l3cd(l3cfg, TRUE);
            if (l3cd)
                priv->ip6_mtu = nm_l3_config_data_get_ip6_mtu(l3cd);
            _commit_mtu(self);
        }
        return;
    }
    case NM_L3_CONFIG_NOTIFY_TYPE_POST_COMMIT:
        if (priv->ipshared_data_4.state == NM_DEVICE_IP_STATE_PENDING
            && !priv->ipshared_data_4.v4.dnsmasq_manager && priv->ipshared_data_4.v4.l3cd) {
            _dev_ipshared4_spawn_dnsmasq(self);
            nm_clear_l3cd(&priv->ipshared_data_4.v4.l3cd);
        }
        _dev_ip_state_check_async(self, AF_UNSPEC);
        _dev_ipmanual_check_ready(self);
        return;
    case NM_L3_CONFIG_NOTIFY_TYPE_IPV4LL_EVENT:
        nm_assert(NM_IS_L3_IPV4LL(notify_data->ipv4ll_event.ipv4ll));
        if (priv->ipll_data_4.v4.ipv4ll == notify_data->ipv4ll_event.ipv4ll)
            _dev_ipll4_notify_event(self);
        return;
    case NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE:
        return;
    case NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE:
        if (NM_FLAGS_ANY(notify_data->platform_change_on_idle.obj_type_flags,
                         nmp_object_type_to_flags(NMP_OBJECT_TYPE_LINK)
                             | nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP4_ADDRESS)
                             | nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP6_ADDRESS)))
            _dev_unmanaged_check_external_down(self, TRUE, TRUE);

        if (NM_FLAGS_ANY(notify_data->platform_change_on_idle.obj_type_flags,
                         nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP4_ADDRESS)
                             | nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP6_ADDRESS))) {
            g_signal_emit(self, signals[PLATFORM_ADDRESS_CHANGED], 0);
        }

        /* Check if AC6 addresses completed DAD */
        if (NM_FLAGS_ANY(notify_data->platform_change_on_idle.obj_type_flags,
                         nmp_object_type_to_flags(NMP_OBJECT_TYPE_IP6_ADDRESS))
            && priv->ipac6_data.state == NM_DEVICE_IP_STATE_PENDING && priv->ipac6_data.l3cd) {
            gs_unref_array GArray *conflicts = NULL;
            gboolean               ready;

            ready = nm_l3cfg_check_ready(l3cfg,
                                         priv->ipac6_data.l3cd,
                                         AF_INET6,
                                         NM_L3CFG_CHECK_READY_FLAGS_IP6_DAD_READY,
                                         &conflicts);
            if (conflicts) {
                /* nm_ndisc_dad_failed() will emit a new "NDisc:config-received"
                 * signal; _dev_ipac6_ndisc_config_changed() will be called
                 * synchronously to update the current state and schedule a commit. */
                nm_ndisc_dad_failed(priv->ipac6_data.ndisc, conflicts, TRUE);
            } else if (ready) {
                nm_clear_l3cd(&priv->ipac6_data.l3cd);
                _dev_ipac6_set_state(self, NM_DEVICE_IP_STATE_READY);
                _dev_ip_state_check_async(self, AF_INET6);
            } else {
                /* wait */
            }
        }

        _dev_ipmanual_check_ready(self);
        update_external_connection(self);
        nm_device_queue_recheck_assume(self);
        return;

    case _NM_L3_CONFIG_NOTIFY_TYPE_NUM:
        break;
    }
    nm_assert_not_reached();
}

static void
_dev_l3_cfg_commit_type_reset(NMDevice *self)
{
    NMDevicePrivate  *priv = NM_DEVICE_GET_PRIVATE(self);
    NML3CfgCommitType commit_type;

    if (!priv->l3cfg)
        return;

    switch (priv->sys_iface_state) {
    case NM_DEVICE_SYS_IFACE_STATE_EXTERNAL:
    case NM_DEVICE_SYS_IFACE_STATE_REMOVED:
        commit_type = NM_L3_CFG_COMMIT_TYPE_NONE;
        goto do_set;
    case NM_DEVICE_SYS_IFACE_STATE_ASSUME:
        /* TODO: NM_DEVICE_SYS_IFACE_STATE_ASSUME, will be dropped from the code.
         * Meanwhile, the commit type must be updated. */
        commit_type = NM_L3_CFG_COMMIT_TYPE_UPDATE;
        goto do_set;
    case NM_DEVICE_SYS_IFACE_STATE_MANAGED:
        commit_type = NM_L3_CFG_COMMIT_TYPE_UPDATE;
        goto do_set;
    }
    nm_assert_not_reached();
    return;

do_set:
    priv->l3cfg_commit_type =
        nm_l3cfg_commit_type_register(priv->l3cfg, commit_type, priv->l3cfg_commit_type, "device");
    if (commit_type == NM_L3_CFG_COMMIT_TYPE_NONE)
        nm_l3cfg_commit_type_reset_update(priv->l3cfg);
}

/*****************************************************************************/

const char *
nm_device_get_udi(NMDevice *self)
{
    g_return_val_if_fail(self != NULL, NULL);

    return NM_DEVICE_GET_PRIVATE(self)->udi;
}

const char *
nm_device_get_iface(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), NULL);

    return NM_DEVICE_GET_PRIVATE(self)->iface;
}

static gboolean
_set_ifindex(NMDevice *self, int ifindex, gboolean is_ip_ifindex)
{
    NMDevicePrivate         *priv                  = NM_DEVICE_GET_PRIVATE(self);
    gs_unref_object NML3Cfg *l3cfg_old             = NULL;
    NML3CfgCommitTypeHandle *l3cfg_commit_type_old = NULL;
    int                      ip_ifindex_new;
    int                     *p_ifindex;
    gboolean                 l3cfg_was_reset = FALSE;

    if (ifindex < 0) {
        nm_assert_not_reached();
        ifindex = 0;
    }

    p_ifindex = is_ip_ifindex ? &priv->ip_ifindex_ : &priv->ifindex_;

    if (*p_ifindex == ifindex)
        return FALSE;

    *p_ifindex = ifindex;

    ip_ifindex_new = nm_device_get_ip_ifindex(self);

    if (priv->l3cfg) {
        if (ip_ifindex_new <= 0 || ip_ifindex_new != nm_l3cfg_get_ifindex(priv->l3cfg)) {
            const NML3ConfigData *l3cd_old;

            if (ip_ifindex_new <= 0) {
                /* The ifindex was reset. Send a last L3CD_CHANGED
                 * signal with a NULL l3cd so that the old one can
                 * be removed from the DNS manager.
                 */
                l3cd_old = nm_l3cfg_get_combined_l3cd(priv->l3cfg, TRUE);
                if (l3cd_old)
                    g_signal_emit(self, signals[L3CD_CHANGED], 0, l3cd_old, NULL);
            }

            g_signal_handlers_disconnect_by_func(priv->l3cfg,
                                                 G_CALLBACK(_dev_l3_cfg_notify_cb),
                                                 self);
            l3cfg_old             = g_steal_pointer(&priv->l3cfg_);
            l3cfg_commit_type_old = g_steal_pointer(&priv->l3cfg_commit_type);
            l3cfg_was_reset       = TRUE;
        }
    }

    if (!priv->l3cfg && l3cfg_old)
        _dev_l3_register_l3cds(self, l3cfg_old, FALSE, FALSE);

    if (!priv->l3cfg && ip_ifindex_new > 0) {
        priv->l3cfg_ = nm_netns_l3cfg_acquire(priv->netns, ip_ifindex_new);

        g_signal_connect(priv->l3cfg,
                         NM_L3CFG_SIGNAL_NOTIFY,
                         G_CALLBACK(_dev_l3_cfg_notify_cb),
                         self);

        _dev_l3_cfg_commit_type_reset(self);
        l3cfg_was_reset = TRUE;
    }

    if (!priv->l3cfg) {
        _cleanup_ip_pre(self, AF_INET, CLEANUP_TYPE_KEEP, FALSE);
        _cleanup_ip_pre(self, AF_INET6, CLEANUP_TYPE_KEEP, FALSE);
    }

    _LOGD(LOGD_DEVICE,
          "ifindex: set %sifindex %d%s%s%s%s%s%s",
          is_ip_ifindex ? "ip-" : "",
          ifindex,
          NM_PRINT_FMT_QUOTED(l3cfg_old && l3cfg_old != priv->l3cfg,
                              " (old-l3cfg: ",
                              nm_hash_obfuscated_ptr_str_a(l3cfg_old),
                              ")",
                              ""),
          NM_PRINT_FMT_QUOTED(priv->l3cfg && l3cfg_old != priv->l3cfg,
                              " (l3cfg: ",
                              nm_hash_obfuscated_ptr_str_a(priv->l3cfg),
                              ")",
                              ""));

    if (priv->manager)
        nm_manager_emit_device_ifindex_changed(priv->manager, self);

    if (!is_ip_ifindex)
        _notify(self, PROP_IFINDEX);

    if (l3cfg_was_reset) {
        gs_unref_object NMIPConfig *ipconf_old_4 = NULL;
        gs_unref_object NMIPConfig *ipconf_old_6 = NULL;

        ipconf_old_4 = g_steal_pointer(&priv->l3ipdata_4.ip_config);
        ipconf_old_6 = g_steal_pointer(&priv->l3ipdata_6.ip_config);
        if (priv->l3cfg) {
            priv->l3ipdata_4.ip_config = nm_l3cfg_ipconfig_acquire(priv->l3cfg, AF_INET);
            priv->l3ipdata_6.ip_config = nm_l3cfg_ipconfig_acquire(priv->l3cfg, AF_INET6);
        }
        _notify(self, PROP_IP4_CONFIG);
        _notify(self, PROP_IP6_CONFIG);
    }

    if (priv->l3cfg && l3cfg_old != priv->l3cfg) {
        /* Now it gets ugly. We changed the ip-ifindex, which determines the NML3Cfg instance.
         * But all the NML3ConfigData we currently track are still for the old ifindex. We
         * need to update them.
         *
         * This should be all handled entirely different, where an NMDevice is strictly
         * associated with one ifindex (and not the ifindex/ip-ifindex split). Or it
         * is not at all associated with an ifindex, but only a controlling device for
         * a real NMDevice (that has the ifindex). */

        _dev_l3_update_l3cds_ifindex(self);

        if (_dev_l3_register_l3cds(self, priv->l3cfg, TRUE, FALSE))
            _dev_l3_cfg_commit(self, TRUE);
    }

    if (l3cfg_commit_type_old)
        nm_l3cfg_commit_type_unregister(l3cfg_old, l3cfg_commit_type_old);

    update_prop_ip_iface(self);

    return TRUE;
}

/**
 * nm_device_take_over_link:
 * @self: the #NMDevice
 * @ifindex: a ifindex
 * @old_name: (transfer full): on return, the name of the old link, if
 *   the link was renamed
 * @error: location to store error, or %NULL
 *
 * Given an existing link, move it under the control of a device. In
 * particular, the link will be renamed to match the device name. If the
 * link was renamed, the old name is returned in @old_name.
 *
 * Returns: %TRUE if the device took control of the link, %FALSE otherwise
 */
gboolean
nm_device_take_over_link(NMDevice *self, int ifindex, char **old_name, GError **error)
{
    NMDevicePrivate      *priv = NM_DEVICE_GET_PRIVATE(self);
    const NMPlatformLink *plink;
    NMPlatform           *platform;

    nm_assert(ifindex > 0);
    NM_SET_OUT(old_name, NULL);

    if (priv->ifindex > 0 && priv->ifindex != ifindex) {
        nm_utils_error_set(error,
                           NM_UTILS_ERROR_UNKNOWN,
                           "the device already has ifindex %d",
                           priv->ifindex);
        return FALSE;
    }

    platform = nm_device_get_platform(self);
    plink    = nm_platform_link_get(platform, ifindex);
    if (!plink) {
        nm_utils_error_set(error, NM_UTILS_ERROR_UNKNOWN, "link %d not found", ifindex);
        return FALSE;
    }

    if (!nm_streq(plink->name, nm_device_get_iface(self))) {
        gboolean      up;
        gboolean      success;
        gs_free char *name = NULL;

        up   = NM_FLAGS_HAS(plink->n_ifi_flags, IFF_UP);
        name = g_strdup(plink->name);

        /* Rename the link to the device ifname */
        if (up)
            nm_platform_link_change_flags(platform, ifindex, IFF_UP, FALSE);
        success = nm_platform_link_set_name(platform, ifindex, nm_device_get_iface(self));
        if (up)
            nm_platform_link_change_flags(platform, ifindex, IFF_UP, TRUE);

        if (!success) {
            nm_utils_error_set(error, NM_UTILS_ERROR_UNKNOWN, "failure renaming link %d", ifindex);
            return FALSE;
        }

        NM_SET_OUT(old_name, g_steal_pointer(&name));
    }

    _set_ifindex(self, ifindex, FALSE);

    return TRUE;
}

int
nm_device_get_ifindex(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), 0);

    return NM_DEVICE_GET_PRIVATE(self)->ifindex;
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
nm_device_is_software(NMDevice *self)
{
    return NM_FLAGS_HAS(NM_DEVICE_GET_PRIVATE(self)->capabilities, NM_DEVICE_CAP_IS_SOFTWARE);
}

/**
 * nm_device_is_real:
 * @self: the #NMDevice
 *
 * Returns: %TRUE if the device exists, %FALSE if the device is a placeholder
 */
gboolean
nm_device_is_real(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    return NM_DEVICE_GET_PRIVATE(self)->real;
}

const char *
nm_device_get_ip_iface(NMDevice *self)
{
    NMDevicePrivate *priv;

    g_return_val_if_fail(self != NULL, NULL);

    priv = NM_DEVICE_GET_PRIVATE(self);
    /* If it's not set, default to iface */
    return priv->ip_iface ?: priv->iface;
}

const char *
nm_device_get_ip_iface_from_platform(NMDevice *self)
{
    int ifindex;

    ifindex = nm_device_get_ip_ifindex(self);
    if (ifindex <= 0)
        return NULL;

    return nm_platform_link_get_name(nm_device_get_platform(self), ifindex);
}

int
nm_device_get_ip_ifindex(const NMDevice *self)
{
    const NMDevicePrivate *priv;

    g_return_val_if_fail(self != NULL, 0);

    priv = NM_DEVICE_GET_PRIVATE(self);
    /* If it's not set, default to ifindex */
    return priv->ip_iface ? priv->ip_ifindex : priv->ifindex;
}

static void
_set_ip_ifindex(NMDevice *self, int ifindex, const char *ifname)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    NMPlatform      *platform;
    gboolean         eq_name;

    /* normalize arguments */
    if (ifindex <= 0) {
        ifindex = 0;
        ifname  = NULL;
    }

    eq_name = nm_streq0(priv->ip_iface, ifname);

    if (eq_name && priv->ip_ifindex == ifindex)
        return;

    _LOGD(LOGD_DEVICE,
          "ip-ifindex: update ip-interface to %s%s%s, ifindex %d",
          NM_PRINT_FMT_QUOTE_STRING(ifname),
          ifindex);

    if (!eq_name) {
        g_free(priv->ip_iface_);
        priv->ip_iface_ = g_strdup(ifname);
        update_prop_ip_iface(self);
    }
    _set_ifindex(self, ifindex, TRUE);

    if (priv->ip_ifindex > 0) {
        platform = nm_device_get_platform(self);

        nm_platform_process_events_ensure_link(platform, priv->ip_ifindex, priv->ip_iface);

        nm_platform_link_set_inet6_addr_gen_mode(platform,
                                                 priv->ip_ifindex,
                                                 NM_IN6_ADDR_GEN_MODE_NONE);

        if (!nm_platform_link_is_up(platform, priv->ip_ifindex))
            nm_platform_link_change_flags(platform, priv->ip_ifindex, IFF_UP, TRUE);
    }

    /* We don't care about any saved values from the old iface */
    g_hash_table_remove_all(priv->ip6_saved_properties);
}

gboolean
nm_device_set_ip_ifindex(NMDevice *self, int ifindex)
{
    char        ifname_buf[IFNAMSIZ];
    const char *ifname = NULL;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);
    g_return_val_if_fail(nm_device_is_activating(self), FALSE);

    if (ifindex > 0) {
        ifname = nm_platform_if_indextoname(nm_device_get_platform(self), ifindex, ifname_buf);
        if (!ifname)
            _LOGW(LOGD_DEVICE, "ip-ifindex: ifindex %d not found", ifindex);
    }

    _set_ip_ifindex(self, ifindex, ifname);
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
nm_device_set_ip_iface(NMDevice *self, const char *ifname)
{
    int ifindex = 0;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);
    g_return_val_if_fail(nm_device_is_activating(self), FALSE);

    if (ifname) {
        ifindex = nm_platform_if_nametoindex(nm_device_get_platform(self), ifname);
        if (ifindex <= 0)
            _LOGW(LOGD_DEVICE, "ip-ifindex: ifname %s not found", ifname);
    }

    _set_ip_ifindex(self, ifindex, ifname);
    return ifindex > 0;
}

/*****************************************************************************/

int
nm_device_parent_get_ifindex(NMDevice *self)
{
    NMDevicePrivate *priv;

    g_return_val_if_fail(NM_IS_DEVICE(self), 0);

    priv = NM_DEVICE_GET_PRIVATE(self);
    return priv->parent_ifindex;
}

NMDevice *
nm_device_parent_get_device(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), NULL);

    return NM_DEVICE_GET_PRIVATE(self)->parent_device.obj;
}

static void
parent_changed_notify(NMDevice *self,
                      int       old_ifindex,
                      NMDevice *old_parent,
                      int       new_ifindex,
                      NMDevice *new_parent)
{
    /* empty handler to allow subclasses to always chain up the virtual function. */
}

static gboolean
_parent_set_ifindex(NMDevice *self, int parent_ifindex, gboolean force_check)
{
    NMDevicePrivate          *priv;
    NMDevice                 *parent_device;
    gboolean                  changed = FALSE;
    int                       old_ifindex;
    gs_unref_object NMDevice *old_device = NULL;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (parent_ifindex <= 0)
        parent_ifindex = 0;

    old_ifindex = priv->parent_ifindex;

    if (priv->parent_ifindex == parent_ifindex) {
        if (parent_ifindex > 0) {
            if (!force_check && priv->parent_device.obj
                && nm_device_get_ifindex(priv->parent_device.obj) == parent_ifindex)
                return FALSE;
        } else {
            if (!priv->parent_device.obj)
                return FALSE;
        }
    } else {
        priv->parent_ifindex = parent_ifindex;
        changed              = TRUE;
    }

    if (parent_ifindex > 0) {
        parent_device = nm_manager_get_device_by_ifindex(NM_MANAGER_GET, parent_ifindex);
        if (parent_device == self)
            parent_device = NULL;
    } else
        parent_device = NULL;

    if (parent_device != priv->parent_device.obj) {
        old_device = nm_g_object_ref(priv->parent_device.obj);
        nm_dbus_track_obj_path_set(&priv->parent_device, parent_device, TRUE);
        changed = TRUE;
    }

    if (changed) {
        if (priv->parent_ifindex <= 0)
            _LOGD(LOGD_DEVICE, "parent: clear");
        else if (!priv->parent_device.obj)
            _LOGD(LOGD_DEVICE, "parent: ifindex %d, no device", priv->parent_ifindex);
        else {
            _LOGD(LOGD_DEVICE,
                  "parent: ifindex %d, device " NM_HASH_OBFUSCATE_PTR_FMT ", %s",
                  priv->parent_ifindex,
                  NM_HASH_OBFUSCATE_PTR(priv->parent_device.obj),
                  nm_device_get_iface(priv->parent_device.obj));
        }

        NM_DEVICE_GET_CLASS(self)->parent_changed_notify(self,
                                                         old_ifindex,
                                                         old_device,
                                                         priv->parent_ifindex,
                                                         priv->parent_device.obj);
    }
    return changed;
}

void
nm_device_parent_set_ifindex(NMDevice *self, int parent_ifindex)
{
    _parent_set_ifindex(self, parent_ifindex, FALSE);
}

gboolean
nm_device_parent_notify_changed(NMDevice *self, NMDevice *change_candidate, gboolean device_removed)
{
    NMDevicePrivate *priv;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(NM_IS_DEVICE(change_candidate));

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->parent_ifindex > 0) {
        if (priv->parent_device.obj == change_candidate
            || priv->parent_ifindex == nm_device_get_ifindex(change_candidate))
            return _parent_set_ifindex(self, priv->parent_ifindex, device_removed);
    }
    return FALSE;
}

/*****************************************************************************/

const char *
nm_device_parent_find_for_connection(NMDevice *self, const char *current_setting_parent)
{
    const char *new_parent;
    NMDevice   *parent_device;

    parent_device = nm_device_parent_get_device(self);
    if (!parent_device)
        return NULL;

    new_parent = nm_device_get_iface(parent_device);
    if (!new_parent)
        return NULL;

    if (current_setting_parent && !nm_streq(current_setting_parent, new_parent)
        && nm_utils_is_uuid(current_setting_parent)) {
        NMSettingsConnection *parent_connection;

        /* Don't change a parent specified by UUID if it's still valid */
        parent_connection = nm_settings_get_connection_by_uuid(nm_device_get_settings(self),
                                                               current_setting_parent);
        if (parent_connection
            && nm_device_check_connection_compatible(
                parent_device,
                nm_settings_connection_get_connection(parent_connection),
                TRUE,
                NULL))
            return current_setting_parent;
    }

    return new_parent;
}

/*****************************************************************************/

static void
_stats_update_counters(NMDevice *self, guint64 tx_bytes, guint64 rx_bytes)
{
    NMDevicePrivate *priv;
    gboolean         tx_changed = FALSE;
    gboolean         rx_changed = FALSE;

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->stats.tx_bytes != tx_bytes) {
        priv->stats.tx_bytes = tx_bytes;
        tx_changed           = TRUE;
    }
    if (priv->stats.rx_bytes != rx_bytes) {
        priv->stats.rx_bytes = rx_bytes;
        rx_changed           = TRUE;
    }

    nm_gobject_notify_together(self,
                               tx_changed ? PROP_STATISTICS_TX_BYTES : PROP_0,
                               rx_changed ? PROP_STATISTICS_RX_BYTES : PROP_0);
}

static void
_stats_update_counters_from_pllink(NMDevice *self, const NMPlatformLink *pllink)
{
    _stats_update_counters(self, pllink->tx_bytes, pllink->rx_bytes);
}

static gboolean
_stats_timeout_cb(gpointer user_data)
{
    NMDevice *self = user_data;
    int       ifindex;

    ifindex = nm_device_get_ip_ifindex(self);

    _LOGT(LOGD_DEVICE, "stats: refresh %d", ifindex);

    if (ifindex > 0)
        nm_platform_link_refresh(nm_device_get_platform(self), ifindex);

    return G_SOURCE_CONTINUE;
}

static guint
_stats_refresh_rate_real(guint refresh_rate_ms)
{
    const guint STATS_REFRESH_RATE_MS_MIN = 200;

    if (refresh_rate_ms == 0)
        return 0;

    if (refresh_rate_ms < STATS_REFRESH_RATE_MS_MIN) {
        /* you cannot set the refresh-rate arbitrarily small. E.g.
         * setting to 1ms is just killing. Have a lowest number. */
        return STATS_REFRESH_RATE_MS_MIN;
    }

    return refresh_rate_ms;
}

static void
_stats_set_refresh_rate(NMDevice *self, guint refresh_rate_ms)
{
    NMDevicePrivate *priv;
    int              ifindex;
    guint            old_rate;

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->stats.refresh_rate_ms == refresh_rate_ms)
        return;

    old_rate                    = priv->stats.refresh_rate_ms;
    priv->stats.refresh_rate_ms = refresh_rate_ms;
    _notify(self, PROP_STATISTICS_REFRESH_RATE_MS);

    _LOGD(LOGD_DEVICE, "stats: set refresh to %u ms", priv->stats.refresh_rate_ms);

    if (!nm_device_is_real(self))
        return;

    refresh_rate_ms = _stats_refresh_rate_real(refresh_rate_ms);
    if (_stats_refresh_rate_real(old_rate) == refresh_rate_ms)
        return;

    nm_clear_g_source_inst(&priv->stats.timeout_source);

    if (!refresh_rate_ms)
        return;

    /* trigger an initial refresh of the data whenever the refresh-rate changes.
     * As we process the result in an idle handler with device_link_changed(),
     * we don't get the result right away. */
    ifindex = nm_device_get_ip_ifindex(self);
    if (ifindex > 0)
        nm_platform_link_refresh(nm_device_get_platform(self), ifindex);

    priv->stats.timeout_source = nm_g_timeout_add_source(refresh_rate_ms, _stats_timeout_cb, self);
}

/*****************************************************************************/

static gboolean
get_ip_iface_identifier(NMDevice *self, NMUtilsIPv6IfaceId *out_iid)
{
    NMDevicePrivate      *priv     = NM_DEVICE_GET_PRIVATE(self);
    NMPlatform           *platform = nm_device_get_platform(self);
    const NMPlatformLink *pllink;
    NMLinkType            link_type;
    const guint8         *hwaddr;
    guint8                pseudo_hwaddr[ETH_ALEN];
    gsize                 hwaddr_len;
    int                   ifindex;
    gboolean              success;

    /* If we get here, we *must* have a kernel netdev, which implies an ifindex */
    ifindex = nm_device_get_ip_ifindex(self);
    g_return_val_if_fail(ifindex > 0, FALSE);

    pllink = nm_platform_link_get(platform, ifindex);
    if (!pllink || NM_IN_SET(pllink->type, NM_LINK_TYPE_NONE, NM_LINK_TYPE_UNKNOWN))
        return FALSE;

    hwaddr = nmp_link_address_get(&pllink->l_address, &hwaddr_len);
    if (hwaddr_len <= 0)
        return FALSE;

    link_type = pllink->type;

    if (pllink->type == NM_LINK_TYPE_6LOWPAN) {
        /* If the underlying IEEE 802.15.4 device has a short address we generate
         * a "pseudo 48-bit address" that's to be used in the same fashion as a
         * wired Ethernet address. The mechanism is specified in Section 6. of
         * RFC 4944 */
        guint16 pan_id;
        guint16 short_addr;

        short_addr = nm_platform_wpan_get_short_addr(platform, pllink->parent);
        if (short_addr != G_MAXUINT16) {
            pan_id           = nm_platform_wpan_get_pan_id(platform, pllink->parent);
            pseudo_hwaddr[0] = short_addr & 0xff;
            pseudo_hwaddr[1] = (short_addr >> 8) & 0xff;
            pseudo_hwaddr[2] = 0;
            pseudo_hwaddr[3] = 0;
            pseudo_hwaddr[4] = pan_id & 0xff;
            pseudo_hwaddr[5] = (pan_id >> 8) & 0xff;

            hwaddr     = pseudo_hwaddr;
            hwaddr_len = G_N_ELEMENTS(pseudo_hwaddr);
            link_type  = NM_LINK_TYPE_ETHERNET;
        }
    }

    success = nm_utils_get_ipv6_interface_identifier(link_type,
                                                     hwaddr,
                                                     hwaddr_len,
                                                     priv->dev_id,
                                                     out_iid);
    if (!success) {
        _LOGW(LOGD_PLATFORM,
              "failed to generate interface identifier "
              "for link type %u hwaddr_len %zu",
              pllink->type,
              hwaddr_len);
    }
    return success;
}

/**
 * nm_device_get_ip_iface_identifier:
 * @self: an #NMDevice
 * @iid: where to place the interface identifier
 * @ignore_token: force creation of a non-tokenized address
 * @out_is_token: on return, whether the identifier is tokenized
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
nm_device_get_ip_iface_identifier(NMDevice           *self,
                                  NMUtilsIPv6IfaceId *iid,
                                  gboolean            ignore_token,
                                  gboolean           *out_is_token)
{
    NMSettingIP6Config *s_ip6;
    const char         *token;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    NM_SET_OUT(out_is_token, FALSE);

    if (!ignore_token) {
        s_ip6 = nm_device_get_applied_setting(self, NM_TYPE_SETTING_IP6_CONFIG);

        g_return_val_if_fail(s_ip6, FALSE);

        token = nm_setting_ip6_config_get_token(s_ip6);
        if (token) {
            NM_SET_OUT(out_is_token, TRUE);
            return nm_utils_ipv6_interface_identifier_get_from_token(iid, token);
        }
    }
    return NM_DEVICE_GET_CLASS(self)->get_ip_iface_identifier(self, iid);
}

const char *
nm_device_get_s390_subchannels(NMDevice *self)
{
    NMDeviceClass *klass;

    g_return_val_if_fail(NM_IS_DEVICE(self), NULL);

    klass = NM_DEVICE_GET_CLASS(self);

    return klass->get_s390_subchannels ? klass->get_s390_subchannels(self) : NULL;
}

const char *
nm_device_get_driver(NMDevice *self)
{
    g_return_val_if_fail(self != NULL, NULL);

    return NM_DEVICE_GET_PRIVATE(self)->driver;
}

const char *
nm_device_get_driver_version(NMDevice *self)
{
    g_return_val_if_fail(self != NULL, NULL);

    return NM_DEVICE_GET_PRIVATE(self)->driver_version;
}

NMDeviceType
nm_device_get_device_type(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), NM_DEVICE_TYPE_UNKNOWN);

    return NM_DEVICE_GET_PRIVATE(self)->type;
}

NMLinkType
nm_device_get_link_type(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), NM_LINK_TYPE_UNKNOWN);

    return NM_DEVICE_GET_PRIVATE(self)->link_type;
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
nm_device_get_metered(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), NM_METERED_UNKNOWN);

    return NM_DEVICE_GET_PRIVATE(self)->metered;
}

guint32
nm_device_get_route_metric_default(NMDeviceType device_type)
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
    case NM_DEVICE_TYPE_LOOPBACK:
        return 30;

    /* 50 is also used for VPN plugins (NM_VPN_ROUTE_METRIC_DEFAULT).
     *
     * Note that returning 50 from this function means that this device-type is
     * in some aspects a VPN. */
    case NM_DEVICE_TYPE_WIREGUARD:
        return NM_VPN_ROUTE_METRIC_DEFAULT;

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
    case NM_DEVICE_TYPE_VRF:
        return 470;
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
    case NM_DEVICE_TYPE_6LOWPAN:
        return 775;
    case NM_DEVICE_TYPE_OVS_BRIDGE:
    case NM_DEVICE_TYPE_OVS_INTERFACE:
    case NM_DEVICE_TYPE_OVS_PORT:
        return 800;
    case NM_DEVICE_TYPE_WPAN:
        return 850;
    case NM_DEVICE_TYPE_WIFI_P2P:
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

static guint32
_dev_default_route_metric_penalty_get(NMDevice *self, int addr_family)
{
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);

    if (priv->concheck_x[IS_IPv4].state != NM_CONNECTIVITY_FULL
        && nm_connectivity_check_enabled(concheck_get_mgr(self)))
        return 20000;

    return 0;
}

guint32
nm_device_get_route_metric(NMDevice *self, int addr_family)
{
    gint64             route_metric;
    NMSettingIPConfig *s_ip;
    NMConnection      *connection;
    const char        *property;

    g_return_val_if_fail(NM_IS_DEVICE(self), G_MAXUINT32);
    g_return_val_if_fail(NM_IN_SET(addr_family, AF_INET, AF_INET6), G_MAXUINT32);

    connection = nm_device_get_applied_connection(self);
    if (connection) {
        s_ip = nm_connection_get_setting_ip_config(connection, addr_family);

        /* Slave interfaces don't have IP settings, but we may get here when
         * external changes are made or when noticing IP changes when starting
         * the slave connection.
         */
        if (s_ip) {
            route_metric = nm_setting_ip_config_get_route_metric(s_ip);
            if (route_metric >= 0)
                goto out;
        }
    }

    /* use the current NMConfigData, which makes this configuration reloadable.
     * Note that that means that the route-metric might change between SIGHUP.
     * You must cache the returned value if that is a problem. */
    property     = NM_IS_IPv4(addr_family) ? NM_CON_DEFAULT("ipv4.route-metric")
                                           : NM_CON_DEFAULT("ipv6.route-metric");
    route_metric = nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                               property,
                                                               self,
                                                               0,
                                                               G_MAXUINT32,
                                                               -1);
    if (route_metric >= 0)
        goto out;

    route_metric = nm_manager_device_route_metric_reserve(NM_MANAGER_GET,
                                                          nm_device_get_ip_ifindex(self),
                                                          nm_device_get_device_type(self));
out:
    return nm_utils_ip_route_metric_normalize(addr_family, route_metric);
}

guint32
nm_device_get_route_table(NMDevice *self, int addr_family)
{
    guint32 route_table;

    g_return_val_if_fail(NM_IS_DEVICE(self), RT_TABLE_MAIN);

    route_table = _prop_get_ipvx_route_table(self, addr_family);
    return route_table ?: (guint32) RT_TABLE_MAIN;
}

/* FIXME(l3cfg): need to properly handle the route-table sync mode and
 * use it during commit. */
_nm_unused static NMIPRouteTableSyncMode
_get_route_table_sync_mode_stateful(NMDevice *self, int addr_family)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    gboolean         all_sync_now;
    gboolean         all_sync_eff;

    all_sync_now = _prop_get_ipvx_route_table(self, addr_family) != 0u;

    if (!all_sync_now) {
        const NML3ConfigData *l3cd = priv->l3cds[L3_CONFIG_DATA_TYPE_MANUALIP].d;

        /* If there's a local route switch to all-sync in order
         * to properly manage the local table */
        all_sync_now = l3cd && nm_l3_config_data_has_routes_with_type_local(l3cd, addr_family);
    }

    if (all_sync_now)
        all_sync_eff = TRUE;
    else {
        /* When we change from all-sync to no all-sync, we do a last all-sync one
         * more time. For that, we determine the effective all-state based on the
         * cached/previous all-sync flag.
         *
         * The purpose of this is to support reapply of route-table (and thus the
         * all-sync mode). If reapply toggles from all-sync to no-all-sync, we must
         * sync one last time. */
        if (NM_IS_IPv4(addr_family))
            all_sync_eff = priv->v4_route_table_all_sync_before;
        else
            all_sync_eff = priv->v6_route_table_all_sync_before;
    }

    if (NM_IS_IPv4(addr_family))
        priv->v4_route_table_all_sync_before = all_sync_now;
    else
        priv->v6_route_table_all_sync_before = all_sync_now;

    return all_sync_eff ? NM_IP_ROUTE_TABLE_SYNC_MODE_ALL : NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN;
}

const NMPObject *
nm_device_get_best_default_route(NMDevice *self, int addr_family)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (!priv->l3cfg)
        return NULL;

    /* FIXME(l3cfg): this function returns the best default route that we
     * *want* to configure. What is the meaning of that? Possibly the caller
     * cares whether there *is* a default route configured, for which they
     * should ask platform.
     *
     * Check callers why they call this. Quite possibly this whole notion of
     * "has a default route" is wrong to being with, regardless whether we
     * look at the desired or actual configuration. That is, because "has a default route"
     * does not do justice to the complexity of routing (with policy routing,
     * etc.). */
    return nm_l3cfg_get_best_default_route(priv->l3cfg, addr_family, TRUE);
}

const char *
nm_device_get_type_desc(NMDevice *self)
{
    g_return_val_if_fail(self != NULL, NULL);

    return NM_DEVICE_GET_PRIVATE(self)->type_desc;
}

const char *
nm_device_get_type_desc_for_log(NMDevice *self)
{
    const char *type;

    type = nm_device_get_type_desc(self);

    /* Some OVS device types (ports and bridges) are not backed by a kernel link, and
     * they can have the same name of another device of a different type. In fact, it's
     * quite common to assign the same name to the OVS bridge, the OVS port and the OVS
     * interface. For this reason, also log the type in case of OVS devices to make the
     * log message unambiguous. */
    if (NM_STR_HAS_PREFIX(type, "Open vSwitch"))
        return type;

    return NULL;
}

const char *
nm_device_get_type_description(NMDevice *self)
{
    g_return_val_if_fail(self != NULL, NULL);

    /* Beware: this function should return the same
     * value as nm_device_get_type_description() in libnm.
     * The returned string is static or interned */
    return NM_DEVICE_GET_CLASS(self)->get_type_description(self);
}

static const char *
get_type_description(NMDevice *self)
{
    NMDeviceClass *klass;

    nm_assert(NM_IS_DEVICE(self));

    /* the default implementation for the description just returns the (modified)
     * class name and depends entirely on the type of self. Note that we cache the
     * description in the klass itself.
     *
     * Also note, that as the GObject class gets inited, it inherrits the fields
     * of the parent class. That means, if NMDeviceVethClass was initialized after
     * NMDeviceEthernetClass already has the description cached in the class
     * (because we already fetched the description for an ethernet device),
     * then default_type_description will wrongly contain "ethernet".
     * To avoid that, and catch the situation, also cache the klass for
     * which the description was cached. If that doesn't match, it was
     * inherited and we need to reset it. */
    klass = NM_DEVICE_GET_CLASS(self);
    if (G_UNLIKELY(klass->default_type_description_klass != klass)) {
        const char *typename;
        gs_free char *s = NULL;

        typename = G_OBJECT_TYPE_NAME(self);
        if (g_str_has_prefix(typename, "NMDevice")) {
            typename += 8;
            if (nm_streq(typename, "Veth"))
                typename = "Ethernet";
        }
        s                                     = g_ascii_strdown(typename, -1);
        klass->default_type_description       = g_intern_string(s);
        klass->default_type_description_klass = klass;
    }

    nm_assert(klass->default_type_description);
    return klass->default_type_description;
}

gboolean
nm_device_has_carrier(NMDevice *self)
{
    return NM_DEVICE_GET_PRIVATE(self)->carrier;
}

NMActRequest *
nm_device_get_act_request(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), NULL);

    return NM_DEVICE_GET_PRIVATE(self)->act_request.obj;
}

NMActivationStateFlags
nm_device_get_activation_state_flags(NMDevice *self)
{
    NMActRequest *ac;

    g_return_val_if_fail(NM_IS_DEVICE(self), NM_ACTIVATION_STATE_FLAG_NONE);

    ac = NM_DEVICE_GET_PRIVATE(self)->act_request.obj;
    if (!ac)
        return NM_ACTIVATION_STATE_FLAG_NONE;
    return nm_active_connection_get_state_flags(NM_ACTIVE_CONNECTION(ac));
}

NMSettingsConnection *
nm_device_get_settings_connection(NMDevice *self)
{
    NMDevicePrivate *priv;

    g_return_val_if_fail(NM_IS_DEVICE(self), NULL);

    priv = NM_DEVICE_GET_PRIVATE(self);

    return priv->act_request.obj ? nm_act_request_get_settings_connection(priv->act_request.obj)
                                 : NULL;
}

NMConnection *
nm_device_get_settings_connection_get_connection(NMDevice *self)
{
    NMSettingsConnection *sett_con;
    NMDevicePrivate      *priv = NM_DEVICE_GET_PRIVATE(self);

    if (!priv->act_request.obj)
        return NULL;

    sett_con = nm_act_request_get_settings_connection(priv->act_request.obj);
    if (!sett_con)
        return NULL;

    return nm_settings_connection_get_connection(sett_con);
}

NMConnection *
nm_device_get_applied_connection(NMDevice *self)
{
    NMDevicePrivate *priv;

    g_return_val_if_fail(NM_IS_DEVICE(self), NULL);

    priv = NM_DEVICE_GET_PRIVATE(self);

    return priv->act_request.obj ? nm_act_request_get_applied_connection(priv->act_request.obj)
                                 : NULL;
}

gboolean
nm_device_has_unmodified_applied_connection(NMDevice *self, NMSettingCompareFlags compare_flags)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (!priv->act_request.obj)
        return FALSE;

    return nm_active_connection_has_unmodified_applied_connection(
        (NMActiveConnection *) priv->act_request.obj,
        compare_flags);
}

gpointer
nm_device_get_applied_setting(NMDevice *self, GType setting_type)
{
    NMConnection *connection;

    connection = nm_device_get_applied_connection(self);
    return connection ? nm_connection_get_setting(connection, setting_type) : NULL;
}

NMRfkillType
nm_device_get_rfkill_type(NMDevice *self)
{
    NMRfkillType t;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    t = NM_DEVICE_GET_CLASS(self)->rfkill_type;

    nm_assert(NM_IN_SET(t, NM_RFKILL_TYPE_UNKNOWN, NM_RFKILL_TYPE_WLAN, NM_RFKILL_TYPE_WWAN));
    return t;
}

static const char *
nm_device_get_physical_port_id(NMDevice *self)
{
    return NM_DEVICE_GET_PRIVATE(self)->physical_port_id;
}

/*****************************************************************************/

typedef enum {
    CONCHECK_SCHEDULE_UPDATE_INTERVAL,
    CONCHECK_SCHEDULE_UPDATE_INTERVAL_RESTART,
    CONCHECK_SCHEDULE_CHECK_EXTERNAL,
    CONCHECK_SCHEDULE_CHECK_PERIODIC,
    CONCHECK_SCHEDULE_RETURNED_MIN,
    CONCHECK_SCHEDULE_RETURNED_BUMP,
    CONCHECK_SCHEDULE_RETURNED_MAX,
} ConcheckScheduleMode;

static NMDeviceConnectivityHandle *concheck_start(NMDevice                    *self,
                                                  int                          addr_family,
                                                  NMDeviceConnectivityCallback callback,
                                                  gpointer                     user_data,
                                                  gboolean                     is_periodic);

static void
concheck_periodic_schedule_set(NMDevice *self, int addr_family, ConcheckScheduleMode mode);

static gboolean
_concheck_periodic_timeout_cb(NMDevice *self, int addr_family)
{
    _LOGt(LOGD_CONCHECK,
          "connectivity: [IPv%c] periodic timeout",
          nm_utils_addr_family_to_char(addr_family));
    concheck_periodic_schedule_set(self, addr_family, CONCHECK_SCHEDULE_CHECK_PERIODIC);
    return G_SOURCE_REMOVE;
}

static gboolean
concheck_ip4_periodic_timeout_cb(gpointer user_data)
{
    return _concheck_periodic_timeout_cb(user_data, AF_INET);
}

static gboolean
concheck_ip6_periodic_timeout_cb(gpointer user_data)
{
    return _concheck_periodic_timeout_cb(user_data, AF_INET6);
}

static gboolean
concheck_is_possible(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (!nm_device_is_real(self) || NM_IS_DEVICE_LOOPBACK(self))
        return FALSE;

    /* we enable periodic checks for every device state (except UNKNOWN). Especially with
     * unmanaged devices, it is interesting to know whether we have connectivity on that device. */
    if (priv->state == NM_DEVICE_STATE_UNKNOWN)
        return FALSE;

    return TRUE;
}

static gboolean
concheck_periodic_schedule_do(NMDevice *self, int addr_family, gint64 now_ns)
{
    NMDevicePrivate *priv                    = NM_DEVICE_GET_PRIVATE(self);
    gboolean         periodic_check_disabled = FALSE;
    gint64           expiry, tdiff;
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);

    /* we always cancel whatever was pending. */
    if (nm_clear_g_source(&priv->concheck_x[IS_IPv4].p_cur_id))
        periodic_check_disabled = TRUE;

    if (priv->concheck_x[IS_IPv4].p_max_interval == 0) {
        /* periodic checks are disabled */
        goto out;
    }

    if (!concheck_is_possible(self))
        goto out;

    nm_assert(now_ns > 0);
    nm_assert(priv->concheck_x[IS_IPv4].p_cur_interval > 0);

    /* we schedule the timeout based on our current settings cur-interval and cur-basetime.
     * Before calling concheck_periodic_schedule_do(), make sure that these properties are
     * correct. */

    expiry = priv->concheck_x[IS_IPv4].p_cur_basetime_ns
             + (priv->concheck_x[IS_IPv4].p_cur_interval * NM_UTILS_NSEC_PER_SEC);
    tdiff = expiry - now_ns;

    _LOGT(LOGD_CONCHECK,
          "connectivity: [IPv%c] periodic-check: %sscheduled in %lld milliseconds (%u seconds "
          "interval)",
          nm_utils_addr_family_to_char(addr_family),
          periodic_check_disabled ? "re-" : "",
          (long long) (tdiff / NM_UTILS_NSEC_PER_MSEC),
          priv->concheck_x[IS_IPv4].p_cur_interval);

    priv->concheck_x[IS_IPv4].p_cur_id =
        g_timeout_add(NM_MAX((gint64) 0, tdiff) / NM_UTILS_NSEC_PER_MSEC,
                      IS_IPv4 ? concheck_ip4_periodic_timeout_cb : concheck_ip6_periodic_timeout_cb,
                      self);
    return TRUE;
out:
    if (periodic_check_disabled) {
        _LOGT(LOGD_CONCHECK,
              "connectivity: [IPv%c] periodic-check: unscheduled",
              nm_utils_addr_family_to_char(addr_family));
    }
    return FALSE;
}

#define CONCHECK_P_PROBE_INTERVAL 1

static void
concheck_periodic_schedule_set(NMDevice *self, int addr_family, ConcheckScheduleMode mode)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    gint64           new_expiry, exp_expiry, cur_expiry, tdiff;
    gint64           now_ns  = 0;
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);

    if (priv->concheck_x[IS_IPv4].p_max_interval == 0) {
        /* periodic check is disabled. Nothing to do. */
        return;
    }

    if (!priv->concheck_x[IS_IPv4].p_cur_id) {
        /* we currently don't have a timeout scheduled. No need to reschedule
         * another one... */
        if (NM_IN_SET(mode,
                      CONCHECK_SCHEDULE_UPDATE_INTERVAL,
                      CONCHECK_SCHEDULE_UPDATE_INTERVAL_RESTART)) {
            /* ... unless, we are about to start periodic checks after update-interval.
             * In this case, fall through and restart the periodic checks below. */
            mode = CONCHECK_SCHEDULE_UPDATE_INTERVAL_RESTART;
        } else
            return;
    }

    switch (mode) {
    case CONCHECK_SCHEDULE_UPDATE_INTERVAL_RESTART:
        priv->concheck_x[IS_IPv4].p_cur_interval =
            NM_MIN(priv->concheck_x[IS_IPv4].p_max_interval, CONCHECK_P_PROBE_INTERVAL);
        priv->concheck_x[IS_IPv4].p_cur_basetime_ns =
            nm_utils_get_monotonic_timestamp_nsec_cached(&now_ns);
        if (concheck_periodic_schedule_do(self, addr_family, now_ns))
            concheck_start(self, addr_family, NULL, NULL, TRUE);
        return;

    case CONCHECK_SCHEDULE_UPDATE_INTERVAL:
        /* called with "UPDATE_INTERVAL" and already have a p_cur_id scheduled. */

        nm_assert(priv->concheck_x[IS_IPv4].p_max_interval > 0);
        nm_assert(priv->concheck_x[IS_IPv4].p_cur_interval > 0);

        if (priv->concheck_x[IS_IPv4].p_cur_interval <= priv->concheck_x[IS_IPv4].p_max_interval) {
            /* we currently have a shorter interval set, than what we now have. Either,
             * because we are probing, or because the previous max interval was shorter.
             *
             * Either way, the current timer is set just fine. Nothing to do, we will
             * probe our way up. */
            return;
        }

        cur_expiry = priv->concheck_x[IS_IPv4].p_cur_basetime_ns
                     + (priv->concheck_x[IS_IPv4].p_max_interval * NM_UTILS_NSEC_PER_SEC);
        nm_utils_get_monotonic_timestamp_nsec_cached(&now_ns);

        priv->concheck_x[IS_IPv4].p_cur_interval = priv->concheck_x[IS_IPv4].p_max_interval;
        if (cur_expiry <= now_ns) {
            /* Since the last time we scheduled a periodic check, already more than the
             * new max_interval passed. We need to start a check right away (and
             * schedule a timeout in cur-interval in the future). */
            priv->concheck_x[IS_IPv4].p_cur_basetime_ns = now_ns;
            if (concheck_periodic_schedule_do(self, addr_family, now_ns))
                concheck_start(self, addr_family, NULL, NULL, TRUE);
        } else {
            /* we are reducing the max-interval to a shorter interval that we have currently
             * scheduled (with cur_interval).
             *
             * However, since the last time we scheduled the check, not even the new max-interval
             * expired. All we need to do, is reschedule the timer to expire sooner. The cur_basetime
             * is unchanged. */
            concheck_periodic_schedule_do(self, addr_family, now_ns);
        }
        return;

    case CONCHECK_SCHEDULE_CHECK_EXTERNAL:
        /* a external connectivity check delays our periodic check. We reset the counter. */
        priv->concheck_x[IS_IPv4].p_cur_basetime_ns =
            nm_utils_get_monotonic_timestamp_nsec_cached(&now_ns);
        concheck_periodic_schedule_do(self, addr_family, now_ns);
        return;

    case CONCHECK_SCHEDULE_CHECK_PERIODIC:
    {
        gboolean                    any_periodic_pending;
        NMDeviceConnectivityHandle *handle;
        guint                       old_interval = priv->concheck_x[IS_IPv4].p_cur_interval;

        any_periodic_pending = FALSE;
        c_list_for_each_entry (handle, &priv->concheck_lst_head, concheck_lst) {
            if (handle->addr_family != addr_family)
                continue;
            if (handle->is_periodic_bump) {
                handle->is_periodic_bump             = FALSE;
                handle->is_periodic_bump_on_complete = FALSE;
                any_periodic_pending                 = TRUE;
            }
        }
        if (any_periodic_pending) {
            /* we reached a timeout to schedule a new periodic request, however we still
             * have period requests pending that didn't complete yet. We need to bump the
             * interval already. */
            priv->concheck_x[IS_IPv4].p_cur_interval =
                NM_MIN(old_interval * 2, priv->concheck_x[IS_IPv4].p_max_interval);
        }

        /* we just reached a timeout. The expected expiry (exp_expiry) should be
         * pretty close to now_ns.
         *
         * We want to reschedule the timeout at exp_expiry (aka now) + cur_interval. */
        nm_utils_get_monotonic_timestamp_nsec_cached(&now_ns);
        exp_expiry =
            priv->concheck_x[IS_IPv4].p_cur_basetime_ns + (old_interval * NM_UTILS_NSEC_PER_SEC);
        new_expiry =
            exp_expiry + (priv->concheck_x[IS_IPv4].p_cur_interval * NM_UTILS_NSEC_PER_SEC);
        tdiff = NM_MAX(new_expiry - now_ns, 0);
        priv->concheck_x[IS_IPv4].p_cur_basetime_ns =
            (now_ns + tdiff) - (priv->concheck_x[IS_IPv4].p_cur_interval * NM_UTILS_NSEC_PER_SEC);
        if (concheck_periodic_schedule_do(self, addr_family, now_ns)) {
            handle = concheck_start(self, addr_family, NULL, NULL, TRUE);
            if (old_interval != priv->concheck_x[IS_IPv4].p_cur_interval) {
                /* we just bumped the interval already when scheduling this check.
                 * When the handle returns, don't bump a second time.
                 *
                 * But if we reach the timeout again before the handle returns (this
                 * code here) we will still bump the interval. */
                handle->is_periodic_bump_on_complete = FALSE;
            }
        }
        return;
    }

    /* we just got an event that we lost connectivity (that is, concheck returned). We reset
     * the interval to min/max or increase the probe interval (bump). */
    case CONCHECK_SCHEDULE_RETURNED_MIN:
        priv->concheck_x[IS_IPv4].p_cur_interval =
            NM_MIN(priv->concheck_x[IS_IPv4].p_max_interval, CONCHECK_P_PROBE_INTERVAL);
        break;
    case CONCHECK_SCHEDULE_RETURNED_MAX:
        priv->concheck_x[IS_IPv4].p_cur_interval = priv->concheck_x[IS_IPv4].p_max_interval;
        break;
    case CONCHECK_SCHEDULE_RETURNED_BUMP:
        priv->concheck_x[IS_IPv4].p_cur_interval =
            NM_MIN(priv->concheck_x[IS_IPv4].p_cur_interval * 2,
                   priv->concheck_x[IS_IPv4].p_max_interval);
        break;
    }

    /* we are here, because we returned from a connectivity check and adjust the current interval.
     *
     * But note that we calculate the new timeout based on the time when we scheduled the
     * last check, instead of counting from now. The reason is that we want that the times
     * when we schedule checks be at precise intervals, without including the time it took for
     * the connectivity check. */
    new_expiry = priv->concheck_x[IS_IPv4].p_cur_basetime_ns
                 + (priv->concheck_x[IS_IPv4].p_cur_interval * NM_UTILS_NSEC_PER_SEC);
    tdiff = NM_MAX(new_expiry - nm_utils_get_monotonic_timestamp_nsec_cached(&now_ns), 0);
    priv->concheck_x[IS_IPv4].p_cur_basetime_ns =
        now_ns + tdiff - (priv->concheck_x[IS_IPv4].p_cur_interval * NM_UTILS_NSEC_PER_SEC);
    concheck_periodic_schedule_do(self, addr_family, now_ns);
}

static void
concheck_update_interval(NMDevice *self, int addr_family, gboolean check_now)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    guint            new_interval;
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);

    new_interval = nm_connectivity_get_interval(concheck_get_mgr(self));

    new_interval = NM_MIN(new_interval, 7 * 24 * 3600);

    if (new_interval != priv->concheck_x[IS_IPv4].p_max_interval) {
        _LOGT(LOGD_CONCHECK,
              "connectivity: [IPv%c] periodic-check: set interval to %u seconds",
              nm_utils_addr_family_to_char(addr_family),
              new_interval);
        priv->concheck_x[IS_IPv4].p_max_interval = new_interval;
    }

    if (!new_interval) {
        /* this will cancel any potentially pending timeout because max-interval is zero.
         * But it logs a nice message... */
        concheck_periodic_schedule_do(self, addr_family, 0);

        /* also update the fake connectivity state. */
        concheck_update_state(self, addr_family, NM_CONNECTIVITY_FAKE, TRUE);
        return;
    }

    concheck_periodic_schedule_set(self,
                                   addr_family,
                                   check_now ? CONCHECK_SCHEDULE_UPDATE_INTERVAL_RESTART
                                             : CONCHECK_SCHEDULE_UPDATE_INTERVAL);
}

void
nm_device_check_connectivity_update_interval(NMDevice *self)
{
    concheck_update_interval(self, AF_INET, TRUE);
    concheck_update_interval(self, AF_INET6, TRUE);
}

static void
concheck_update_state(NMDevice           *self,
                      int                 addr_family,
                      NMConnectivityState state,
                      gboolean            allow_periodic_bump)
{
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);

    /* @state is a result of the connectivity check. We only expect a precise
     * number of possible values. */
    nm_assert(NM_IN_SET(state,
                        NM_CONNECTIVITY_LIMITED,
                        NM_CONNECTIVITY_PORTAL,
                        NM_CONNECTIVITY_FULL,
                        NM_CONNECTIVITY_FAKE,
                        NM_CONNECTIVITY_NONE,
                        NM_CONNECTIVITY_ERROR));

    if (state == NM_CONNECTIVITY_ERROR) {
        /* on error, we don't change the current connectivity state,
         * except making UNKNOWN to NONE. */
        state = priv->concheck_x[IS_IPv4].state;
        if (state == NM_CONNECTIVITY_UNKNOWN)
            state = NM_CONNECTIVITY_NONE;
    } else if (state == NM_CONNECTIVITY_FAKE) {
        /* If the connectivity check is disabled and we obtain a fake
         * result, make an optimistic guess. */
        if (priv->state == NM_DEVICE_STATE_ACTIVATED) {
            /* FIXME: the fake connectivity state depends on the availability of
             * a default route. However, we have no mechanism that rechecks the
             * value if a device route appears/disappears after the device
             * was activated. */
            if (nm_device_get_best_default_route(self, AF_UNSPEC))
                state = NM_CONNECTIVITY_FULL;
            else
                state = NM_CONNECTIVITY_LIMITED;
        } else
            state = NM_CONNECTIVITY_NONE;
    }

    if (priv->concheck_x[IS_IPv4].state == state) {
        /* we got a connectivity update, but the state didn't change. If we were probing,
         * we bump the probe frequency. */
        if (allow_periodic_bump)
            concheck_periodic_schedule_set(self, addr_family, CONCHECK_SCHEDULE_RETURNED_BUMP);
        return;
    }
    /* we need to update the probe interval before emitting signals. Emitting
     * a signal might call back into NMDevice and change the probe settings.
     * So, do that first. */
    if (state == NM_CONNECTIVITY_FULL) {
        /* we reached full connectivity state. Stop probing by setting the
         * interval to the max. */
        concheck_periodic_schedule_set(self, addr_family, CONCHECK_SCHEDULE_RETURNED_MAX);
    } else if (priv->concheck_x[IS_IPv4].state == NM_CONNECTIVITY_FULL) {
        /* we are about to loose connectivity. (re)start probing by setting
         * the timeout interval to the min. */
        concheck_periodic_schedule_set(self, addr_family, CONCHECK_SCHEDULE_RETURNED_MIN);
    } else {
        if (allow_periodic_bump)
            concheck_periodic_schedule_set(self, addr_family, CONCHECK_SCHEDULE_RETURNED_BUMP);
    }

    _LOGD(LOGD_CONCHECK,
          "connectivity state changed from %s to %s",
          nm_connectivity_state_to_string(priv->concheck_x[IS_IPv4].state),
          nm_connectivity_state_to_string(state));
    priv->concheck_x[IS_IPv4].state = state;

    _notify(self, IS_IPv4 ? PROP_IP4_CONNECTIVITY : PROP_IP6_CONNECTIVITY);

    if (priv->state == NM_DEVICE_STATE_ACTIVATED && !nm_device_sys_iface_state_is_external(self))
        _dev_l3_register_l3cds(self, priv->l3cfg, TRUE, NM_TERNARY_DEFAULT);
}

static const char *
nm_device_get_effective_ip_config_method(NMDevice *self, int addr_family)
{
    NMDeviceClass *klass;
    NMConnection  *connection = nm_device_get_applied_connection(self);
    const char    *method;
    const int      IS_IPv4 = NM_IS_IPv4(addr_family);

    g_return_val_if_fail(NM_IS_CONNECTION(connection), "" /* bogus */);

    method = nm_utils_get_ip_config_method(connection, addr_family);

    if ((IS_IPv4 && nm_streq(method, NM_SETTING_IP4_CONFIG_METHOD_AUTO))
        || (!IS_IPv4 && nm_streq(method, NM_SETTING_IP6_CONFIG_METHOD_AUTO))) {
        klass = NM_DEVICE_GET_CLASS(self);
        if (klass->get_auto_ip_config_method) {
            const char *auto_method;

            auto_method = klass->get_auto_ip_config_method(self, addr_family);
            if (auto_method)
                return auto_method;
        }
    }

    return method;
}

static void
concheck_handle_complete(NMDeviceConnectivityHandle *handle, GError *error)
{
    const int IS_IPv4 = NM_IS_IPv4(handle->addr_family);

    /* The moment we invoke the callback, we unlink it. It signals
     * that @handle is handled -- as far as the callee of callback
     * is concerned. */
    c_list_unlink(&handle->concheck_lst);

    if (handle->c_handle)
        nm_connectivity_check_cancel(handle->c_handle);

    if (handle->callback) {
        handle->callback(handle->self,
                         handle,
                         NM_DEVICE_GET_PRIVATE(handle->self)->concheck_x[IS_IPv4].state,
                         error,
                         handle->user_data);
    }

    g_slice_free(NMDeviceConnectivityHandle, handle);
}

static void
concheck_cb(NMConnectivity            *connectivity,
            NMConnectivityCheckHandle *c_handle,
            NMConnectivityState        state,
            gpointer                   user_data)
{
    _nm_unused gs_unref_object NMDevice *self_keep_alive = NULL;
    NMDevice                            *self;
    NMDevicePrivate                     *priv;
    NMDeviceConnectivityHandle          *handle;
    NMDeviceConnectivityHandle          *other_handle;
    gboolean                             handle_is_alive;
    gboolean                             allow_periodic_bump;
    gboolean                             any_periodic_before;
    gboolean                             any_periodic_after;
    guint64                              seq;

    handle = user_data;
    nm_assert(handle->c_handle == c_handle);
    nm_assert(NM_IS_DEVICE(handle->self));

    handle->c_handle = NULL;
    self             = handle->self;

    if (state == NM_CONNECTIVITY_CANCELLED) {
        /* the only place where we nm_connectivity_check_cancel(@c_handle), is
         * from inside concheck_handle_complete(). This is a recursive call,
         * nothing to do. */
        _LOGT(LOGD_CONCHECK,
              "connectivity: [IPv%c] complete check (seq:%llu, cancelled)",
              nm_utils_addr_family_to_char(handle->addr_family),
              (long long unsigned) handle->seq);
        return;
    }

    /* we keep NMConnectivity instance alive. It cannot be disposing. */
    nm_assert(state != NM_CONNECTIVITY_DISPOSING);

    self_keep_alive = g_object_ref(self);

    /* keep @self alive, while we invoke callbacks. */
    priv = NM_DEVICE_GET_PRIVATE(self);

    nm_assert(handle && c_list_contains(&priv->concheck_lst_head, &handle->concheck_lst));

    seq = handle->seq;

    _LOGT(LOGD_CONCHECK,
          "connectivity: [IPv%c] complete check (seq:%llu, state:%s)",
          nm_utils_addr_family_to_char(handle->addr_family),
          (long long unsigned) handle->seq,
          nm_connectivity_state_to_string(state));

    /* find out, if there are any periodic checks pending (either whether they
     * were scheduled before or after @handle. */
    any_periodic_before = FALSE;
    any_periodic_after  = FALSE;
    c_list_for_each_entry (other_handle, &priv->concheck_lst_head, concheck_lst) {
        if (other_handle->addr_family != handle->addr_family)
            continue;
        if (other_handle->is_periodic_bump_on_complete) {
            if (other_handle->seq < seq)
                any_periodic_before = TRUE;
            else if (other_handle->seq > seq)
                any_periodic_after = TRUE;
        }
    }
    if (NM_IN_SET(state, NM_CONNECTIVITY_ERROR)) {
        /* the request failed. We consider this periodic check only as completed if
         * this was a periodic check, and there are not checks pending (either
         * before or after this one).
         *
         * We allow_periodic_bump, if the request failed and there are
         * still other requests periodic pending. */
        allow_periodic_bump =
            handle->is_periodic_bump_on_complete && !any_periodic_before && !any_periodic_after;
    } else {
        /* the request succeeded. This marks the completion of a periodic check,
         * if this handle was periodic, or any previously scheduled one (that
         * we are going to complete below). */
        allow_periodic_bump = handle->is_periodic_bump_on_complete || any_periodic_before;
    }

    /* first update the new state, and emit signals. */
    concheck_update_state(self, handle->addr_family, state, allow_periodic_bump);

    handle_is_alive = FALSE;

    /* we might have invoked callbacks during concheck_update_state(). The caller might have
     * cancelled and thus destroyed @handle. We have to check whether handle is still alive,
     * by searching it in the list of alive handles.
     *
     * Also, we might want to complete all pending callbacks that were started before
     * @handle, as they are automatically obsoleted. */
check_handles:
    c_list_for_each_entry (other_handle, &priv->concheck_lst_head, concheck_lst) {
        if (other_handle->addr_family != handle->addr_family)
            continue;
        if (other_handle->seq >= seq) {
            /* it's not guaranteed that @handle is still in the list. It might already
             * be canceled while invoking callbacks for a previous other_handle.
             * If it is already cancelled, @handle is a dangling pointer.
             *
             * Since @seq is assigned uniquely and increasing, either @other_handle is
             * @handle (and thus, handle is alive), or it isn't. */
            if (other_handle == handle)
                handle_is_alive = TRUE;
            break;
        }

        nm_assert(other_handle != handle);

        if (!NM_IN_SET(state, NM_CONNECTIVITY_ERROR)) {
            /* we also want to complete handles that were started before the current
             * @handle. Their response is out-dated. */
            concheck_handle_complete(other_handle, NULL);

            /* we invoked callbacks, other handles might be cancelled and removed from the list.
             * Need to iterate the list from the start. */
            goto check_handles;
        }
    }

    if (!handle_is_alive) {
        /* We didn't find @handle in the list of alive handles. Thus, the handles
         * was cancelled while we were invoking events. Nothing to do, and don't
         * touch the dangling pointer. */
        return;
    }

    concheck_handle_complete(handle, NULL);
}

static NMDeviceConnectivityHandle *
concheck_start(NMDevice                    *self,
               int                          addr_family,
               NMDeviceConnectivityCallback callback,
               gpointer                     user_data,
               gboolean                     is_periodic)
{
    static guint64              seq_counter = 0;
    NMDevicePrivate            *priv;
    NMDeviceConnectivityHandle *handle;
    const char                 *ifname;

    g_return_val_if_fail(NM_IS_DEVICE(self), NULL);

    priv = NM_DEVICE_GET_PRIVATE(self);

    handle                               = g_slice_new0(NMDeviceConnectivityHandle);
    handle->seq                          = ++seq_counter;
    handle->self                         = self;
    handle->callback                     = callback;
    handle->user_data                    = user_data;
    handle->is_periodic                  = is_periodic;
    handle->is_periodic_bump             = is_periodic;
    handle->is_periodic_bump_on_complete = is_periodic;
    handle->addr_family                  = addr_family;

    c_list_link_tail(&priv->concheck_lst_head, &handle->concheck_lst);

    _LOGT(LOGD_CONCHECK,
          "connectivity: [IPv%c] start check (seq:%llu%s)",
          nm_utils_addr_family_to_char(addr_family),
          (long long unsigned) handle->seq,
          is_periodic ? ", periodic-check" : "");

    if (NM_IS_IPv4(addr_family) && !priv->concheck_rp_filter_checked) {
        if ((ifname = nm_device_get_ip_iface_from_platform(self))) {
            gboolean due_to_all;
            int      val;

            val = nm_platform_sysctl_ip_conf_get_rp_filter_ipv4(nm_device_get_platform(self),
                                                                ifname,
                                                                TRUE,
                                                                &due_to_all);
            if (val == 1) {
                _LOGW(LOGD_CONCHECK,
                      "connectivity: \"/proc/sys/net/ipv4/conf/%s/rp_filter\" is set to \"1\". "
                      "This might break connectivity checking for IPv4 on this device",
                      due_to_all ? "all" : ifname);
            }
        }

        /* we only check once per device. It's a warning after all.  */
        priv->concheck_rp_filter_checked = TRUE;
    }

    handle->c_handle = nm_connectivity_check_start(concheck_get_mgr(self),
                                                   handle->addr_family,
                                                   nm_device_get_platform(self),
                                                   nm_device_get_ip_ifindex(self),
                                                   nm_device_get_ip_iface(self),
                                                   concheck_cb,
                                                   handle);
    return handle;
}

NMDeviceConnectivityHandle *
nm_device_check_connectivity(NMDevice                    *self,
                             int                          addr_family,
                             NMDeviceConnectivityCallback callback,
                             gpointer                     user_data)
{
    if (!concheck_is_possible(self))
        return NULL;

    concheck_periodic_schedule_set(self, addr_family, CONCHECK_SCHEDULE_CHECK_EXTERNAL);
    return concheck_start(self, addr_family, callback, user_data, FALSE);
}

void
nm_device_check_connectivity_cancel(NMDeviceConnectivityHandle *handle)
{
    gs_free_error GError *cancelled_error = NULL;

    g_return_if_fail(handle);
    g_return_if_fail(NM_IS_DEVICE(handle->self));
    g_return_if_fail(!c_list_is_empty(&handle->concheck_lst));

    /* nobody has access to periodic handles, and cannot cancel
     * them externally. */
    nm_assert(!handle->is_periodic);

    nm_utils_error_set_cancelled(&cancelled_error, FALSE, "NMDevice");
    concheck_handle_complete(handle, cancelled_error);
}

NMConnectivityState
nm_device_get_connectivity_state(NMDevice *self, int addr_family)
{
    NMDevicePrivate *priv;

    g_return_val_if_fail(NM_IS_DEVICE(self), NM_CONNECTIVITY_UNKNOWN);

    priv = NM_DEVICE_GET_PRIVATE(self);

    switch (addr_family) {
    case AF_INET:
    case AF_INET6:
        return priv->concheck_x[NM_IS_IPv4(addr_family)].state;
    default:
        nm_assert(addr_family == AF_UNSPEC);
        return NM_MAX_WITH_CMP(nm_connectivity_state_cmp,
                               priv->concheck_x[0].state,
                               priv->concheck_x[1].state);
    }
}

/*****************************************************************************/

static SlaveInfo *
find_slave_info(NMDevice *self, NMDevice *slave)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    SlaveInfo       *info;

    c_list_for_each_entry (info, &priv->slaves, lst_slave) {
        if (info->slave == slave)
            return info;
    }
    return NULL;
}

static void
attach_port_done(NMDevice *self, NMDevice *slave, gboolean success)
{
    SlaveInfo *info;

    info = find_slave_info(self, slave);
    if (!info)
        return;

    info->slave_is_enslaved = success;

    nm_device_slave_notify_enslave(info->slave, success);

    /* Ensure the device's hardware address is up-to-date; it often changes
     * when slaves change.
     */
    nm_device_update_hw_address(self);

    /* Since slave devices don't have their own IP configuration,
     * set the MTU here.
     */
    _commit_mtu(slave);

    /* Restart IP configuration if we're waiting for slaves.  Do this
     * after updating the hardware address as IP config may need the
     * new address.
     */
    if (success)
        nm_device_activate_schedule_stage3_ip_config(self, FALSE);
}

static void
attach_port_cb(NMDevice *self, GError *error, gpointer user_data)
{
    NMDevice  *slave = user_data;
    SlaveInfo *info;

    if (nm_utils_error_is_cancelled(error))
        return;

    info = find_slave_info(self, slave);
    if (!info)
        return;

    nm_clear_g_cancellable(&info->cancellable);
    attach_port_done(self, slave, !error);
}

/**
 * nm_device_master_enslave_slave:
 * @self: the master device
 * @slave: the slave device to enslave
 * @connection: (nullable): the slave device's connection
 *
 * If @self is capable of enslaving other devices (ie it's a bridge, bond, team,
 * etc) then this function enslaves @slave.
 */
static void
nm_device_master_enslave_slave(NMDevice *self, NMDevice *slave, NMConnection *connection)
{
    SlaveInfo *info;
    NMTernary  success;
    gboolean   configure;

    g_return_if_fail(self);
    g_return_if_fail(slave);
    g_return_if_fail(NM_DEVICE_GET_CLASS(self)->attach_port);

    info = find_slave_info(self, slave);
    if (!info)
        return;

    if (info->slave_is_enslaved)
        success = TRUE;
    else {
        configure = (info->configure && connection != NULL);
        if (configure)
            g_return_if_fail(nm_device_get_state(slave) >= NM_DEVICE_STATE_DISCONNECTED);

        nm_clear_g_cancellable(&info->cancellable);
        info->cancellable = g_cancellable_new();
        success           = NM_DEVICE_GET_CLASS(self)->attach_port(self,
                                                         slave,
                                                         connection,
                                                         configure,
                                                         info->cancellable,
                                                         attach_port_cb,
                                                         slave);

        if (success == NM_TERNARY_DEFAULT)
            return;
    }

    attach_port_done(self, slave, success);
}

static void
detach_port_cb(NMDevice *self, GError *error, gpointer user_data)
{
    nm_auto_unref_object NMDevice *slave      = user_data;
    NMDevicePrivate               *slave_priv = NM_DEVICE_GET_PRIVATE(slave);

    nm_assert(slave_priv->port_detach_count > 0);

    if (--slave_priv->port_detach_count == 0) {
        if (slave_priv->state == NM_DEVICE_STATE_DEACTIVATING) {
            deactivate_ready(slave, slave_priv->port_detach_reason);
        }
    }
}

/**
 * nm_device_master_release_slave:
 * @self: the master device
 * @slave: the slave device to release
 * @configure: whether @self needs to actually release @slave
 * @release_type: whether @self needs to actually release slave
 *   and whether that is forced.
 * @reason: the state change reason for the @slave
 *
 * If @self is capable of enslaving other devices (ie it's a bridge, bond, team,
 * etc) then this function releases the previously enslaved @slave and/or
 * updates the state of @self and @slave to reflect its release.
 */
static void
nm_device_master_release_slave(NMDevice           *self,
                               NMDevice           *slave,
                               ReleaseSlaveType    release_type,
                               NMDeviceStateReason reason)
{
    NMDevicePrivate          *priv;
    NMDevicePrivate          *slave_priv;
    SlaveInfo                *info;
    gs_unref_object NMDevice *self_free  = NULL;
    gs_unref_object NMDevice *slave_free = NULL;

    g_return_if_fail(NM_DEVICE(self));
    g_return_if_fail(NM_DEVICE(slave));
    nm_assert(NM_IN_SET(release_type,
                        RELEASE_SLAVE_TYPE_NO_CONFIG,
                        RELEASE_SLAVE_TYPE_CONFIG,
                        RELEASE_SLAVE_TYPE_CONFIG_FORCE));
    g_return_if_fail(NM_DEVICE_GET_CLASS(self)->detach_port != NULL);

    info = find_slave_info(self, slave);

    _LOGT(LOGD_CORE,
          "master: release one slave " NM_HASH_OBFUSCATE_PTR_FMT "/%s %s%s",
          NM_HASH_OBFUSCATE_PTR(slave),
          nm_device_get_iface(slave),
          !info ? "(not registered)" : (info->slave_is_enslaved ? "(enslaved)" : "(not enslaved)"),
          release_type == RELEASE_SLAVE_TYPE_CONFIG_FORCE
              ? " (force-configure)"
              : (release_type == RELEASE_SLAVE_TYPE_CONFIG ? " (configure)" : "(no-config)"));

    if (!info)
        g_return_if_reached();

    priv       = NM_DEVICE_GET_PRIVATE(self);
    slave_priv = NM_DEVICE_GET_PRIVATE(slave);

    g_return_if_fail(self == slave_priv->master);
    nm_assert(slave == info->slave);
    nm_clear_g_cancellable(&info->cancellable);

    /* first, let subclasses handle the release ... */
    if (info->slave_is_enslaved || nm_device_sys_iface_state_is_external(slave)
        || release_type >= RELEASE_SLAVE_TYPE_CONFIG_FORCE) {
        NMTernary ret;

        ret = NM_DEVICE_GET_CLASS(self)->detach_port(self,
                                                     slave,
                                                     release_type >= RELEASE_SLAVE_TYPE_CONFIG,
                                                     NULL,
                                                     detach_port_cb,
                                                     g_object_ref(slave));
        if (ret == NM_TERNARY_DEFAULT) {
            slave_priv->port_detach_count++;
            slave_priv->port_detach_reason = reason;
        }
    }

    /* raise notifications about the release, including clearing is_enslaved. */
    nm_device_slave_notify_release(slave, reason, release_type);

    /* keep both alive until the end of the function.
     * Transfers ownership from slave_priv->master.  */
    nm_assert(self == slave_priv->master);
    self_free = g_steal_pointer(&slave_priv->master);

    nm_assert(slave == info->slave);
    slave_free = g_steal_pointer(&info->slave);

    c_list_unlink(&info->lst_slave);
    g_signal_handler_disconnect(slave, info->watch_id);
    nm_g_slice_free(info);

    if (c_list_is_empty(&priv->slaves)) {
        _active_connection_set_state_flags_full(self,
                                                0,
                                                NM_ACTIVATION_STATE_FLAG_MASTER_HAS_SLAVES);
    }

    /* Ensure the device's hardware address is up-to-date; it often changes
     * when slaves change.
     */
    nm_device_update_hw_address(self);
    nm_device_set_unmanaged_by_flags(slave,
                                     NM_UNMANAGED_IS_SLAVE,
                                     NM_UNMAN_FLAG_OP_FORGET,
                                     NM_DEVICE_STATE_REASON_REMOVED);
}

/*****************************************************************************/

/**
 * can_unmanaged_external_down:
 * @self: the device
 *
 * Check whether the device should stay NM_UNMANAGED_EXTERNAL_DOWN unless
 * IFF_UP-ed externally.
 */
static gboolean
can_unmanaged_external_down(NMDevice *self)
{
    return !NM_DEVICE_GET_PRIVATE(self)->nm_owned && nm_device_is_software(self);
}

static NMUnmanFlagOp
_dev_unmanaged_is_external_down(NMDevice *self, gboolean consider_can)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (consider_can && !NM_DEVICE_GET_CLASS(self)->can_unmanaged_external_down(self))
        return NM_UNMAN_FLAG_OP_FORGET;

    /* Manage externally-created software interfaces only when they are IFF_UP */
    if (priv->ifindex <= 0 || !priv->up
        || !(!c_list_is_empty(&priv->slaves)
             || nm_platform_link_can_assume(nm_device_get_platform(self), priv->ifindex)))
        return NM_UNMAN_FLAG_OP_SET_UNMANAGED;

    return NM_UNMAN_FLAG_OP_SET_MANAGED;
}

static void
_dev_unmanaged_check_external_down(NMDevice *self, gboolean only_if_unmanaged, gboolean now)
{
    NMUnmanFlagOp ext_flags;

    if (!nm_device_get_unmanaged_mask(self, NM_UNMANAGED_EXTERNAL_DOWN))
        return;

    if (only_if_unmanaged) {
        if (!nm_device_get_unmanaged_flags(self, NM_UNMANAGED_EXTERNAL_DOWN))
            return;
    }

    ext_flags = _dev_unmanaged_is_external_down(self, FALSE);
    if (now) {
        nm_device_set_unmanaged_by_flags(self,
                                         NM_UNMANAGED_EXTERNAL_DOWN,
                                         ext_flags,
                                         NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
    } else {
        nm_device_set_unmanaged_by_flags_queue(self,
                                               NM_UNMANAGED_EXTERNAL_DOWN,
                                               ext_flags,
                                               NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
    }
}

void
nm_device_update_dynamic_ip_setup(NMDevice *self, const char *reason)
{
    NMDevicePrivate *priv;

    g_return_if_fail(NM_IS_DEVICE(self));

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->state < NM_DEVICE_STATE_IP_CONFIG || priv->state > NM_DEVICE_STATE_ACTIVATED)
        return;

    _LOGD(LOGD_DEVICE, "restarting dynamic IP configuration (%s)", reason);

    g_hash_table_remove_all(priv->ip6_saved_properties);

    if (priv->ipdhcp_data_4.state != NM_DEVICE_IP_STATE_NONE)
        _dev_ipdhcpx_restart(self, AF_INET, FALSE);
    if (priv->ipdhcp_data_6.state != NM_DEVICE_IP_STATE_NONE)
        _dev_ipdhcpx_restart(self, AF_INET6, FALSE);

    if (priv->ipac6_data.ndisc) {
        /* FIXME: todo */
    }
    if (priv->ipshared_data_4.v4.dnsmasq_manager) {
        /* FIXME: todo */
    }
}

/*****************************************************************************/

static void
carrier_changed_notify(NMDevice *self, gboolean carrier)
{
    /* stub */
}

static void
carrier_changed(NMDevice *self, gboolean carrier)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->state <= NM_DEVICE_STATE_UNMANAGED)
        return;

    nm_device_recheck_available_connections(self);

    /* ignore-carrier devices ignore all carrier-down events */
    if (priv->ignore_carrier && !carrier)
        return;

    if (nm_device_is_master(self)) {
        if (carrier) {
            /* If needed, also resume IP configuration that is
             * waiting for carrier. */
            if (priv->state >= NM_DEVICE_STATE_IP_CONFIG
                && priv->state <= NM_DEVICE_STATE_ACTIVATED)
                nm_device_activate_schedule_stage3_ip_config(self, FALSE);
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
        gboolean recheck_auto_activate = FALSE;

        if (priv->state == NM_DEVICE_STATE_UNAVAILABLE) {
            nm_device_queue_state(self,
                                  NM_DEVICE_STATE_DISCONNECTED,
                                  NM_DEVICE_STATE_REASON_CARRIER);
        } else if (priv->state == NM_DEVICE_STATE_DISCONNECTED) {
            /* If the device is already in DISCONNECTED state without a carrier
             * (probably because it is tagged for carrier ignore) ensure that
             * when the carrier appears, auto connections are rechecked for
             * the device.
             */
            recheck_auto_activate = TRUE;
        }
        if (nm_manager_devcon_autoconnect_blocked_reason_set(
                nm_device_get_manager(self),
                self,
                NULL,
                NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_FAILED,
                FALSE))
            recheck_auto_activate = TRUE;

        if (recheck_auto_activate)
            nm_device_recheck_auto_activate_schedule(self);
    } else {
        if (priv->state == NM_DEVICE_STATE_UNAVAILABLE) {
            if (priv->queued_state.id && priv->queued_state.state >= NM_DEVICE_STATE_DISCONNECTED)
                queued_state_clear(self);
        } else {
            nm_device_queue_state(self,
                                  NM_DEVICE_STATE_UNAVAILABLE,
                                  NM_DEVICE_STATE_REASON_CARRIER);
        }
    }
}

static gboolean
carrier_disconnected_action_cb(gpointer user_data)
{
    NMDevice        *self = NM_DEVICE(user_data);
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    _LOGD(LOGD_DEVICE, "carrier: link disconnected (calling deferred action)");

    nm_clear_g_source_inst(&priv->carrier_defer_source);
    carrier_changed(self, FALSE);
    return G_SOURCE_CONTINUE;
}

static void
carrier_disconnected_action_cancel(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (nm_clear_g_source_inst(&priv->carrier_defer_source))
        _LOGD(LOGD_DEVICE, "carrier: link disconnected (canceling deferred action)");
}

void
nm_device_set_carrier(NMDevice *self, gboolean carrier)
{
    NMDevicePrivate *priv         = NM_DEVICE_GET_PRIVATE(self);
    NMDeviceState    state        = nm_device_get_state(self);
    gboolean         notify_flags = FALSE;

    if (priv->carrier == carrier)
        return;

    if (NM_FLAGS_ALL(priv->capabilities,
                     NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_NONSTANDARD_CARRIER)) {
        notify_flags = set_interface_flags(self, NM_DEVICE_INTERFACE_FLAG_CARRIER, carrier, FALSE);
    }

    priv->carrier = carrier;

    nm_gobject_notify_together(self, PROP_CARRIER, notify_flags ? PROP_INTERFACE_FLAGS : PROP_0);

    if (priv->carrier) {
        _LOGI(LOGD_DEVICE, "carrier: link connected");
        carrier_disconnected_action_cancel(self);
        NM_DEVICE_GET_CLASS(self)->carrier_changed_notify(self, carrier);
        carrier_changed(self, TRUE);

        if (priv->carrier_wait_source) {
            nm_device_remove_pending_action(self, NM_PENDING_ACTION_CARRIER_WAIT, FALSE);
            _carrier_wait_check_queued_act_request(self);
        }
    } else {
        if (priv->carrier_wait_source)
            nm_device_add_pending_action(self, NM_PENDING_ACTION_CARRIER_WAIT, FALSE);
        NM_DEVICE_GET_CLASS(self)->carrier_changed_notify(self, carrier);
        if (state <= NM_DEVICE_STATE_DISCONNECTED && !priv->queued_act_request) {
            _LOGD(LOGD_DEVICE, "carrier: link disconnected");
            carrier_disconnected_action_cancel(self);
            carrier_changed(self, FALSE);
        } else if (!priv->carrier_defer_source) {
            gint64 until_ms;
            gint64 now_ms;

            now_ms   = nm_utils_get_monotonic_timestamp_msec();
            until_ms = NM_MAX(now_ms + _get_carrier_wait_ms(self), priv->carrier_wait_until_msec);
            priv->carrier_defer_source =
                nm_g_timeout_add_source(until_ms - now_ms, carrier_disconnected_action_cb, self);
            _LOGD(LOGD_DEVICE,
                  "carrier: link disconnected (deferring action for %ld milliseconds)",
                  (long) (until_ms - now_ms));
        }
    }
}

static void
nm_device_set_carrier_from_platform(NMDevice *self)
{
    int ifindex;

    if (nm_device_has_capability(self, NM_DEVICE_CAP_CARRIER_DETECT)) {
        if (!nm_device_has_capability(self, NM_DEVICE_CAP_NONSTANDARD_CARRIER)
            && (ifindex = nm_device_get_ip_ifindex(self)) > 0) {
            nm_device_set_carrier(
                self,
                nm_platform_link_is_connected(nm_device_get_platform(self), ifindex));
        }
    } else {
        NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

        /* Fake online link when carrier detection is not available. */
        if (!priv->carrier) {
            priv->carrier = TRUE;
            _notify(self, PROP_CARRIER);
        }
    }
}

/*****************************************************************************/

static void
device_recheck_slave_status(NMDevice *self, const NMPlatformLink *plink)
{
    NMDevicePrivate                *priv = NM_DEVICE_GET_PRIVATE(self);
    NMDevice                       *master;
    nm_auto_nmpobj const NMPObject *plink_master_keep_alive = NULL;
    const NMPlatformLink           *plink_master;

    g_return_if_fail(plink);

    if (plink->master > 0) {
        master                  = nm_manager_get_device_by_ifindex(NM_MANAGER_GET, plink->master);
        plink_master            = nm_platform_link_get(nm_device_get_platform(self), plink->master);
        plink_master_keep_alive = nmp_object_ref(NMP_OBJECT_UP_CAST(plink_master));
    } else {
        if (priv->master_ifindex == 0)
            goto out;
        master       = NULL;
        plink_master = NULL;
    }

    if (master == NULL && plink_master
        && NM_IN_STRSET(plink_master->name, "ovs-system", "ovs-netdev")
        && plink_master->type == NM_LINK_TYPE_OPENVSWITCH) {
        _LOGD(LOGD_DEVICE, "the device claimed by openvswitch");
        goto out;
    }

    priv->master_ifindex = plink->master;

    if (priv->master) {
        if (plink->master > 0 && plink->master == nm_device_get_ifindex(priv->master)) {
            /* call add-slave again. We expect @self already to be added to
             * the master, but this also triggers a recheck-assume. */
            nm_device_master_add_slave(priv->master, self, FALSE);
            goto out;
        }

        nm_device_master_release_slave(priv->master,
                                       self,
                                       RELEASE_SLAVE_TYPE_NO_CONFIG,
                                       NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
    }

    if (master) {
        if (NM_DEVICE_GET_CLASS(master)->attach_port) {
            nm_device_master_add_slave(master, self, FALSE);
        } else {
            _LOGD(LOGD_DEVICE,
                  "enslaved to non-master-type device %s; ignoring",
                  nm_device_get_iface(master));
        }
        goto out;
    }

    if (plink->master) {
        _LOGD(LOGD_DEVICE,
              "enslaved to unknown device %d (%s%s%s)",
              plink->master,
              NM_PRINT_FMT_QUOTED(plink_master, "\"", plink_master->name, "\"", "??"));
        if (!priv->ifindex_changed_id) {
            priv->ifindex_changed_id = g_signal_connect(nm_device_get_manager(self),
                                                        NM_MANAGER_DEVICE_IFINDEX_CHANGED,
                                                        G_CALLBACK(device_ifindex_changed_cb),
                                                        self);
        }
    }

    return;

out:
    nm_clear_g_signal_handler(nm_device_get_manager(self), &priv->ifindex_changed_id);
}

static void
device_ifindex_changed_cb(NMManager *manager, NMDevice *device_changed, NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    g_return_if_fail(priv->master_ifindex > 0);

    if (priv->master_ifindex != nm_device_get_ifindex(device_changed))
        return;

    _LOGD(LOGD_DEVICE,
          "master %s with ifindex %d appeared",
          nm_device_get_iface(device_changed),
          nm_device_get_ifindex(device_changed));
    if (!priv->device_link_changed_id)
        priv->device_link_changed_id = g_idle_add((GSourceFunc) device_link_changed, self);
}

static void
device_update_interface_flags(NMDevice *self, const NMPlatformLink *plink)
{
    NMDevicePrivate       *priv  = NM_DEVICE_GET_PRIVATE(self);
    NMDeviceInterfaceFlags flags = NM_DEVICE_INTERFACE_FLAG_NONE;

    if (plink && NM_FLAGS_HAS(plink->n_ifi_flags, IFF_UP))
        flags |= NM_DEVICE_INTERFACE_FLAG_UP;
    if (plink && NM_FLAGS_HAS(plink->n_ifi_flags, IFF_LOWER_UP))
        flags |= NM_DEVICE_INTERFACE_FLAG_LOWER_UP;
    if (plink && NM_FLAGS_HAS(plink->n_ifi_flags, IFF_PROMISC))
        flags |= NM_DEVICE_INTERFACE_FLAG_PROMISC;

    if (NM_FLAGS_ALL(priv->capabilities,
                     NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_NONSTANDARD_CARRIER)) {
        if (priv->carrier)
            flags |= NM_DEVICE_INTERFACE_FLAG_CARRIER;
    } else {
        if (plink && NM_FLAGS_HAS(plink->n_ifi_flags, IFF_LOWER_UP))
            flags |= NM_DEVICE_INTERFACE_FLAG_CARRIER;
    }

    set_interface_flags_full(self,
                             NM_DEVICE_INTERFACE_FLAG_UP | NM_DEVICE_INTERFACE_FLAG_LOWER_UP
                                 | NM_DEVICE_INTERFACE_FLAG_CARRIER
                                 | NM_DEVICE_INTERFACE_FLAG_PROMISC,
                             flags,
                             TRUE);
}

/*
 * Returns the reason for managing a device. The suffix "external" indicates
 * that the reason mainly depends on whether we want to make the device
 * sys-iface-state=external or not.
 */
NMDeviceStateReason
nm_device_get_manage_reason_external(NMDevice *self)
{
    NMDeviceStateReason reason;

    /* By default we return reason NOW_MANAGED, which makes the device fully
     * managed by NM (sys-iface-state=managed). */
    reason = NM_DEVICE_STATE_REASON_NOW_MANAGED;

    /* If the device is an external-down candidate but no longer has the flag
     * set, then the device is an externally created interface that previously
     * had no addresses or no controller and now has.
     * We need to set CONNECTION_ASSUMED as the reason, so that the device
     * is managed but is not touched by NM (sys-iface-state=external). */
    if (nm_device_get_unmanaged_mask(self, NM_UNMANAGED_EXTERNAL_DOWN)
        && !nm_device_get_unmanaged_flags(self, NM_UNMANAGED_EXTERNAL_DOWN)) {
        /* user-udev overwrites external-down, so we only assume the device
         * when it is a external-down candidate which is not managed via udev. */
        if (!nm_device_get_unmanaged_mask(self, NM_UNMANAGED_USER_UDEV)) {
            reason = NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED;
        }
    }

    return reason;
}

static gboolean
device_link_changed(gpointer user_data)
{
    NMDevice                       *self              = user_data;
    NMDeviceClass                  *klass             = NM_DEVICE_GET_CLASS(self);
    NMDevicePrivate                *priv              = NM_DEVICE_GET_PRIVATE(self);
    gboolean                        ip_ifname_changed = FALSE;
    nm_auto_nmpobj const NMPObject *pllink_keep_alive = NULL;
    const NMPlatformLink           *pllink;
    const char                     *str;
    int                             ifindex;
    gboolean                        was_up;
    gboolean                        update_unmanaged_specs = FALSE;
    gboolean                        got_hw_addr            = FALSE, had_hw_addr;
    gboolean                        seen_down              = priv->device_link_changed_down;

    priv->device_link_changed_id   = 0;
    priv->device_link_changed_down = FALSE;

    ifindex = nm_device_get_ifindex(self);
    if (ifindex <= 0)
        return G_SOURCE_REMOVE;
    pllink = nm_platform_link_get(nm_device_get_platform(self), ifindex);
    if (!pllink)
        return G_SOURCE_REMOVE;

    pllink_keep_alive = nmp_object_ref(NMP_OBJECT_UP_CAST(pllink));

    str = nm_platform_link_get_udi(nm_device_get_platform(self), pllink->ifindex);
    if (!nm_streq0(str, priv->udi)) {
        g_free(priv->udi);
        priv->udi = g_strdup(str);
        _notify(self, PROP_UDI);
    }

    str = nm_platform_link_get_path(nm_device_get_platform(self), pllink->ifindex);
    if (!nm_streq0(str, priv->path)) {
        g_free(priv->path);
        priv->path = g_strdup(str);
        _notify(self, PROP_PATH);
    }

    if (!nm_streq0(pllink->driver, priv->driver)) {
        g_free(priv->driver);
        priv->driver = g_strdup(pllink->driver);
        _notify(self, PROP_DRIVER);
    }

    _set_mtu(self, pllink->mtu);

    if (ifindex == nm_device_get_ip_ifindex(self))
        _stats_update_counters_from_pllink(self, pllink);

    had_hw_addr = (priv->hw_addr != NULL);
    nm_device_update_hw_address(self);
    got_hw_addr = (!had_hw_addr && priv->hw_addr);
    nm_device_update_permanent_hw_address(self, FALSE);

    if (pllink->name[0] && !nm_streq(priv->iface, pllink->name)) {
        _LOGI(LOGD_DEVICE,
              "interface index %d renamed iface from '%s' to '%s'",
              priv->ifindex,
              priv->iface,
              pllink->name);
        g_free(priv->iface_);
        priv->iface_ = g_strdup(pllink->name);

        /* If the device has no explicit ip_iface, then changing iface changes ip_iface too. */
        ip_ifname_changed = !priv->ip_iface;

        if (!nm_device_get_unmanaged_flags(self, NM_UNMANAGED_PLATFORM_INIT)) {
            /* Since the interface name changed, we need to re-evaluate the
             * user settings specs. */
            update_unmanaged_specs = TRUE;
        }

        _notify(self, PROP_IFACE);
        if (ip_ifname_changed)
            update_prop_ip_iface(self);

        /* Re-match available connections against the new interface name */
        nm_device_recheck_available_connections(self);

        /* Let any connections that use the new interface name have a chance
         * to auto-activate on the device.
         */
        nm_device_recheck_auto_activate_schedule(self);
    }

    if (priv->ipac6_data.ndisc && pllink->inet6_token.id) {
        if (nm_ndisc_set_iid(priv->ipac6_data.ndisc, pllink->inet6_token, TRUE))
            _LOGD(LOGD_DEVICE, "IPv6 tokenized identifier present on device %s", priv->iface);
    }

    /* Update carrier from link event if applicable. */
    if (nm_device_has_capability(self, NM_DEVICE_CAP_CARRIER_DETECT)
        && !nm_device_has_capability(self, NM_DEVICE_CAP_NONSTANDARD_CARRIER))
        nm_device_set_carrier(self, pllink->connected);

    device_update_interface_flags(self, pllink);

    klass->link_changed(self, pllink);

    /* Update DHCP, etc, if needed */
    if (ip_ifname_changed)
        nm_device_update_dynamic_ip_setup(self, "IP interface changed");

    was_up   = priv->up;
    priv->up = NM_FLAGS_HAS(pllink->n_ifi_flags, IFF_UP);

    if (pllink->initialized && nm_device_get_unmanaged_flags(self, NM_UNMANAGED_PLATFORM_INIT)) {
        nm_device_set_unmanaged_by_user_udev(self);
        nm_device_set_unmanaged_by_user_conf(self);

        nm_device_set_unmanaged_by_flags_queue(self,
                                               NM_UNMANAGED_PLATFORM_INIT,
                                               NM_UNMAN_FLAG_OP_SET_MANAGED,
                                               nm_device_get_manage_reason_external(self));
    }

    _dev_unmanaged_check_external_down(self, FALSE, FALSE);

    device_recheck_slave_status(self, pllink);

    if (priv->up && (!was_up || seen_down)) {
        /* the link was down and just came up. That happens for example, while changing MTU.
         * We must restore IP configuration.
         *
         * FIXME(l3cfg): when NML3Cfg notices that the device goes down and up, then
         * it should automatically schedule a REAPPLY commit -- provided that the current
         * commit-type is >= UPDATE. The idea is to move logic away from NMDevice
         * so that it theoretically would also work for NMVpnConnection (although,
         * NMVpnConnection should become like a regular device, akin to NMDevicePpp).
         */
        if (priv->state >= NM_DEVICE_STATE_IP_CONFIG && priv->state <= NM_DEVICE_STATE_ACTIVATED
            && !nm_device_sys_iface_state_is_external(self))
            nm_device_l3cfg_commit(self, NM_L3_CFG_COMMIT_TYPE_REAPPLY, FALSE);

        /* If the device is active without a carrier (probably because it is
         * tagged for carrier ignore) ensure that when the carrier appears we
         * renew DHCP leases and such.
         */
        if (priv->state == NM_DEVICE_STATE_ACTIVATED) {
            nm_device_update_dynamic_ip_setup(self, "interface got carrier");
        }
    }

    if (update_unmanaged_specs)
        nm_device_set_unmanaged_by_user_settings(self, FALSE);

    if (got_hw_addr && !priv->up && nm_device_get_state(self) == NM_DEVICE_STATE_UNAVAILABLE) {
        /*
         * If the device is UNAVAILABLE, any previous try to
         * bring it up probably has failed because of the
         * invalid hardware address; try again.
         */
        nm_device_bring_up(self);
        nm_device_queue_recheck_available(self,
                                          NM_DEVICE_STATE_REASON_NONE,
                                          NM_DEVICE_STATE_REASON_NONE);
    }

    return G_SOURCE_REMOVE;
}

static gboolean
device_ip_link_changed(gpointer user_data)
{
    NMDevice             *self = user_data;
    NMDevicePrivate      *priv = NM_DEVICE_GET_PRIVATE(self);
    const NMPlatformLink *pllink;
    const char           *ip_iface;

    priv->device_ip_link_changed_id = 0;

    if (priv->ip_ifindex <= 0)
        return G_SOURCE_REMOVE;

    nm_assert(priv->ip_iface);

    pllink = nm_platform_link_get(nm_device_get_platform(self), priv->ip_ifindex);
    if (!pllink)
        return G_SOURCE_REMOVE;

    if (priv->ifindex <= 0 && pllink->mtu)
        _set_mtu(self, pllink->mtu);

    _stats_update_counters_from_pllink(self, pllink);

    ip_iface = pllink->name;

    if (!ip_iface[0])
        return FALSE;

    if (!nm_streq(priv->ip_iface, ip_iface)) {
        _LOGI(LOGD_DEVICE,
              "ip-ifname: interface index %d renamed ip_iface (%d) from '%s' to '%s'",
              priv->ifindex,
              priv->ip_ifindex,
              priv->ip_iface,
              ip_iface);
        g_free(priv->ip_iface_);
        priv->ip_iface_ = g_strdup(ip_iface);
        update_prop_ip_iface(self);

        nm_device_update_dynamic_ip_setup(self, "interface renamed");
    }

    return G_SOURCE_REMOVE;
}

static void
link_changed_cb(NMPlatform     *platform,
                int             obj_type_i,
                int             ifindex,
                NMPlatformLink *pllink,
                int             change_type_i,
                NMDevice       *self)
{
    const NMPlatformSignalChangeType change_type = change_type_i;
    NMDevicePrivate                 *priv;

    if (change_type != NM_PLATFORM_SIGNAL_CHANGED)
        return;

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (ifindex == nm_device_get_ifindex(self)) {
        if (!(pllink->n_ifi_flags & IFF_UP))
            priv->device_link_changed_down = TRUE;
        if (!priv->device_link_changed_id) {
            priv->device_link_changed_id = g_idle_add(device_link_changed, self);
            _LOGD(LOGD_DEVICE, "queued link change for ifindex %d", ifindex);
        }
    } else if (ifindex == nm_device_get_ip_ifindex(self)) {
        if (!priv->device_ip_link_changed_id) {
            priv->device_ip_link_changed_id = g_idle_add(device_ip_link_changed, self);
            _LOGD(LOGD_DEVICE, "queued link change for ip-ifindex %d", ifindex);
        }
    }
}

/*****************************************************************************/

static void
link_changed(NMDevice *self, const NMPlatformLink *pllink)
{
    /* stub implementation of virtual function to allow subclasses to chain up. */
}

static gboolean
link_type_compatible(NMDevice *self, NMLinkType link_type, gboolean *out_compatible, GError **error)
{
    NMDeviceClass *klass;
    NMLinkType     device_type;
    guint          i = 0;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    klass = NM_DEVICE_GET_CLASS(self);

    if (!klass->link_types) {
        NM_SET_OUT(out_compatible, FALSE);
        g_set_error_literal(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_FAILED,
                            "Device does not support platform links");
        return FALSE;
    }

    device_type = self->_priv->link_type;
    if (device_type > NM_LINK_TYPE_UNKNOWN && device_type != link_type) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_FAILED,
                    "Needed link type 0x%x does not match the platform link type 0x%X",
                    device_type,
                    link_type);
        return FALSE;
    }

    for (i = 0; klass->link_types[i] > NM_LINK_TYPE_UNKNOWN; i++) {
        if (klass->link_types[i] == link_type)
            return TRUE;
        if (klass->link_types[i] == NM_LINK_TYPE_ANY)
            return TRUE;
    }

    NM_SET_OUT(out_compatible, FALSE);
    g_set_error(error,
                NM_DEVICE_ERROR,
                NM_DEVICE_ERROR_FAILED,
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
nm_device_realize_start(NMDevice             *self,
                        const NMPlatformLink *plink,
                        gboolean              assume_state_guess_assume,
                        const char           *assume_state_connection_uuid,
                        gboolean              set_nm_owned,
                        NMUnmanFlagOp         unmanaged_user_explicit,
                        gboolean             *out_compatible,
                        GError              **error)
{
    nm_auto_nmpobj const NMPObject *plink_keep_alive = NULL;

    nm_assert(!plink || NMP_OBJECT_GET_TYPE(NMP_OBJECT_UP_CAST(plink)) == NMP_OBJECT_TYPE_LINK);

    NM_SET_OUT(out_compatible, TRUE);

    if (plink) {
        if (!nm_streq0(nm_device_get_iface(self), plink->name)) {
            NM_SET_OUT(out_compatible, FALSE);
            g_set_error_literal(error,
                                NM_DEVICE_ERROR,
                                NM_DEVICE_ERROR_FAILED,
                                "Device interface name does not match platform link");
            return FALSE;
        }

        if (!link_type_compatible(self, plink->type, out_compatible, error))
            return FALSE;

        plink_keep_alive = nmp_object_ref(NMP_OBJECT_UP_CAST(plink));
    }

    realize_start_setup(self,
                        plink,
                        assume_state_guess_assume,
                        assume_state_connection_uuid,
                        set_nm_owned,
                        unmanaged_user_explicit,
                        FALSE);
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
nm_device_create_and_realize(NMDevice     *self,
                             NMConnection *connection,
                             NMDevice     *parent,
                             GError      **error)
{
    nm_auto_nmpobj const NMPObject *plink_keep_alive = NULL;
    NMDevicePrivate                *priv             = NM_DEVICE_GET_PRIVATE(self);
    const NMPlatformLink           *plink;
    gboolean                        nm_owned;

    /* Must be set before device is realized */
    plink    = nm_platform_link_get_by_ifname(nm_device_get_platform(self), priv->iface);
    nm_owned = !plink || !link_type_compatible(self, plink->type, NULL, NULL);
    _LOGD(LOGD_DEVICE, "create (is %snm-owned)", nm_owned ? "" : "not ");

    plink = NULL;
    /* Create any resources the device needs */
    if (NM_DEVICE_GET_CLASS(self)->create_and_realize) {
        if (!NM_DEVICE_GET_CLASS(self)->create_and_realize(self, connection, parent, &plink, error))
            return FALSE;
        if (plink) {
            nm_assert(NMP_OBJECT_GET_TYPE(NMP_OBJECT_UP_CAST(plink)) == NMP_OBJECT_TYPE_LINK);
            plink_keep_alive = nmp_object_ref(NMP_OBJECT_UP_CAST(plink));
        }
    }

    priv->nm_owned = nm_owned;

    realize_start_setup(self,
                        plink,
                        FALSE, /* assume_state_guess_assume */
                        NULL,  /* assume_state_connection_uuid */
                        FALSE,
                        NM_UNMAN_FLAG_OP_FORGET,
                        TRUE);
    nm_device_realize_finish(self, plink);

    if (nm_device_get_managed(self, FALSE)) {
        nm_device_state_changed(self,
                                NM_DEVICE_STATE_UNAVAILABLE,
                                NM_DEVICE_STATE_REASON_NOW_MANAGED);
    }
    return TRUE;
}

static gboolean
can_update_from_platform_link(NMDevice *self, const NMPlatformLink *plink)
{
    return TRUE;
}

void
nm_device_update_from_platform_link(NMDevice *self, const NMPlatformLink *plink)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    const char      *str;
    gboolean         ifindex_changed;
    guint32          mtu;

    if (!NM_DEVICE_GET_CLASS(self)->can_update_from_platform_link(self, plink))
        return;

    g_return_if_fail(plink == NULL || link_type_compatible(self, plink->type, NULL, NULL));

    str = plink ? nm_platform_link_get_udi(nm_device_get_platform(self), plink->ifindex) : NULL;
    if (!nm_streq0(str, priv->udi)) {
        g_free(priv->udi);
        priv->udi = g_strdup(str);
        _notify(self, PROP_UDI);
    }

    str = plink ? nm_platform_link_get_path(nm_device_get_platform(self), plink->ifindex) : NULL;
    if (!nm_streq0(str, priv->path)) {
        g_free(priv->path);
        priv->path = g_strdup(str);
        _notify(self, PROP_PATH);
    }

    if (plink && !nm_str_is_empty(plink->name) && nm_strdup_reset(&priv->iface_, plink->name))
        _notify(self, PROP_IFACE);

    str = plink ? plink->driver : NULL;
    if (!nm_streq0(str, priv->driver)) {
        g_free(priv->driver);
        priv->driver = g_strdup(str);
        _notify(self, PROP_DRIVER);
    }

    if (plink) {
        priv->up = NM_FLAGS_HAS(plink->n_ifi_flags, IFF_UP);
        if (plink->ifindex == nm_device_get_ip_ifindex(self))
            _stats_update_counters_from_pllink(self, plink);
    } else {
        priv->up = FALSE;
    }

    mtu = plink ? plink->mtu : 0;
    _set_mtu(self, mtu);

    ifindex_changed = _set_ifindex(self, plink ? plink->ifindex : 0, FALSE);

    nm_device_update_hw_address(self);
    nm_device_update_permanent_hw_address(self, FALSE);

    if (ifindex_changed)
        NM_DEVICE_GET_CLASS(self)->link_changed(self, plink);

    device_update_interface_flags(self, plink);
}

/*****************************************************************************/

static void
sriov_op_start(NMDevice *self, SriovOp *op)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_assert(!priv->sriov.pending);

    op->cancellable     = g_cancellable_new();
    op->device          = g_object_ref(self);
    priv->sriov.pending = op;

    nm_platform_link_set_sriov_params_async(nm_device_get_platform(self),
                                            priv->ifindex,
                                            op->num_vfs,
                                            op->autoprobe,
                                            sriov_op_cb,
                                            op,
                                            op->cancellable);
}

static void
sriov_op_cb(GError *error, gpointer user_data)
{
    SriovOp                  *op   = user_data;
    gs_unref_object NMDevice *self = op->device;
    NMDevicePrivate          *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_assert(op == priv->sriov.pending);

    g_clear_object(&op->cancellable);

    if (op->callback)
        op->callback(error, op->callback_data);

    priv->sriov.pending = NULL;
    nm_g_slice_free(op);

    if (priv->sriov.next) {
        sriov_op_start(self, g_steal_pointer(&priv->sriov.next));
    }
}

static void
sriov_op_queue_op(NMDevice *self, SriovOp *op)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->sriov.next) {
        SriovOp *op_next = g_steal_pointer(&priv->sriov.next);

        priv->sriov.next = op;

        /* Cancel the next operation immediately */
        if (op_next->callback) {
            gs_free_error GError *error = NULL;

            nm_utils_error_set_cancelled(&error, FALSE, NULL);
            op_next->callback(error, op_next->callback_data);
        }

        nm_g_slice_free(op_next);
        return;
    }

    if (priv->sriov.pending) {
        priv->sriov.next = op;
        g_cancellable_cancel(priv->sriov.pending->cancellable);
        return;
    }

    if (op)
        sriov_op_start(self, op);
}

static void
sriov_op_queue(NMDevice               *self,
               guint                   num_vfs,
               NMOptionBool            autoprobe,
               NMPlatformAsyncCallback callback,
               gpointer                callback_data)
{
    SriovOp *op;

    /* We usually never want to cancel an async write operation, unless it's superseded
     * by a newer operation (that resets the state). That is, because we need to ensure
     * that we never end up doing two concurrent writes (since we write on a background
     * thread, that would be unordered/racy).
     * Of course, since we queue requests only per-device, when devices get renamed we
     * might end up writing the same sysctl concurrently still. But that's really
     * unlikely, and don't rename after udev completes!
     *
     * The "next" operation is not yet even started. It can be replaced/canceled right away
     * when a newer request comes.
     * The "pending" operation is currently ongoing, and we may cancel it if
     * we have a follow-up operation (queued in "next"). Unless we have a such
     * a newer request, we cannot cancel it!
     *
     * FIXME(shutdown): However, during shutdown we don't have a follow-up write request to cancel
     * this operation and we have to give it at least some time to complete. The solution is that
     * we register a way to abort the last call during shutdown, and after NM_SHUTDOWN_TIMEOUT_MAX_MSEC
     * grace period we pull the plug and cancel it. */

    op  = g_slice_new(SriovOp);
    *op = (SriovOp){
        .num_vfs       = num_vfs,
        .autoprobe     = autoprobe,
        .callback      = callback,
        .callback_data = callback_data,
    };
    sriov_op_queue_op(self, op);
}

static void
device_init_static_sriov_num_vfs(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->ifindex > 0 && nm_device_has_capability(self, NM_DEVICE_CAP_SRIOV)) {
        int num_vfs;

        num_vfs = nm_config_data_get_device_config_int64_by_device(
            NM_CONFIG_GET_DATA,
            NM_CONFIG_KEYFILE_KEY_DEVICE_SRIOV_NUM_VFS,
            self,
            10,
            0,
            G_MAXINT32,
            -1,
            -1);
        if (num_vfs >= 0)
            sriov_op_queue(self, num_vfs, NM_OPTION_BOOL_DEFAULT, NULL, NULL);
    }
}

static void
config_changed(NMConfig           *config,
               NMConfigData       *config_data,
               NMConfigChangeFlags changes,
               NMConfigData       *old_data,
               NMDevice           *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->state <= NM_DEVICE_STATE_DISCONNECTED || priv->state >= NM_DEVICE_STATE_ACTIVATED) {
        priv->ignore_carrier = nm_config_data_get_ignore_carrier_by_device(config_data, self);
        if (NM_FLAGS_HAS(changes, NM_CONFIG_CHANGE_VALUES)
            && !nm_device_get_applied_setting(self, NM_TYPE_SETTING_SRIOV))
            device_init_static_sriov_num_vfs(self);
    }
}

static void
realize_start_notify(NMDevice *self, const NMPlatformLink *pllink)
{
    /* the default implementation of realize_start_notify() just calls
     * link_changed() -- which by default does nothing. */
    NM_DEVICE_GET_CLASS(self)->link_changed(self, pllink);
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
 * @force_platform_init: if TRUE the platform-init unmanaged flag is
 *    forcefully cleared.
 *
 * Update the device from backing resource properties (like hardware
 * addresses, carrier states, driver/firmware info, etc).  This function
 * should only change properties for this device, and should not perform
 * any tasks that affect other interfaces (like master/slave or parent/child
 * stuff).
 */
static void
realize_start_setup(NMDevice             *self,
                    const NMPlatformLink *plink,
                    gboolean              assume_state_guess_assume,
                    const char           *assume_state_connection_uuid,
                    gboolean              set_nm_owned,
                    NMUnmanFlagOp         unmanaged_user_explicit,
                    gboolean              force_platform_init)
{
    NMDevicePrivate     *priv;
    NMDeviceClass       *klass;
    NMPlatform          *platform;
    NMDeviceCapabilities capabilities = 0;
    NMConfig            *config;
    guint                refresh_rate_ms;
    gboolean             unmanaged;

    /* plink is a NMPlatformLink type, however, we require it to come from the platform
     * cache (where else would it come from?). */
    nm_assert(!plink || NMP_OBJECT_GET_TYPE(NMP_OBJECT_UP_CAST(plink)) == NMP_OBJECT_TYPE_LINK);

    g_return_if_fail(NM_IS_DEVICE(self));

    priv = NM_DEVICE_GET_PRIVATE(self);

    /* The device should not be realized */
    g_return_if_fail(!priv->real);
    g_return_if_fail(nm_device_get_unmanaged_flags(self, NM_UNMANAGED_PLATFORM_INIT));
    g_return_if_fail(priv->ip_ifindex <= 0);
    g_return_if_fail(priv->ip_iface == NULL);

    _LOGD(LOGD_DEVICE,
          "start setup of %s, kernel ifindex %d",
          G_OBJECT_TYPE_NAME(self),
          plink ? plink->ifindex : 0);

    klass    = NM_DEVICE_GET_CLASS(self);
    platform = nm_device_get_platform(self);

    /* Balanced by a thaw in nm_device_realize_finish() */
    g_object_freeze_notify(G_OBJECT(self));

    priv->mtu_source      = NM_DEVICE_MTU_SOURCE_NONE;
    priv->mtu_initial     = 0;
    priv->ip6_mtu_initial = 0;
    priv->ip6_mtu         = 0;
    _set_mtu(self, 0);

    _assume_state_set(self, assume_state_guess_assume, assume_state_connection_uuid);

    nm_device_sys_iface_state_set(self, NM_DEVICE_SYS_IFACE_STATE_EXTERNAL);

    if (plink)
        nm_device_update_from_platform_link(self, plink);

    if (priv->ifindex > 0) {
        priv->physical_port_id = nm_platform_link_get_physical_port_id(platform, priv->ifindex);
        _notify(self, PROP_PHYSICAL_PORT_ID);

        priv->dev_id = nm_platform_link_get_dev_id(platform, priv->ifindex);

        if (nm_platform_link_is_software(platform, priv->ifindex))
            capabilities |= NM_DEVICE_CAP_IS_SOFTWARE;

        _set_mtu(self, nm_platform_link_get_mtu(platform, priv->ifindex));

        nm_platform_link_get_driver_info(platform,
                                         priv->ifindex,
                                         NULL,
                                         &priv->driver_version,
                                         &priv->firmware_version);
        if (priv->driver_version)
            _notify(self, PROP_DRIVER_VERSION);
        if (priv->firmware_version)
            _notify(self, PROP_FIRMWARE_VERSION);

        if (nm_platform_link_supports_sriov(platform, priv->ifindex))
            capabilities |= NM_DEVICE_CAP_SRIOV;
    }

    if (klass->get_generic_capabilities)
        capabilities |= klass->get_generic_capabilities(self);

    _add_capabilities(self, capabilities);

    if (!priv->nm_owned && set_nm_owned && nm_device_is_software(self)) {
        priv->nm_owned = TRUE;
        _LOGD(LOGD_DEVICE, "set nm-owned from state file");
    }

    if (!priv->udi) {
        /* Use a placeholder UDI until we get a real one */
        if (priv->udi_id == 0) {
            static guint64 udi_id_counter = 0;

            priv->udi_id = ++udi_id_counter;
        }
        priv->udi = g_strdup_printf("/virtual/device/placeholder/%" G_GUINT64_FORMAT, priv->udi_id);
        _notify(self, PROP_UDI);
    }

    nm_device_update_hw_address(self);
    nm_device_update_initial_hw_address(self);
    nm_device_update_permanent_hw_address(self, FALSE);

    /* Note: initial hardware address must be read before calling get_ignore_carrier() */
    config = nm_config_get();
    priv->ignore_carrier =
        nm_config_data_get_ignore_carrier_by_device(nm_config_get_data(config), self);
    if (!priv->config_changed_id) {
        priv->config_changed_id = g_signal_connect(config,
                                                   NM_CONFIG_SIGNAL_CONFIG_CHANGED,
                                                   G_CALLBACK(config_changed),
                                                   self);
    }

    nm_device_set_carrier_from_platform(self);

    nm_assert(!priv->stats.timeout_source);
    refresh_rate_ms = _stats_refresh_rate_real(priv->stats.refresh_rate_ms);
    if (refresh_rate_ms > 0) {
        priv->stats.timeout_source =
            nm_g_timeout_add_source(refresh_rate_ms, _stats_timeout_cb, self);
    }

    klass->realize_start_notify(self, plink);

    nm_assert(!nm_device_get_unmanaged_mask(self, NM_UNMANAGED_USER_EXPLICIT));
    nm_device_set_unmanaged_flags(self, NM_UNMANAGED_USER_EXPLICIT, unmanaged_user_explicit);

    /* Do not manage externally created software devices until they are IFF_UP
     * or have IP addressing */
    nm_device_set_unmanaged_flags(self,
                                  NM_UNMANAGED_EXTERNAL_DOWN,
                                  _dev_unmanaged_is_external_down(self, TRUE));

    nm_device_set_unmanaged_by_user_udev(self);
    nm_device_set_unmanaged_by_user_conf(self);

    unmanaged = plink && !plink->initialized && !force_platform_init;

    nm_device_set_unmanaged_flags(self, NM_UNMANAGED_PLATFORM_INIT, unmanaged);
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
nm_device_realize_finish(NMDevice *self, const NMPlatformLink *plink)
{
    NMDevicePrivate *priv;

    g_return_if_fail(NM_IS_DEVICE(self));
    g_return_if_fail(!plink || link_type_compatible(self, plink->type, NULL, NULL));

    priv = NM_DEVICE_GET_PRIVATE(self);

    g_return_if_fail(!priv->real);

    if (plink)
        device_recheck_slave_status(self, plink);

    priv->real = TRUE;
    _notify(self, PROP_REAL);

    nm_device_recheck_available_connections(self);

    /* Balanced by a freeze in realize_start_setup(). */
    g_object_thaw_notify(G_OBJECT(self));
}

static void
unrealize_notify(NMDevice *self)
{
    /* Stub implementation for unrealize_notify(). It does nothing,
     * but allows derived classes to uniformly invoke the parent
     * implementation. */
}

static gboolean
available_connections_check_delete_unrealized_on_idle(gpointer user_data)
{
    NMDevice        *self = user_data;
    NMDevicePrivate *priv;

    g_return_val_if_fail(NM_IS_DEVICE(self), G_SOURCE_REMOVE);

    priv = NM_DEVICE_GET_PRIVATE(self);

    priv->check_delete_unrealized_id = 0;

    if (g_hash_table_size(priv->available_connections) == 0 && !nm_device_is_real(self))
        g_signal_emit(self, signals[REMOVED], 0);

    return G_SOURCE_REMOVE;
}

static void
available_connections_check_delete_unrealized(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    /* always rescheadule the remove signal. */
    nm_clear_g_source(&priv->check_delete_unrealized_id);

    if (g_hash_table_size(priv->available_connections) == 0 && !nm_device_is_real(self))
        priv->check_delete_unrealized_id =
            g_idle_add(available_connections_check_delete_unrealized_on_idle, self);
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
nm_device_unrealize(NMDevice *self, gboolean remove_resources, GError **error)
{
    NMDevicePrivate *priv;
    int              ifindex;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    if (!nm_device_is_software(self) || !nm_device_is_real(self)) {
        g_set_error_literal(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_NOT_SOFTWARE,
                            "This device is not a software device or is not realized");
        return FALSE;
    }

    priv = NM_DEVICE_GET_PRIVATE(self);

    g_return_val_if_fail(priv->iface != NULL, FALSE);
    g_return_val_if_fail(priv->real, FALSE);

    ifindex = nm_device_get_ifindex(self);

    _LOGD(LOGD_DEVICE, "unrealize (ifindex %d)", ifindex > 0 ? ifindex : 0);

    nm_device_assume_state_reset(self);

    if (remove_resources) {
        if (NM_DEVICE_GET_CLASS(self)->unrealize) {
            if (!NM_DEVICE_GET_CLASS(self)->unrealize(self, error))
                return FALSE;
        } else if (ifindex > 0) {
            nm_platform_link_delete(nm_device_get_platform(self), ifindex);
        }
    }

    g_object_freeze_notify(G_OBJECT(self));
    NM_DEVICE_GET_CLASS(self)->unrealize_notify(self);

    _parent_set_ifindex(self, 0, FALSE);

    _set_ifindex(self, 0, FALSE);
    _set_ifindex(self, 0, TRUE);
    if (nm_clear_g_free(&priv->ip_iface_))
        update_prop_ip_iface(self);

    priv->master_ifindex = 0;

    _set_mtu(self, 0);

    if (priv->driver_version) {
        nm_clear_g_free(&priv->driver_version);
        _notify(self, PROP_DRIVER_VERSION);
    }
    if (priv->firmware_version) {
        nm_clear_g_free(&priv->firmware_version);
        _notify(self, PROP_FIRMWARE_VERSION);
    }
    if (priv->udi) {
        nm_clear_g_free(&priv->udi);
        _notify(self, PROP_UDI);
    }
    if (priv->path) {
        nm_clear_g_free(&priv->path);
        _notify(self, PROP_PATH);
    }
    if (priv->physical_port_id) {
        nm_clear_g_free(&priv->physical_port_id);
        _notify(self, PROP_PHYSICAL_PORT_ID);
    }

    nm_clear_g_source_inst(&priv->stats.timeout_source);
    _stats_update_counters(self, 0, 0);

    priv->hw_addr_len_ = 0;
    if (nm_clear_g_free(&priv->hw_addr))
        _notify(self, PROP_HW_ADDRESS);
    priv->hw_addr_type = HW_ADDR_TYPE_UNSET;
    if (nm_clear_g_free(&priv->hw_addr_perm))
        _notify(self, PROP_PERM_HW_ADDRESS);
    nm_clear_g_free(&priv->hw_addr_initial);

    priv->capabilities = NM_DEVICE_CAP_NM_SUPPORTED;
    if (NM_DEVICE_GET_CLASS(self)->get_generic_capabilities)
        priv->capabilities |= NM_DEVICE_GET_CLASS(self)->get_generic_capabilities(self);
    _notify(self, PROP_CAPABILITIES);

    nm_clear_g_signal_handler(nm_config_get(), &priv->config_changed_id);
    nm_clear_g_signal_handler(priv->manager, &priv->ifindex_changed_id);

    priv->real = FALSE;
    _notify(self, PROP_REAL);

    g_object_thaw_notify(G_OBJECT(self));

    nm_device_set_unmanaged_flags(self, NM_UNMANAGED_PLATFORM_INIT, TRUE);

    nm_device_set_unmanaged_flags(self,
                                  NM_UNMANAGED_USER_UDEV | NM_UNMANAGED_USER_EXPLICIT
                                      | NM_UNMANAGED_EXTERNAL_DOWN | NM_UNMANAGED_IS_SLAVE,
                                  NM_UNMAN_FLAG_OP_FORGET);

    nm_device_state_changed(self,
                            NM_DEVICE_STATE_UNMANAGED,
                            remove_resources ? NM_DEVICE_STATE_REASON_USER_REQUESTED
                                             : NM_DEVICE_STATE_REASON_NOW_UNMANAGED);

    /* Garbage-collect unneeded unrealized devices. */
    nm_device_recheck_available_connections(self);

    /* In case the unrealized device is not going away, it may need to
     * autoactivate.  Schedule also a check for that. */
    nm_device_recheck_auto_activate_schedule(self);

    return TRUE;
}

void
nm_device_notify_availability_maybe_changed(NMDevice *self)
{
    NMDevicePrivate *priv;

    g_return_if_fail(NM_IS_DEVICE(self));

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->state != NM_DEVICE_STATE_DISCONNECTED)
        return;

    /* A device could have stayed disconnected because it would
     * want to register with a network server that now become
     * available. */
    nm_device_recheck_available_connections(self);
    if (g_hash_table_size(priv->available_connections) > 0)
        nm_device_recheck_auto_activate_schedule(self);
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
 * Returns: %TRUE if @self or its components own the interface name,
 * %FALSE if not
 */
gboolean
nm_device_owns_iface(NMDevice *self, const char *iface)
{
    if (NM_DEVICE_GET_CLASS(self)->owns_iface)
        return NM_DEVICE_GET_CLASS(self)->owns_iface(self, iface);
    return FALSE;
}

NMConnection *
nm_device_new_default_connection(NMDevice *self)
{
    NMConnection *connection;
    GError       *error = NULL;

    if (!NM_DEVICE_GET_CLASS(self)->new_default_connection)
        return NULL;

    connection = NM_DEVICE_GET_CLASS(self)->new_default_connection(self);
    if (!connection)
        return NULL;

    if (!nm_connection_normalize(connection, NULL, NULL, &error)) {
        _LOGD(LOGD_DEVICE, "device generated an invalid default connection: %s", error->message);
        g_error_free(error);
        g_return_val_if_reached(NULL);
    }

    return connection;
}

static void
slave_state_changed(NMDevice           *slave,
                    NMDeviceState       slave_new_state,
                    NMDeviceState       slave_old_state,
                    NMDeviceStateReason reason,
                    NMDevice           *self)
{
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    gboolean         release = FALSE;
    gboolean         configure;

    _LOGD(LOGD_DEVICE,
          "slave %s state change %d (%s) -> %d (%s)",
          nm_device_get_iface(slave),
          slave_old_state,
          nm_device_state_to_string(slave_old_state),
          slave_new_state,
          nm_device_state_to_string(slave_new_state));

    /* Don't try to enslave slaves until the master is ready */
    if (priv->state < NM_DEVICE_STATE_CONFIG)
        return;

    if (slave_new_state == NM_DEVICE_STATE_IP_CONFIG)
        nm_device_master_enslave_slave(self, slave, nm_device_get_applied_connection(slave));
    else if (slave_new_state > NM_DEVICE_STATE_ACTIVATED)
        release = TRUE;
    else if (slave_new_state <= NM_DEVICE_STATE_DISCONNECTED
             && slave_old_state > NM_DEVICE_STATE_DISCONNECTED) {
        /* Catch failures due to unavailable or unmanaged */
        release = TRUE;
    }

    if (release) {
        configure = (priv->sys_iface_state == NM_DEVICE_SYS_IFACE_STATE_MANAGED
                     && nm_device_sys_iface_state_get(slave) != NM_DEVICE_SYS_IFACE_STATE_EXTERNAL)
                    || nm_device_sys_iface_state_get(slave) == NM_DEVICE_SYS_IFACE_STATE_MANAGED;

        nm_device_master_release_slave(self,
                                       slave,
                                       configure ? RELEASE_SLAVE_TYPE_CONFIG
                                                 : RELEASE_SLAVE_TYPE_NO_CONFIG,
                                       reason);
        /* Bridge/bond/team interfaces are left up until manually deactivated */
        if (c_list_is_empty(&priv->slaves) && priv->state == NM_DEVICE_STATE_ACTIVATED)
            _LOGD(LOGD_DEVICE, "last slave removed; remaining activated");
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
nm_device_master_add_slave(NMDevice *self, NMDevice *slave, gboolean configure)
{
    NMDevicePrivate *priv;
    NMDevicePrivate *slave_priv;
    SlaveInfo       *info;
    gboolean         changed = FALSE;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);
    g_return_val_if_fail(NM_IS_DEVICE(slave), FALSE);
    g_return_val_if_fail(NM_DEVICE_GET_CLASS(self)->attach_port, FALSE);

    priv       = NM_DEVICE_GET_PRIVATE(self);
    slave_priv = NM_DEVICE_GET_PRIVATE(slave);

    info = find_slave_info(self, slave);

    _LOGT(LOGD_CORE,
          "master: add one slave " NM_HASH_OBFUSCATE_PTR_FMT "/%s%s",
          NM_HASH_OBFUSCATE_PTR(slave),
          nm_device_get_iface(slave),
          info ? " (already registered)" : "");

    if (configure)
        g_return_val_if_fail(nm_device_get_state(slave) >= NM_DEVICE_STATE_DISCONNECTED, FALSE);

    if (!info) {
        g_return_val_if_fail(!slave_priv->master, FALSE);
        g_return_val_if_fail(!slave_priv->is_enslaved, FALSE);

        info            = g_slice_new0(SlaveInfo);
        info->slave     = g_object_ref(slave);
        info->configure = configure;
        info->watch_id =
            g_signal_connect(slave, NM_DEVICE_STATE_CHANGED, G_CALLBACK(slave_state_changed), self);
        c_list_link_tail(&priv->slaves, &info->lst_slave);
        slave_priv->master = g_object_ref(self);

        _active_connection_set_state_flags(self, NM_ACTIVATION_STATE_FLAG_MASTER_HAS_SLAVES);

        /* no need to emit
         *
         *   _notify (slave, PROP_MASTER);
         *
         * because slave_priv->is_enslaved is not true, thus the value
         * didn't change yet. */

        g_warn_if_fail(!NM_FLAGS_HAS(slave_priv->unmanaged_mask, NM_UNMANAGED_IS_SLAVE));
        nm_device_set_unmanaged_by_flags(slave,
                                         NM_UNMANAGED_IS_SLAVE,
                                         NM_UNMAN_FLAG_OP_SET_MANAGED,
                                         NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
        changed = TRUE;
    } else
        g_return_val_if_fail(slave_priv->master == self, FALSE);

    nm_device_queue_recheck_assume(self);
    nm_device_queue_recheck_assume(slave);

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
nm_device_master_check_slave_physical_port(NMDevice *self, NMDevice *slave, NMLogDomain log_domain)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    const char      *slave_physical_port_id, *existing_physical_port_id;
    SlaveInfo       *info;

    slave_physical_port_id = nm_device_get_physical_port_id(slave);
    if (!slave_physical_port_id)
        return;

    c_list_for_each_entry (info, &priv->slaves, lst_slave) {
        if (info->slave == slave)
            continue;

        existing_physical_port_id = nm_device_get_physical_port_id(info->slave);
        if (nm_streq0(slave_physical_port_id, existing_physical_port_id)) {
            _LOGW(log_domain,
                  "slave %s shares a physical port with existing slave %s",
                  nm_device_get_ip_iface(slave),
                  nm_device_get_ip_iface(info->slave));
            /* Since this function will get called for every slave, we only have
             * to warn about the first match we find; if there are other matches
             * later in the list, we will have already warned about them matching
             * @existing earlier.
             */
            return;
        }
    }
}

void
nm_device_master_release_slaves_all(NMDevice *self)
{
    NMDevicePrivate    *priv = NM_DEVICE_GET_PRIVATE(self);
    NMDeviceStateReason reason;
    SlaveInfo          *info;
    SlaveInfo          *safe;

    /* Don't release the slaves if this connection doesn't belong to NM. */
    if (nm_device_sys_iface_state_is_external(self))
        return;

    reason = priv->state_reason;
    if (priv->state == NM_DEVICE_STATE_FAILED)
        reason = NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED;

    c_list_for_each_entry_safe (info, safe, &priv->slaves, lst_slave) {
        if (priv->activation_state_preserve_external_ports
            && nm_device_sys_iface_state_is_external(info->slave)) {
            _LOGT(LOGD_DEVICE,
                  "master: preserve external port %s",
                  nm_device_get_iface(info->slave));
            continue;
        }
        nm_device_master_release_slave(self, info->slave, RELEASE_SLAVE_TYPE_CONFIG, reason);
    }

    /* We only need this flag for a short time. It served its purpose. Clear
     * it again. */
    nm_device_activation_state_set_preserve_external_ports(self, FALSE);
}

/**
 * nm_device_is_master:
 * @self: the device
 *
 * Returns: %TRUE if the device can have slaves
 */
gboolean
nm_device_is_master(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    return NM_DEVICE_GET_CLASS(self)->is_master;
}

/**
 * nm_device_get_master:
 * @self: the device
 *
 * If @self has been enslaved by another device, this returns that
 * device. Otherwise, it returns %NULL. (In particular, note that if
 * @self is in the process of activating as a slave, but has not yet
 * been enslaved by its master, this will return %NULL.)
 *
 * Returns: (transfer none): @self's master, or %NULL
 */
NMDevice *
nm_device_get_master(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->is_enslaved) {
        g_return_val_if_fail(priv->master, NULL);
        return priv->master;
    }
    return NULL;
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
nm_device_slave_notify_enslave(NMDevice *self, gboolean success)
{
    NMDevicePrivate *priv       = NM_DEVICE_GET_PRIVATE(self);
    NMConnection    *connection = nm_device_get_applied_connection(self);
    gboolean         activating = (priv->state == NM_DEVICE_STATE_IP_CONFIG);

    g_return_if_fail(priv->master);

    if (!priv->is_enslaved) {
        if (success) {
            if (activating) {
                _LOGI(LOGD_DEVICE,
                      "Activation: connection '%s' enslaved, continuing activation",
                      nm_connection_get_id(connection));
            } else
                _LOGI(LOGD_DEVICE, "enslaved to %s", nm_device_get_iface(priv->master));

            priv->is_enslaved = TRUE;

            _notify(self, PROP_MASTER);

            nm_clear_pointer(&NM_DEVICE_GET_PRIVATE(priv->master)->ports_variant, g_variant_unref);
            nm_gobject_notify_together(priv->master, PROP_PORTS, PROP_SLAVES);
        } else if (activating) {
            _LOGW(LOGD_DEVICE,
                  "Activation: connection '%s' could not be enslaved",
                  nm_connection_get_id(connection));
        }
    }

    if (!activating) {
        nm_device_queue_recheck_assume(self);
        return;
    }

    if (!success) {
        nm_device_queue_state(self, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_UNKNOWN);
        return;
    }

    nm_device_activate_schedule_stage3_ip_config(self, FALSE);
}

/**
 * nm_device_slave_notify_release:
 * @self: the slave device
 * @reason: the reason associated with the state change
 *
 * Notifies a slave that it has been released, and why.
 */
static void
nm_device_slave_notify_release(NMDevice           *self,
                               NMDeviceStateReason reason,
                               ReleaseSlaveType    release_type)
{
    NMDevicePrivate *priv       = NM_DEVICE_GET_PRIVATE(self);
    NMConnection    *connection = nm_device_get_applied_connection(self);
    const char      *master_status;

    g_return_if_fail(priv->master);

    if (!priv->is_enslaved && release_type == RELEASE_SLAVE_TYPE_NO_CONFIG)
        return;

    if (priv->state > NM_DEVICE_STATE_DISCONNECTED && priv->state <= NM_DEVICE_STATE_ACTIVATED) {
        switch (nm_device_state_reason_check(reason)) {
        case NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED:
            master_status = "failed";
            break;
        case NM_DEVICE_STATE_REASON_USER_REQUESTED:
            reason        = NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED;
            master_status = "deactivated by user request";
            break;
        case NM_DEVICE_STATE_REASON_CONNECTION_REMOVED:
            reason        = NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED;
            master_status = "deactivated because master was removed";
            break;
        default:
            master_status = "deactivated";
            break;
        }

        _LOGD(LOGD_DEVICE,
              "Activation: connection '%s' master %s",
              nm_connection_get_id(connection),
              master_status);

        /* Cancel any pending activation sources */
        _cancel_activation(self);
        nm_device_queue_state(self, NM_DEVICE_STATE_DEACTIVATING, reason);
    } else
        _LOGI(LOGD_DEVICE, "released from master device %s", nm_device_get_iface(priv->master));

    priv->is_enslaved = FALSE;

    _notify(self, PROP_MASTER);

    nm_clear_pointer(&NM_DEVICE_GET_PRIVATE(priv->master)->ports_variant, g_variant_unref);
    nm_gobject_notify_together(priv->master, PROP_PORTS, PROP_SLAVES);
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
nm_device_removed(NMDevice *self, gboolean unconfigure_ip_config)
{
    NMDevicePrivate      *priv;
    const NML3ConfigData *l3cd_old;

    g_return_if_fail(NM_IS_DEVICE(self));

    _dev_ipdhcpx_cleanup(self, AF_INET, TRUE, FALSE);
    _dev_ipdhcpx_cleanup(self, AF_INET6, TRUE, FALSE);

    priv = NM_DEVICE_GET_PRIVATE(self);
    if (priv->master) {
        /* this is called when something externally messes with the slave or during shut-down.
         * Release the slave from master, but don't touch the device. */
        nm_device_master_release_slave(priv->master,
                                       self,
                                       RELEASE_SLAVE_TYPE_NO_CONFIG,
                                       NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
    }

    _dev_l3_register_l3cds(self, priv->l3cfg, FALSE, unconfigure_ip_config);

    /* _dev_l3_register_l3cds() schedules a commit, but if the device has
     * commit type NONE, that doesn't emit a l3cd-changed. Do it manually,
     * to ensure that entries are removed from the DNS manager. */
    if (priv->l3cfg
        && NM_IN_SET(priv->sys_iface_state,
                     NM_DEVICE_SYS_IFACE_STATE_REMOVED,
                     NM_DEVICE_SYS_IFACE_STATE_EXTERNAL)) {
        l3cd_old = nm_l3cfg_get_combined_l3cd(priv->l3cfg, TRUE);
        if (l3cd_old)
            g_signal_emit(self, signals[L3CD_CHANGED], 0, l3cd_old, NULL);
    }
}

static gboolean
is_available(NMDevice *self, NMDeviceCheckDevAvailableFlags flags)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->carrier || priv->ignore_carrier)
        return TRUE;

    if (NM_FLAGS_HAS(flags, _NM_DEVICE_CHECK_DEV_AVAILABLE_IGNORE_CARRIER))
        return TRUE;

    /* master types are always available even without carrier. */
    if (nm_device_is_master(self))
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
nm_device_is_available(NMDevice *self, NMDeviceCheckDevAvailableFlags flags)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->firmware_missing)
        return FALSE;

    return NM_DEVICE_GET_CLASS(self)->is_available(self, flags);
}

gboolean
nm_device_ignore_carrier_by_default(NMDevice *self)
{
    /* master types ignore-carrier by default. */
    return nm_device_is_master(self);
}

gboolean
nm_device_get_enabled(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    if (NM_DEVICE_GET_CLASS(self)->get_enabled)
        return NM_DEVICE_GET_CLASS(self)->get_enabled(self);
    return TRUE;
}

void
nm_device_set_enabled(NMDevice *self, gboolean enabled)
{
    g_return_if_fail(NM_IS_DEVICE(self));

    if (NM_DEVICE_GET_CLASS(self)->set_enabled)
        NM_DEVICE_GET_CLASS(self)->set_enabled(self, enabled);
}

static NM_UTILS_FLAGS2STR_DEFINE(_autoconnect_blocked_flags_to_string,
                                 NMDeviceAutoconnectBlockedFlags,
                                 NM_UTILS_FLAGS2STR(NM_DEVICE_AUTOCONNECT_BLOCKED_NONE, "none"),
                                 NM_UTILS_FLAGS2STR(NM_DEVICE_AUTOCONNECT_BLOCKED_USER, "user"),
                                 NM_UTILS_FLAGS2STR(NM_DEVICE_AUTOCONNECT_BLOCKED_WRONG_PIN,
                                                    "wrong-pin"),
                                 NM_UTILS_FLAGS2STR(NM_DEVICE_AUTOCONNECT_BLOCKED_MANUAL_DISCONNECT,
                                                    "manual-disconnect"), );

NMDeviceAutoconnectBlockedFlags
nm_device_autoconnect_blocked_get(NMDevice *self, NMDeviceAutoconnectBlockedFlags mask)
{
    NMDevicePrivate *priv;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    if (mask == 0)
        mask = NM_DEVICE_AUTOCONNECT_BLOCKED_ALL;

    priv = NM_DEVICE_GET_PRIVATE(self);
    return priv->autoconnect_blocked_flags & mask;
}

void
nm_device_autoconnect_blocked_set_full(NMDevice                       *self,
                                       NMDeviceAutoconnectBlockedFlags mask,
                                       NMDeviceAutoconnectBlockedFlags value)
{
    NMDevicePrivate *priv;
    gboolean         changed;
    char             buf1[128], buf2[128];

    g_return_if_fail(NM_IS_DEVICE(self));
    nm_assert(mask);
    nm_assert(!NM_FLAGS_ANY(mask, ~NM_DEVICE_AUTOCONNECT_BLOCKED_ALL));
    nm_assert(!NM_FLAGS_ANY(value, ~mask));

    priv = NM_DEVICE_GET_PRIVATE(self);

    value = (priv->autoconnect_blocked_flags & ~mask) | (mask & value);
    if (value == priv->autoconnect_blocked_flags)
        return;

    changed = ((!value) != (!priv->autoconnect_blocked_flags));

    _LOGT(
        LOGD_DEVICE,
        "autoconnect-blocked: set \"%s\" (was \"%s\")",
        _autoconnect_blocked_flags_to_string(value, buf1, sizeof(buf1)),
        _autoconnect_blocked_flags_to_string(priv->autoconnect_blocked_flags, buf2, sizeof(buf2)));

    priv->autoconnect_blocked_flags = value;
    nm_assert(priv->autoconnect_blocked_flags == value);
    if (changed)
        _notify(self, PROP_AUTOCONNECT);
}

static gboolean
autoconnect_allowed_accumulator(GSignalInvocationHint *ihint,
                                GValue                *return_accu,
                                const GValue          *handler_return,
                                gpointer               data)
{
    if (!g_value_get_boolean(handler_return))
        g_value_set_boolean(return_accu, FALSE);
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
nm_device_autoconnect_allowed(NMDevice *self)
{
    NMDevicePrivate *priv     = NM_DEVICE_GET_PRIVATE(self);
    NMDeviceClass   *klass    = NM_DEVICE_GET_CLASS(self);
    GValue           instance = G_VALUE_INIT;
    GValue           retval   = G_VALUE_INIT;

    if (nm_device_autoconnect_blocked_get(self, NM_DEVICE_AUTOCONNECT_BLOCKED_ALL))
        return FALSE;

    if (klass->get_autoconnect_allowed && !klass->get_autoconnect_allowed(self))
        return FALSE;

    if (!nm_device_get_enabled(self))
        return FALSE;

    if (nm_device_is_real(self)) {
        if (priv->state < NM_DEVICE_STATE_DISCONNECTED)
            return FALSE;
    } else {
        if (!nm_device_check_unrealized_device_managed(self))
            return FALSE;
    }

    if (priv->delete_on_deactivate_idle_source)
        return FALSE;

    /* The 'autoconnect-allowed' signal is emitted on a device to allow
     * other listeners to block autoconnect on the device if they wish.
     * This is mainly used by the OLPC Mesh devices to block autoconnect
     * on their companion Wi-Fi device as they share radio resources and
     * cannot be connected at the same time.
     */

    g_value_init(&instance, G_TYPE_OBJECT);
    g_value_set_object(&instance, self);

    g_value_init(&retval, G_TYPE_BOOLEAN);
    g_value_set_boolean(&retval, TRUE);

    /* Use g_signal_emitv() rather than g_signal_emit() to avoid the return
     * value being changed if no handlers are connected */
    g_signal_emitv(&instance, signals[AUTOCONNECT_ALLOWED], 0, &retval);
    g_value_unset(&instance);

    return g_value_get_boolean(&retval);
}

static gboolean
can_auto_connect(NMDevice *self, NMSettingsConnection *sett_conn, char **specific_object)
{
    nm_assert(!specific_object || !*specific_object);
    return TRUE;
}

/**
 * nm_device_can_auto_connect:
 * @self: an #NMDevice
 * @sett_conn: a #NMSettingsConnection
 * @specific_object: (out) (transfer full): on output, the path of an
 *   object associated with the returned connection, to be passed to
 *   nm_manager_activate_connection(), or %NULL.
 *
 * Checks if @sett_conn can be auto-activated on @self right now.
 * This requires, at a minimum, that the connection be compatible with
 * @self, and that it have the #NMSettingConnection:autoconnect property
 * set, and that the device allow auto connections. Some devices impose
 * additional requirements. (Eg, a Wi-Fi connection can only be activated
 * if its SSID was seen in the last scan.)
 *
 * Returns: %TRUE, if the @sett_conn can be auto-activated.
 **/
gboolean
nm_device_can_auto_connect(NMDevice *self, NMSettingsConnection *sett_conn, char **specific_object)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);
    g_return_val_if_fail(NM_IS_SETTINGS_CONNECTION(sett_conn), FALSE);
    g_return_val_if_fail(!specific_object || !*specific_object, FALSE);

    /* the caller must ensure that nm_device_autoconnect_allowed() returns
     * TRUE as well. This is done, because nm_device_can_auto_connect()
     * has only one caller, and it iterates over a list of available
     * connections.
     *
     * Hence, we don't need to re-check nm_device_autoconnect_allowed()
     * over and over again. The caller is supposed to do that. */
    nm_assert(nm_device_autoconnect_allowed(self));

    if (!nm_device_check_connection_available(self,
                                              nm_settings_connection_get_connection(sett_conn),
                                              NM_DEVICE_CHECK_CON_AVAILABLE_NONE,
                                              NULL,
                                              NULL))
        return FALSE;

    if (!NM_DEVICE_GET_CLASS(self)->can_auto_connect(self, sett_conn, specific_object))
        return FALSE;

    return TRUE;
}

static gboolean
device_has_config(NMDevice *self)
{
    NMDevicePrivate             *priv = NM_DEVICE_GET_PRIVATE(self);
    const NMDedupMultiHeadEntry *head_entry;
    const NMPlatformLink        *pllink;
    NMPLookup                    lookup;

    pllink = nm_l3cfg_get_pllink(priv->l3cfg, TRUE);
    if (!pllink)
        return FALSE;

    if (pllink->master > 0) {
        /* Master-slave relationship is also a configuration */
        return TRUE;
    }

    head_entry = nm_platform_lookup(
        nm_device_get_platform(self),
        nmp_lookup_init_object_by_ifindex(&lookup, NMP_OBJECT_TYPE_IP4_ADDRESS, pllink->ifindex));
    if (head_entry)
        return TRUE;

    head_entry = nm_platform_lookup(
        nm_device_get_platform(self),
        nmp_lookup_init_object_by_ifindex(&lookup, NMP_OBJECT_TYPE_IP6_ADDRESS, pllink->ifindex));
    if (head_entry)
        return TRUE;

    if (nm_device_is_software(self) && nm_device_is_real(self)) {
        /* The existence of a software device is good enough. */
        return TRUE;
    }

    return FALSE;
}

/**
 * nm_device_master_update_slave_connection:
 * @self: the master #NMDevice
 * @slave: the slave #NMDevice
 * @connection: the #NMConnection to update with the slave settings
 * @error: error description
 *
 * Reads the slave configuration for @slave and updates @connection with those
 * properties. This invokes a virtual function on the master device @self.
 *
 * Returns: %TRUE if the configuration was read and @connection updated,
 * %FALSE on failure.
 */
gboolean
nm_device_master_update_slave_connection(NMDevice     *self,
                                         NMDevice     *slave,
                                         NMConnection *connection,
                                         GError      **error)
{
    NMDeviceClass *klass;
    gboolean       success;

    g_return_val_if_fail(self, FALSE);
    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);
    g_return_val_if_fail(slave, FALSE);
    g_return_val_if_fail(connection, FALSE);
    g_return_val_if_fail(!error || !*error, FALSE);
    g_return_val_if_fail(nm_connection_get_setting_connection(connection), FALSE);

    g_return_val_if_fail(nm_device_get_iface(self), FALSE);

    klass = NM_DEVICE_GET_CLASS(self);
    if (klass->master_update_slave_connection) {
        success = klass->master_update_slave_connection(self, slave, connection, error);

        g_return_val_if_fail(!error || (success && !*error) || *error, success);
        return success;
    }

    g_set_error(error,
                NM_DEVICE_ERROR,
                NM_DEVICE_ERROR_FAILED,
                "master device '%s' cannot update a slave connection for slave device '%s' (master "
                "type not supported?)",
                nm_device_get_iface(self),
                nm_device_get_iface(slave));
    return FALSE;
}

static gboolean
_get_maybe_ipv6_disabled(NMDevice *self)
{
    NMPlatform *platform;
    int         ifindex;
    const char *path;
    char        ifname[IFNAMSIZ];

    ifindex = nm_device_get_ip_ifindex(self);
    if (ifindex <= 0)
        return FALSE;

    platform = nm_device_get_platform(self);
    if (!nm_platform_if_indextoname(platform, ifindex, ifname))
        return FALSE;

    path = nm_sprintf_bufa(128, "/proc/sys/net/ipv6/conf/%s/disable_ipv6", ifname);
    return (nm_platform_sysctl_get_int32(platform, NMP_SYSCTL_PATHID_ABSOLUTE(path), 1) != 0);
}

/*
 * nm_device_generate_connection:
 *
 * Generates a connection from an existing interface.
 *
 * If the device doesn't have an IP configuration and it's not a port or a
 * controller, then no connection gets generated and the function returns
 * %NULL. In such case, @maybe_later is set to %TRUE if a connection can be
 * generated later when an IP address is assigned to the interface.
 */
NMConnection *
nm_device_generate_connection(NMDevice *self,
                              NMDevice *master,
                              gboolean *out_maybe_later,
                              GError  **error)
{
    NMDeviceClass                *klass      = NM_DEVICE_GET_CLASS(self);
    NMDevicePrivate              *priv       = NM_DEVICE_GET_PRIVATE(self);
    const char                   *ifname     = nm_device_get_iface(self);
    gs_unref_object NMConnection *connection = NULL;
    NMSetting                    *s_con;
    NMSetting                    *s_ip4;
    NMSetting                    *s_ip6;
    char                          uuid[37];
    const char                   *ip4_method, *ip6_method;
    GError                       *local = NULL;
    const NMPlatformLink         *pllink;

    NM_SET_OUT(out_maybe_later, FALSE);

    /* If update_connection() is not implemented, just fail. */
    if (!klass->update_connection) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_FAILED,
                    "device class %s does not support generating a connection",
                    G_OBJECT_TYPE_NAME(self));
        return NULL;
    }

    /* Return NULL if device is unconfigured. */
    if (!device_has_config(self)) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_FAILED,
                    "device has no existing configuration");
        return NULL;
    }

    connection = nm_simple_connection_new();
    s_con      = nm_setting_connection_new();

    g_object_set(s_con,
                 NM_SETTING_CONNECTION_UUID,
                 nm_uuid_generate_random_str_arr(uuid),
                 NM_SETTING_CONNECTION_ID,
                 ifname,
                 NM_SETTING_CONNECTION_AUTOCONNECT,
                 FALSE,
                 NM_SETTING_CONNECTION_INTERFACE_NAME,
                 ifname,
                 NM_SETTING_CONNECTION_TIMESTAMP,
                 (guint64) time(NULL),
                 NULL);

    if (klass->connection_type_supported)
        g_object_set(s_con, NM_SETTING_CONNECTION_TYPE, klass->connection_type_supported, NULL);

    nm_connection_add_setting(connection, s_con);

    /* If the device is a slave, update various slave settings */
    if (master) {
        if (!nm_device_master_update_slave_connection(master, self, connection, &local)) {
            g_set_error(error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_FAILED,
                        "master device '%s' failed to update slave connection: %s",
                        nm_device_get_iface(master),
                        local->message);
            g_error_free(local);
            NM_SET_OUT(out_maybe_later, TRUE);
            return NULL;
        }
    } else {
        /* Only regular and master devices get IP configuration; slaves do not */
        s_ip4 = nm_utils_platform_capture_ip_setting(nm_device_get_platform(self),
                                                     AF_INET,
                                                     nm_device_get_ip_ifindex(self),
                                                     FALSE);
        nm_connection_add_setting(connection, s_ip4);

        s_ip6 = nm_utils_platform_capture_ip_setting(nm_device_get_platform(self),
                                                     AF_INET6,
                                                     nm_device_get_ip_ifindex(self),
                                                     _get_maybe_ipv6_disabled(self));
        nm_connection_add_setting(connection, s_ip6);

        nm_connection_add_setting(connection, nm_setting_proxy_new());

        pllink = nm_platform_link_get(nm_device_get_platform(self), priv->ifindex);
        if (pllink && pllink->inet6_token.id) {
            char sbuf[NM_INET_ADDRSTRLEN];

            g_object_set(s_ip6,
                         NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE,
                         NM_IN6_ADDR_GEN_MODE_EUI64,
                         NM_SETTING_IP6_CONFIG_TOKEN,
                         nm_utils_inet6_interface_identifier_to_token(&pllink->inet6_token, sbuf),
                         NULL);
        }
    }

    klass->update_connection(self, connection);

    if (!nm_connection_normalize(connection, NULL, NULL, &local)) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_FAILED,
                    "generated connection does not verify: %s",
                    local->message);
        g_error_free(local);
        return NULL;
    }

    /* Ignore the connection if it has no IP configuration,
     * no slave configuration, and is not a master interface.
     */
    ip4_method = nm_utils_get_ip_config_method(connection, AF_INET);
    ip6_method = nm_utils_get_ip_config_method(connection, AF_INET6);
    if (nm_streq0(ip4_method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)
        && NM_IN_STRSET(ip6_method,
                        NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
                        NM_SETTING_IP6_CONFIG_METHOD_DISABLED)
        && !nm_setting_connection_get_master(NM_SETTING_CONNECTION(s_con))
        && c_list_is_empty(&priv->slaves)) {
        NM_SET_OUT(out_maybe_later, TRUE);
        g_set_error_literal(
            error,
            NM_DEVICE_ERROR,
            NM_DEVICE_ERROR_FAILED,
            "ignoring generated connection (no IP and not in master-slave relationship)");
        return NULL;
    }

    /* Ignore any IPv6LL-only, not master connections without slaves,
     * unless they are in the assume-ipv6ll-only list.
     */
    if (nm_streq0(ip4_method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)
        && nm_streq0(ip6_method, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL)
        && !nm_setting_connection_get_master(NM_SETTING_CONNECTION(s_con))
        && c_list_is_empty(&priv->slaves)
        && !nm_config_data_get_assume_ipv6ll_only(NM_CONFIG_GET_DATA, self)) {
        _LOGD(LOGD_DEVICE,
              "ignoring generated connection (IPv6LL-only and not in master-slave relationship)");
        NM_SET_OUT(out_maybe_later, TRUE);
        g_set_error_literal(
            error,
            NM_DEVICE_ERROR,
            NM_DEVICE_ERROR_FAILED,
            "ignoring generated connection (IPv6LL-only and not in master-slave relationship)");
        return NULL;
    }

    return g_steal_pointer(&connection);
}

/**
 * nm_device_complete_connection:
 *
 * Complete the connection. This is solely used for AddAndActivate where the user
 * may pass in an incomplete connection and a device, and the device tries to
 * make sense of it and complete it for activation. Otherwise, this is not
 * used.
 *
 * Returns: success or failure.
 */
gboolean
nm_device_complete_connection(NMDevice            *self,
                              NMConnection        *connection,
                              const char          *specific_object,
                              NMConnection *const *existing_connections,
                              GError             **error)
{
    NMDeviceClass *klass;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);
    g_return_val_if_fail(NM_IS_CONNECTION(connection), FALSE);

    klass = NM_DEVICE_GET_CLASS(self);

    if (!klass->complete_connection) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_INVALID_CONNECTION,
                    "Device class %s had no complete_connection method",
                    G_OBJECT_TYPE_NAME(self));
        return FALSE;
    }

    if (!klass->complete_connection(self, connection, specific_object, existing_connections, error))
        return FALSE;

    if (!nm_connection_normalize(connection, NULL, NULL, error))
        return FALSE;

    return nm_device_check_connection_compatible(self, connection, TRUE, error);
}

gboolean
nm_device_match_parent(NMDevice *self, const char *parent)
{
    NMDevice *parent_device;

    g_return_val_if_fail(parent, FALSE);

    parent_device = nm_device_parent_get_device(self);
    if (!parent_device)
        return FALSE;

    if (nm_utils_is_uuid(parent)) {
        NMConnection *connection;

        /* If the parent is a UUID, the connection matches when there is
         * no connection active on the device or when a connection with
         * that UUID is active.
         */
        connection = nm_device_get_applied_connection(parent_device);
        if (connection && !nm_streq0(parent, nm_connection_get_uuid(connection)))
            return FALSE;
    } else {
        /* Interface name */
        if (!nm_streq0(parent, nm_device_get_ip_iface(parent_device)))
            return FALSE;
    }

    return TRUE;
}

gboolean
nm_device_match_parent_hwaddr(NMDevice     *device,
                              NMConnection *connection,
                              gboolean      fail_if_no_hwaddr)
{
    NMSettingWired *s_wired;
    NMDevice       *parent_device;
    const char     *setting_mac;
    const char     *parent_mac;

    s_wired = nm_connection_get_setting_wired(connection);
    if (!s_wired)
        return !fail_if_no_hwaddr;

    setting_mac = nm_setting_wired_get_mac_address(s_wired);
    if (!setting_mac)
        return !fail_if_no_hwaddr;

    parent_device = nm_device_parent_get_device(device);
    if (!parent_device)
        return !fail_if_no_hwaddr;

    parent_mac = nm_device_get_permanent_hw_address(parent_device);
    return parent_mac && nm_utils_hwaddr_matches(setting_mac, -1, parent_mac, -1);
}

static gboolean
check_connection_compatible(NMDevice     *self,
                            NMConnection *connection,
                            gboolean      check_properties,
                            GError      **error)
{
    NMDevicePrivate      *priv         = NM_DEVICE_GET_PRIVATE(self);
    const char           *device_iface = nm_device_get_iface(self);
    gs_free_error GError *local        = NULL;
    gs_free char         *conn_iface   = NULL;
    NMDeviceClass        *klass;
    NMSettingMatch       *s_match;
    const GSList         *specs;
    gboolean              has_match = FALSE;

    klass = NM_DEVICE_GET_CLASS(self);
    if (klass->connection_type_check_compatible) {
        if (!_nm_connection_check_main_setting(connection,
                                               klass->connection_type_check_compatible,
                                               error))
            return FALSE;
    } else if (klass->check_connection_compatible == check_connection_compatible) {
        /* the device class does not implement check_connection_compatible nor set
         * connection_type_check_compatible. That means, it is by default not compatible
         * with any connection type. */
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                   "device does not support any connections");
        return FALSE;
    }

    if (!nm_device_has_capability(self, NM_DEVICE_CAP_SRIOV)
        && nm_connection_get_setting(connection, NM_TYPE_SETTING_SRIOV)) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "device does not support SR-IOV");
        return FALSE;
    }

    conn_iface = nm_manager_get_connection_iface(NM_MANAGER_GET, connection, NULL, NULL, &local);

    /* We always need a interface name for virtual devices, but for
     * physical ones a connection without interface name is fine for
     * any device. */
    if (!conn_iface) {
        if (nm_connection_is_virtual(connection)) {
            nm_utils_error_set(error,
                               NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                               "cannot get interface name due to %s",
                               local->message);
            return FALSE;
        }
    } else if (!nm_streq0(conn_iface, device_iface)) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                   "mismatching interface name");
        return FALSE;
    }

    s_match = (NMSettingMatch *) nm_connection_get_setting(connection, NM_TYPE_SETTING_MATCH);
    if (s_match) {
        const char *const *patterns;
        guint              num_patterns = 0;

        patterns = nm_setting_match_get_interface_names(s_match, &num_patterns);
        if (num_patterns > 0 && !nm_wildcard_match_check(device_iface, patterns, num_patterns)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "device does not satisfy match.interface-name property");
            return FALSE;
        }

        patterns = nm_setting_match_get_kernel_command_lines(s_match, &num_patterns);
        if (num_patterns > 0
            && !nm_utils_kernel_cmdline_match_check(nm_utils_proc_cmdline_split(),
                                                    patterns,
                                                    num_patterns,
                                                    error))
            return FALSE;

        patterns = nm_setting_match_get_drivers(s_match, &num_patterns);
        if (num_patterns > 0
            && !nm_wildcard_match_check(nm_device_get_driver(self), patterns, num_patterns)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "device does not satisfy match.driver property");
            return FALSE;
        }

        patterns = nm_setting_match_get_paths(s_match, &num_patterns);
        if (num_patterns > 0 && !nm_wildcard_match_check(priv->path, patterns, num_patterns)) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
                                       "device does not satisfy match.path property");
            return FALSE;
        }
    }

    specs =
        nm_config_data_get_device_allowed_connections_specs(NM_CONFIG_GET_DATA, self, &has_match);
    if (has_match && !nm_utils_connection_match_spec_list(connection, specs, FALSE)) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_DISALLOWED,
                                   "device configuration doesn't allow this connection");
        return FALSE;
    }

    return TRUE;
}

/**
 * nm_device_check_connection_compatible:
 * @self: an #NMDevice
 * @connection: an #NMConnection
 * @error: optional reason why it is incompatible. Note that the
 *   error code is set to %NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
 *   if the profile is fundamentally incompatible with the device
 *   (most commonly, because the device-type does not support the
 *   connection-type).
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
nm_device_check_connection_compatible(NMDevice     *self,
                                      NMConnection *connection,
                                      gboolean      check_properties,
                                      GError      **error)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);
    g_return_val_if_fail(NM_IS_CONNECTION(connection), FALSE);

    return NM_DEVICE_GET_CLASS(self)->check_connection_compatible(self,
                                                                  connection,
                                                                  check_properties,
                                                                  error);
}

gboolean
nm_device_check_slave_connection_compatible(NMDevice *self, NMConnection *slave)
{
    NMSettingConnection *s_con;
    const char          *connection_type, *slave_type;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);
    g_return_val_if_fail(NM_IS_CONNECTION(slave), FALSE);

    if (!nm_device_is_master(self))
        return FALSE;

    /* All masters should have connection type set */
    connection_type = NM_DEVICE_GET_CLASS(self)->connection_type_supported;
    g_return_val_if_fail(connection_type, FALSE);

    s_con = nm_connection_get_setting_connection(slave);
    g_assert(s_con);
    slave_type = nm_setting_connection_get_slave_type(s_con);
    if (!slave_type)
        return FALSE;

    return nm_streq(connection_type, slave_type);
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
gboolean
nm_device_can_assume_connections(NMDevice *self)
{
    return !!NM_DEVICE_GET_CLASS(self)->update_connection;
}

static gboolean
unmanaged_on_quit(NMDevice *self)
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
    if (!nm_device_can_assume_connections(self))
        return TRUE;

    /* the only exception are IPv4 shared connections. We unmanage them on quit. */
    connection = nm_device_get_applied_connection(self);
    if (connection) {
        if (NM_IN_STRSET(nm_utils_get_ip_config_method(connection, AF_INET),
                         NM_SETTING_IP4_CONFIG_METHOD_SHARED)) {
            /* shared connections are to be unmangaed. */
            return TRUE;
        }
    }

    return FALSE;
}

gboolean
nm_device_unmanage_on_quit(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    return NM_DEVICE_GET_CLASS(self)->unmanaged_on_quit(self);
}

static gboolean
nm_device_emit_recheck_assume(gpointer user_data)
{
    NMDevice        *self = user_data;
    NMDevicePrivate *priv;

    g_return_val_if_fail(NM_IS_DEVICE(self), G_SOURCE_REMOVE);

    priv = NM_DEVICE_GET_PRIVATE(self);

    priv->recheck_assume_id = 0;
    if (!priv->queued_act_request && !nm_device_get_act_request(self))
        g_signal_emit(self, signals[RECHECK_ASSUME], 0);

    return G_SOURCE_REMOVE;
}

void
nm_device_queue_recheck_assume(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (!priv->recheck_assume_id && nm_device_can_assume_connections(self))
        priv->recheck_assume_id = g_idle_add(nm_device_emit_recheck_assume, self);
}

static gboolean
recheck_available(gpointer user_data)
{
    NMDevice        *self = NM_DEVICE(user_data);
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    gboolean         now_available;
    NMDeviceState    state     = nm_device_get_state(self);
    NMDeviceState    new_state = NM_DEVICE_STATE_UNKNOWN;

    priv->recheck_available.call_id = 0;

    now_available = nm_device_is_available(self, NM_DEVICE_CHECK_DEV_AVAILABLE_NONE);

    if (state == NM_DEVICE_STATE_UNAVAILABLE && now_available) {
        new_state = NM_DEVICE_STATE_DISCONNECTED;
        nm_device_queue_state(self, new_state, priv->recheck_available.available_reason);
    } else if (state >= NM_DEVICE_STATE_DISCONNECTED && !now_available) {
        new_state = NM_DEVICE_STATE_UNAVAILABLE;
        nm_device_queue_state(self, new_state, priv->recheck_available.unavailable_reason);
    }

    if (new_state > NM_DEVICE_STATE_UNKNOWN) {
        _LOGD(LOGD_DEVICE,
              "is %savailable, %s %s",
              now_available ? "" : "not ",
              new_state == NM_DEVICE_STATE_UNAVAILABLE ? "no change required for"
                                                       : "will transition to",
              nm_device_state_to_string(new_state == NM_DEVICE_STATE_UNAVAILABLE ? state
                                                                                 : new_state));

        priv->recheck_available.available_reason   = NM_DEVICE_STATE_REASON_NONE;
        priv->recheck_available.unavailable_reason = NM_DEVICE_STATE_REASON_NONE;
    }

    if (priv->recheck_available.call_id == 0)
        nm_device_remove_pending_action(self, NM_PENDING_ACTION_RECHECK_AVAILABLE, TRUE);

    return G_SOURCE_REMOVE;
}

void
nm_device_queue_recheck_available(NMDevice           *self,
                                  NMDeviceStateReason available_reason,
                                  NMDeviceStateReason unavailable_reason)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    priv->recheck_available.available_reason   = available_reason;
    priv->recheck_available.unavailable_reason = unavailable_reason;
    if (!priv->recheck_available.call_id) {
        priv->recheck_available.call_id = g_idle_add(recheck_available, self);
        nm_device_add_pending_action (self, NM_PENDING_ACTION_RECHECK_AVAILABLE,
                                      FALSE /* cannot assert, because of how recheck_available() first clears
                                             * the call-id and postpones removing the pending-action. */);
    }
}

void
nm_device_recheck_auto_activate_schedule(NMDevice *self)
{
    nm_manager_device_recheck_auto_activate_schedule(nm_device_get_manager(self), self);
}

void
nm_device_auth_request(NMDevice                      *self,
                       GDBusMethodInvocation         *context,
                       NMConnection                  *connection,
                       const char                    *permission,
                       gboolean                       allow_interaction,
                       GCancellable                  *cancellable,
                       NMManagerDeviceAuthRequestFunc callback,
                       gpointer                       user_data)
{
    nm_manager_device_auth_request(nm_device_get_manager(self),
                                   self,
                                   context,
                                   connection,
                                   permission,
                                   allow_interaction,
                                   cancellable,
                                   callback,
                                   user_data);
}

/*****************************************************************************/

static void
activation_source_clear(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (nm_clear_g_source_inst(&priv->activation_idle_source)) {
        _LOGD(LOGD_DEVICE,
              "activation-stage: clear %s",
              _activation_func_to_string(priv->activation_func));
        priv->activation_func = NULL;
    }
}

static gboolean
activation_source_handle_cb(gpointer user_data)
{
    NMDevice            *self = user_data;
    NMDevicePrivate     *priv;
    ActivationHandleFunc activation_func;

    g_return_val_if_fail(NM_IS_DEVICE(self), G_SOURCE_REMOVE);

    priv = NM_DEVICE_GET_PRIVATE(self);

    g_return_val_if_fail(priv->activation_idle_source, G_SOURCE_REMOVE);

    nm_assert(priv->activation_func);

    activation_func       = priv->activation_func;
    priv->activation_func = NULL;

    nm_clear_g_source_inst(&priv->activation_idle_source);

    _LOGD(LOGD_DEVICE, "activation-stage: invoke %s", _activation_func_to_string(activation_func));

    activation_func(self);

    return G_SOURCE_CONTINUE;
}

static void
activation_source_schedule(NMDevice *self, ActivationHandleFunc func)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->activation_idle_source && priv->activation_func == func) {
        /* Scheduling the same stage multiple times is fine. */
        _LOGT(LOGD_DEVICE,
              "activation-stage: already scheduled %s",
              _activation_func_to_string(func));
        return;
    }

    if (priv->activation_idle_source) {
        _LOGD(LOGD_DEVICE,
              "activation-stage: schedule %s (which replaces %s)",
              _activation_func_to_string(func),
              _activation_func_to_string(priv->activation_func));
        nm_clear_g_source_inst(&priv->activation_idle_source);
    } else {
        _LOGD(LOGD_DEVICE, "activation-stage: schedule %s", _activation_func_to_string(func));
    }

    priv->activation_idle_source = nm_g_idle_add_source(activation_source_handle_cb, self);
    priv->activation_func        = func;
}

static void
activation_source_invoke_sync(NMDevice *self, ActivationHandleFunc func)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (!priv->activation_idle_source) {
        _LOGD(LOGD_DEVICE,
              "activation-stage: synchronously invoke %s",
              _activation_func_to_string(func));
    } else if (priv->activation_func == func) {
        _LOGD(LOGD_DEVICE,
              "activation-stage: synchronously invoke %s (which was already scheduled)",
              _activation_func_to_string(func));
    } else {
        _LOGD(LOGD_DEVICE,
              "activation-stage: synchronously invoke %s (which replaces %s)",
              _activation_func_to_string(func),
              _activation_func_to_string(priv->activation_func));
    }

    nm_clear_g_source_inst(&priv->activation_idle_source);
    priv->activation_func = NULL;

    func(self);
}

static void
activation_source_invoke_or_schedule(NMDevice *self, ActivationHandleFunc func, gboolean do_sync)
{
    nm_assert(NM_IS_DEVICE(self));
    nm_assert(NM_DEVICE_GET_PRIVATE(self)->act_request.obj);
    nm_assert(func);

    if (do_sync) {
        activation_source_invoke_sync(self, func);
        return;
    }
    activation_source_schedule(self, func);
}

/*****************************************************************************/

static void
master_ready(NMDevice *self, NMActiveConnection *active)
{
    NMDevicePrivate    *priv = NM_DEVICE_GET_PRIVATE(self);
    NMActiveConnection *master_connection;
    NMDevice           *master;

    /* Notify a master device that it has a new slave */
    nm_assert(nm_active_connection_get_master_ready(active));

    master_connection = nm_active_connection_get_master(active);

    master = nm_active_connection_get_device(master_connection);

    _LOGD(LOGD_DEVICE, "master connection ready; master device %s", nm_device_get_iface(master));

    if (priv->master && priv->master != master)
        nm_device_master_release_slave(priv->master,
                                       self,
                                       RELEASE_SLAVE_TYPE_NO_CONFIG,
                                       NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);

    /* If the master didn't change, add-slave only rechecks whether to assume a connection. */
    nm_device_master_add_slave(master,
                               self,
                               !nm_device_sys_iface_state_is_external_or_assume(self));
}

static void
master_ready_cb(NMActiveConnection *active, GParamSpec *pspec, NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_assert(nm_active_connection_get_master_ready(active));

    if (priv->state == NM_DEVICE_STATE_PREPARE)
        nm_device_activate_schedule_stage1_device_prepare(self, FALSE);
}

static NMPlatformVF *
sriov_vf_config_to_platform(NMDevice *self, NMSriovVF *vf, GError **error)
{
    NMDevicePrivate      *priv    = NM_DEVICE_GET_PRIVATE(self);
    gs_free NMPlatformVF *plat_vf = NULL;
    const guint          *vlan_ids;
    GVariant             *variant;
    guint                 i, num_vlans;
    gsize                 length;

    g_return_val_if_fail(!error || !*error, FALSE);

    vlan_ids = nm_sriov_vf_get_vlan_ids(vf, &num_vlans);
    plat_vf  = g_malloc0(sizeof(NMPlatformVF) + sizeof(NMPlatformVFVlan) * num_vlans);

    plat_vf->index = nm_sriov_vf_get_index(vf);

    variant = nm_sriov_vf_get_attribute(vf, NM_SRIOV_VF_ATTRIBUTE_SPOOF_CHECK);
    if (variant)
        plat_vf->spoofchk = g_variant_get_boolean(variant);
    else
        plat_vf->spoofchk = -1;

    variant = nm_sriov_vf_get_attribute(vf, NM_SRIOV_VF_ATTRIBUTE_TRUST);
    if (variant)
        plat_vf->trust = g_variant_get_boolean(variant);
    else
        plat_vf->trust = -1;

    variant = nm_sriov_vf_get_attribute(vf, NM_SRIOV_VF_ATTRIBUTE_MAC);
    if (variant) {
        if (!_nm_utils_hwaddr_aton(g_variant_get_string(variant, NULL),
                                   plat_vf->mac.data,
                                   sizeof(plat_vf->mac.data),
                                   &length)) {
            g_set_error(error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_FAILED,
                        "invalid MAC %s",
                        g_variant_get_string(variant, NULL));
            return NULL;
        }
        if (length != priv->hw_addr_len) {
            g_set_error(error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_FAILED,
                        "wrong MAC length %" G_GSIZE_FORMAT ", should be %u",
                        length,
                        priv->hw_addr_len);
            return NULL;
        }
        plat_vf->mac.len = length;
    }

    variant = nm_sriov_vf_get_attribute(vf, NM_SRIOV_VF_ATTRIBUTE_MIN_TX_RATE);
    if (variant)
        plat_vf->min_tx_rate = g_variant_get_uint32(variant);

    variant = nm_sriov_vf_get_attribute(vf, NM_SRIOV_VF_ATTRIBUTE_MAX_TX_RATE);
    if (variant)
        plat_vf->max_tx_rate = g_variant_get_uint32(variant);

    plat_vf->num_vlans = num_vlans;
    plat_vf->vlans     = (NMPlatformVFVlan *) (&plat_vf[1]);
    for (i = 0; i < num_vlans; i++) {
        plat_vf->vlans[i].id  = vlan_ids[i];
        plat_vf->vlans[i].qos = nm_sriov_vf_get_vlan_qos(vf, vlan_ids[i]);
        plat_vf->vlans[i].proto_ad =
            nm_sriov_vf_get_vlan_protocol(vf, vlan_ids[i]) == NM_SRIOV_VF_VLAN_PROTOCOL_802_1AD;
    }

    return g_steal_pointer(&plat_vf);
}

static void
sriov_params_cb(GError *error, gpointer user_data)
{
    NMDevice                    *self;
    NMDevicePrivate             *priv;
    nm_auto_freev NMPlatformVF **plat_vfs = NULL;

    nm_utils_user_data_unpack(user_data, &self, &plat_vfs);

    if (nm_utils_error_is_cancelled_or_disposing(error))
        return;

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (error) {
        _LOGE(LOGD_DEVICE, "failed to set SR-IOV parameters: %s", error->message);
        nm_device_state_changed(self,
                                NM_DEVICE_STATE_FAILED,
                                NM_DEVICE_STATE_REASON_SRIOV_CONFIGURATION_FAILED);
        return;
    }

    if (!nm_platform_link_set_sriov_vfs(nm_device_get_platform(self),
                                        priv->ifindex,
                                        (const NMPlatformVF *const *) plat_vfs)) {
        _LOGW(LOGD_DEVICE, "failed to apply SR-IOV VF configurations");
    }

    priv->stage1_sriov_state = NM_DEVICE_STAGE_STATE_COMPLETED;

    nm_device_activate_schedule_stage1_device_prepare(self, FALSE);
}

/*
 * activate_stage1_device_prepare
 *
 * Prepare for device activation
 *
 */
static void
activate_stage1_device_prepare(NMDevice *self)
{
    NMDevicePrivate    *priv = NM_DEVICE_GET_PRIVATE(self);
    NMActStageReturn    ret  = NM_ACT_STAGE_RETURN_SUCCESS;
    NMActiveConnection *active;
    NMActiveConnection *master;
    NMDeviceClass      *klass;

    nm_assert((priv->ip_data_4.state == NM_DEVICE_IP_STATE_NONE)
              == (priv->ip_data_6.state == NM_DEVICE_IP_STATE_NONE));

    if (priv->ip_data_4.state == NM_DEVICE_IP_STATE_NONE) {
        _dev_ip_state_set_state(self, AF_INET, NM_DEVICE_IP_STATE_PENDING, "stage1");
        _dev_ip_state_set_state(self, AF_INET6, NM_DEVICE_IP_STATE_PENDING, "stage1");

        /* Notify the new ActiveConnection along with the state change */
        nm_dbus_track_obj_path_set(&priv->act_request, priv->act_request.obj, TRUE);

        priv->v4_route_table_initialized = FALSE;
        priv->v6_route_table_initialized = FALSE;
        priv->l3config_merge_flags_has   = FALSE;
    }

    nm_device_state_changed(self, NM_DEVICE_STATE_PREPARE, NM_DEVICE_STATE_REASON_NONE);

    if (priv->stage1_sriov_state != NM_DEVICE_STAGE_STATE_COMPLETED) {
        NMSettingSriov *s_sriov = NULL;

        if (nm_device_sys_iface_state_is_external_or_assume(self)) {
            /* pass */
        } else if (priv->stage1_sriov_state == NM_DEVICE_STAGE_STATE_PENDING) {
            return;
        } else if (priv->ifindex > 0) {
            s_sriov = nm_device_get_applied_setting(self, NM_TYPE_SETTING_SRIOV);
        }

        if (s_sriov) {
            nm_auto_freev NMPlatformVF **plat_vfs = NULL;
            gs_free_error GError        *error    = NULL;
            NMSriovVF                   *vf;
            NMTernary                    autoprobe;
            guint                        num;
            guint                        i;

            nm_assert(nm_device_has_capability(self, NM_DEVICE_CAP_SRIOV));

            autoprobe = nm_setting_sriov_get_autoprobe_drivers(s_sriov);
            if (autoprobe == NM_TERNARY_DEFAULT) {
                autoprobe = nm_config_data_get_connection_default_int64(
                    NM_CONFIG_GET_DATA,
                    NM_CON_DEFAULT("sriov.autoprobe-drivers"),
                    self,
                    NM_OPTION_BOOL_FALSE,
                    NM_OPTION_BOOL_TRUE,
                    NM_OPTION_BOOL_TRUE);
            }

            num      = nm_setting_sriov_get_num_vfs(s_sriov);
            plat_vfs = g_new0(NMPlatformVF *, num + 1);
            for (i = 0; i < num; i++) {
                vf          = nm_setting_sriov_get_vf(s_sriov, i);
                plat_vfs[i] = sriov_vf_config_to_platform(self, vf, &error);
                if (!plat_vfs[i]) {
                    _LOGE(LOGD_DEVICE,
                          "failed to apply SR-IOV VF '%s': %s",
                          nm_utils_sriov_vf_to_str(vf, FALSE, NULL),
                          error->message);
                    nm_device_state_changed(self,
                                            NM_DEVICE_STATE_FAILED,
                                            NM_DEVICE_STATE_REASON_SRIOV_CONFIGURATION_FAILED);
                    return;
                }
            }

            /* When changing the number of VFs the kernel can block
             * for very long time in the write to sysfs, especially
             * if autoprobe-drivers is enabled. Do it asynchronously
             * to avoid blocking the entire NM process.
             */
            sriov_op_queue(self,
                           nm_setting_sriov_get_total_vfs(s_sriov),
                           NM_TERNARY_TO_OPTION_BOOL(autoprobe),
                           sriov_params_cb,
                           nm_utils_user_data_pack(self, g_steal_pointer(&plat_vfs)));
            priv->stage1_sriov_state = NM_DEVICE_STAGE_STATE_PENDING;
            return;
        }

        priv->stage1_sriov_state = NM_DEVICE_STAGE_STATE_COMPLETED;
    }

    /* Assumed connections were already set up outside NetworkManager */
    klass = NM_DEVICE_GET_CLASS(self);

    if (klass->act_stage1_prepare_set_hwaddr_ethernet
        && !nm_device_sys_iface_state_is_external_or_assume(self)) {
        if (!nm_device_hw_addr_set_cloned(self, nm_device_get_applied_connection(self), FALSE)) {
            nm_device_state_changed(self,
                                    NM_DEVICE_STATE_FAILED,
                                    NM_DEVICE_STATE_REASON_CONFIG_FAILED);
            return;
        }
    }

    if (klass->act_stage1_prepare_also_for_external_or_assume
        || !nm_device_sys_iface_state_is_external_or_assume(self)) {
        nm_assert(!klass->act_stage1_prepare_also_for_external_or_assume
                  || klass->act_stage1_prepare);
        if (klass->act_stage1_prepare) {
            NMDeviceStateReason failure_reason = NM_DEVICE_STATE_REASON_NONE;

            ret = klass->act_stage1_prepare(self, &failure_reason);
            if (ret == NM_ACT_STAGE_RETURN_FAILURE) {
                nm_device_state_changed(self, NM_DEVICE_STATE_FAILED, failure_reason);
                return;
            }
            if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
                return;

            nm_assert(ret == NM_ACT_STAGE_RETURN_SUCCESS);
        }
    }

    active = NM_ACTIVE_CONNECTION(priv->act_request.obj);
    master = nm_active_connection_get_master(active);
    if (master) {
        if (nm_active_connection_get_state(master) >= NM_ACTIVE_CONNECTION_STATE_DEACTIVATING) {
            _LOGD(LOGD_DEVICE, "master connection is deactivating");
            nm_device_state_changed(self,
                                    NM_DEVICE_STATE_FAILED,
                                    NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED);
            return;
        }
        /* If the master connection is ready for slaves, attach ourselves */
        if (!nm_active_connection_get_master_ready(active)) {
            if (priv->master_ready_id == 0) {
                _LOGD(LOGD_DEVICE, "waiting for master connection to become ready");
                priv->master_ready_id =
                    g_signal_connect(active,
                                     "notify::" NM_ACTIVE_CONNECTION_INT_MASTER_READY,
                                     G_CALLBACK(master_ready_cb),
                                     self);
            }
            return;
        }
    }
    nm_clear_g_signal_handler(priv->act_request.obj, &priv->master_ready_id);
    if (master)
        master_ready(self, active);
    else if (priv->master) {
        nm_device_master_release_slave(priv->master,
                                       self,
                                       RELEASE_SLAVE_TYPE_CONFIG_FORCE,
                                       NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
    }

    nm_device_activate_schedule_stage2_device_config(self, TRUE);
}

void
nm_device_activate_schedule_stage1_device_prepare(NMDevice *self, gboolean do_sync)
{
    activation_source_invoke_or_schedule(self, activate_stage1_device_prepare, do_sync);
}

static NMActStageReturn
act_stage2_config(NMDevice *self, NMDeviceStateReason *out_failure_reason)
{
    return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
_lldp_neighbors_changed_cb(NMLldpListener *lldp_listener, gpointer user_data)
{
    _notify(user_data, PROP_LLDP_NEIGHBORS);
}

static void
lldp_setup(NMDevice *self, NMTernary enabled)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    int              ifindex;
    gboolean         notify_lldp_neighbors  = FALSE;
    gboolean         notify_interface_flags = FALSE;

    ifindex = nm_device_get_ifindex(self);

    if (ifindex <= 0)
        enabled = FALSE;
    else if (enabled == NM_TERNARY_DEFAULT)
        enabled = _prop_get_connection_lldp(self);

    if (priv->lldp_listener) {
        if (!enabled || nm_lldp_listener_get_ifindex(priv->lldp_listener) != ifindex) {
            nm_clear_pointer(&priv->lldp_listener, nm_lldp_listener_destroy);
            notify_lldp_neighbors = TRUE;
        }
    }

    if (enabled && !priv->lldp_listener) {
        gs_free_error GError *error = NULL;

        priv->lldp_listener =
            nm_lldp_listener_new(ifindex, _lldp_neighbors_changed_cb, self, &error);
        if (!priv->lldp_listener) {
            /* This really shouldn't happen. It's likely a bug. Investigate when this happens! */
            _LOGW(LOGD_DEVICE,
                  "LLDP listener for ifindex %d could not be started: %s",
                  ifindex,
                  error->message);
        } else
            notify_lldp_neighbors = TRUE;
    }

    notify_interface_flags = set_interface_flags(self,
                                                 NM_DEVICE_INTERFACE_FLAG_LLDP_CLIENT_ENABLED,
                                                 !!priv->lldp_listener,
                                                 FALSE);

    nm_gobject_notify_together(self,
                               notify_lldp_neighbors ? PROP_LLDP_NEIGHBORS : PROP_0,
                               notify_interface_flags ? PROP_INTERFACE_FLAGS : PROP_0);
}

/* set-mode can be:
 *  - TRUE: sync with new rules.
 *  - FALSE: sync, but remove all rules (== flush)
 *  - DEFAULT: forget about all the rules that we previously tracked,
 *       but don't actually remove them. This is when quitting NM
 *       we want to keep the rules.
 *       The problem is, after restart of NM, the rule manager will
 *       no longer remember that NM added these rules and treat them
 *       as externally added ones. Don't restart NetworkManager if
 *       you care about that.
 */
static void
_routing_rules_sync(NMDevice *self, NMTernary set_mode)
{
    NMDevicePrivate  *priv               = NM_DEVICE_GET_PRIVATE(self);
    NMPGlobalTracker *global_tracker     = nm_netns_get_global_tracker(nm_device_get_netns(self));
    NMDeviceClass    *klass              = NM_DEVICE_GET_CLASS(self);
    gboolean          untrack_only_dirty = FALSE;
    gboolean          keep_deleted_rules;
    gpointer          user_tag_1;
    gpointer          user_tag_2;

    /* take two arbitrary user-tag pointers that belong to @self. */
    user_tag_1 = &priv->v4_route_table;
    user_tag_2 = &priv->v6_route_table;

    if (set_mode == NM_TERNARY_TRUE) {
        NMConnection      *applied_connection;
        NMSettingIPConfig *s_ip;
        guint              i, num;
        int                is_ipv4;

        untrack_only_dirty = TRUE;

        applied_connection = nm_device_get_applied_connection(self);

        for (is_ipv4 = 0; applied_connection && is_ipv4 < 2; is_ipv4++) {
            int addr_family = is_ipv4 ? AF_INET : AF_INET6;

            s_ip = nm_connection_get_setting_ip_config(applied_connection, addr_family);
            if (!s_ip)
                continue;

            num = nm_setting_ip_config_get_num_routing_rules(s_ip);
            for (i = 0; i < num; i++) {
                NMPlatformRoutingRule plrule;
                NMIPRoutingRule      *rule;

                rule = nm_setting_ip_config_get_routing_rule(s_ip, i);
                nm_ip_routing_rule_to_platform(rule, &plrule);

                /* We track this rule, but we also make it explicitly not weakly-tracked
                 * (meaning to untrack NMP_GLOBAL_TRACKER_EXTERN_WEAKLY_TRACKED_USER_TAG at
                 * the same time). */
                nmp_global_tracker_track_rule(global_tracker,
                                              &plrule,
                                              10,
                                              user_tag_1,
                                              NMP_GLOBAL_TRACKER_EXTERN_WEAKLY_TRACKED_USER_TAG);
            }

            if (nm_setting_ip_config_get_replace_local_rule(s_ip) == NM_TERNARY_TRUE) {
                /* The user specified that the local rule should be replaced.
                 * In order to do that, we track the local rule with negative
                 * priority. */
                nmp_global_tracker_track_local_rule(
                    global_tracker,
                    addr_family,
                    -5,
                    user_tag_1,
                    NMP_GLOBAL_TRACKER_EXTERN_WEAKLY_TRACKED_USER_TAG);
            }
        }

        if (klass->get_extra_rules) {
            gs_unref_ptrarray GPtrArray *extra_rules = NULL;

            extra_rules = klass->get_extra_rules(self);
            if (extra_rules) {
                for (i = 0; i < extra_rules->len; i++) {
                    nmp_global_tracker_track_rule(
                        global_tracker,
                        NMP_OBJECT_CAST_ROUTING_RULE(extra_rules->pdata[i]),
                        10,
                        user_tag_2,
                        NMP_GLOBAL_TRACKER_EXTERN_WEAKLY_TRACKED_USER_TAG);
                }
            }
        }
    }

    nmp_global_tracker_untrack_all(global_tracker, user_tag_1, !untrack_only_dirty, TRUE);
    if (klass->get_extra_rules)
        nmp_global_tracker_untrack_all(global_tracker, user_tag_2, !untrack_only_dirty, TRUE);

    keep_deleted_rules = FALSE;
    if (set_mode == NM_TERNARY_DEFAULT) {
        /* when exiting NM, we leave the device up and the rules configured.
         * We just call nmp_global_tracker_sync() to forget about the synced rules,
         * but we don't actually delete them.
         *
         * FIXME: that is a problem after restart of NetworkManager, because these
         * rules will look like externally added, and NM will no longer remove
         * them.
         * To fix that, we could during "assume" mark the rules of the profile
         * as owned (and "added" by the device). The problem with that is that it
         * wouldn't cover rules that devices add by internal decision (not because
         * of a setting in the profile, e.g. WireGuard could setup policy routing).
         * Maybe it would be better to remember these orphaned rules at exit in a
         * file and track them after restart again. */
        keep_deleted_rules = TRUE;
    }
    nmp_global_tracker_sync(global_tracker, NMP_OBJECT_TYPE_ROUTING_RULE, keep_deleted_rules);
}

static gboolean
tc_commit(NMDevice *self)
{
    gs_unref_ptrarray GPtrArray *qdiscs   = NULL;
    gs_unref_ptrarray GPtrArray *tfilters = NULL;
    NMSettingTCConfig           *s_tc;
    NMPlatform                  *platform;
    int                          ip_ifindex;

    s_tc = nm_device_get_applied_setting(self, NM_TYPE_SETTING_TC_CONFIG);
    if (!s_tc)
        return TRUE;

    ip_ifindex = nm_device_get_ip_ifindex(self);
    if (!ip_ifindex)
        return FALSE;

    platform = nm_device_get_platform(self);
    qdiscs   = nm_utils_qdiscs_from_tc_setting(platform, s_tc, ip_ifindex);
    tfilters = nm_utils_tfilters_from_tc_setting(platform, s_tc, ip_ifindex);

    if (!nm_platform_tc_sync(platform, ip_ifindex, qdiscs, tfilters))
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
activate_stage2_device_config(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    NMDeviceClass   *klass;
    NMActStageReturn ret;
    NMSettingWired  *s_wired;
    gboolean         no_firmware = FALSE;
    SlaveInfo       *info;
    NMTernary        accept_all_mac_addresses;

    nm_device_state_changed(self, NM_DEVICE_STATE_CONFIG, NM_DEVICE_STATE_REASON_NONE);

    if (!nm_device_sys_iface_state_is_external(self)) {
        _ethtool_state_set(self);
        nm_device_link_properties_set(self, FALSE);
    }

    if (!nm_device_sys_iface_state_is_external(self)) {
        if (!priv->tc_committed && !tc_commit(self)) {
            _LOGW(LOGD_DEVICE, "failed applying traffic control rules");
            nm_device_state_changed(self,
                                    NM_DEVICE_STATE_FAILED,
                                    NM_DEVICE_STATE_REASON_CONFIG_FAILED);
            return;
        }
        priv->tc_committed = TRUE;
    }

    _routing_rules_sync(self, NM_TERNARY_TRUE);

    if (!nm_device_sys_iface_state_is_external_or_assume(self)) {
        if (!nm_device_bring_up_full(self, FALSE, TRUE, &no_firmware)) {
            nm_device_state_changed(self,
                                    NM_DEVICE_STATE_FAILED,
                                    no_firmware ? NM_DEVICE_STATE_REASON_FIRMWARE_MISSING
                                                : NM_DEVICE_STATE_REASON_CONFIG_FAILED);
            return;
        }
    }

    klass = NM_DEVICE_GET_CLASS(self);
    if (klass->act_stage2_config_also_for_external_or_assume
        || !nm_device_sys_iface_state_is_external_or_assume(self)) {
        NMDeviceStateReason failure_reason = NM_DEVICE_STATE_REASON_NONE;

        ret = klass->act_stage2_config(self, &failure_reason);
        if (ret == NM_ACT_STAGE_RETURN_POSTPONE)
            return;
        if (ret != NM_ACT_STAGE_RETURN_SUCCESS) {
            nm_assert(ret == NM_ACT_STAGE_RETURN_FAILURE);
            nm_device_state_changed(self, NM_DEVICE_STATE_FAILED, failure_reason);
            return;
        }
    }

    /* If we have slaves that aren't yet enslaved, do that now */
    c_list_for_each_entry (info, &priv->slaves, lst_slave) {
        NMDeviceState slave_state = nm_device_get_state(info->slave);

        if (slave_state == NM_DEVICE_STATE_IP_CONFIG)
            nm_device_master_enslave_slave(self,
                                           info->slave,
                                           nm_device_get_applied_connection(info->slave));
        else if (priv->act_request.obj && nm_device_sys_iface_state_is_external(self)
                 && slave_state <= NM_DEVICE_STATE_DISCONNECTED)
            nm_device_queue_recheck_assume(info->slave);
    }

    s_wired = nm_device_get_applied_setting(self, NM_TYPE_SETTING_WIRED);
    accept_all_mac_addresses =
        s_wired ? nm_setting_wired_get_accept_all_mac_addresses(s_wired) : NM_TERNARY_DEFAULT;
    if (accept_all_mac_addresses != NM_TERNARY_DEFAULT) {
        int ifindex = nm_device_get_ip_ifindex(self);

        if (ifindex > 0) {
            int ifi_flags =
                nm_platform_link_get_ifi_flags(nm_device_get_platform(self), ifindex, IFF_PROMISC);

            if (ifi_flags >= 0 && ((!!ifi_flags) != (!!accept_all_mac_addresses))) {
                nm_platform_link_change_flags(nm_device_get_platform(self),
                                              ifindex,
                                              IFF_PROMISC,
                                              !!accept_all_mac_addresses);
                if (priv->promisc_reset == NM_OPTION_BOOL_DEFAULT)
                    priv->promisc_reset = !accept_all_mac_addresses;
            }
        }
    }

    lldp_setup(self, NM_TERNARY_DEFAULT);

    nm_device_activate_schedule_stage3_ip_config(self, TRUE);
}

void
nm_device_activate_schedule_stage2_device_config(NMDevice *self, gboolean do_sync)
{
    activation_source_invoke_or_schedule(self, activate_stage2_device_config, do_sync);
}

/*****************************************************************************/

static void
_dev_ipllx_set_state(NMDevice *self, int addr_family, NMDeviceIPState state)
{
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);

    if (priv->ipll_data_x[IS_IPv4].state != state) {
        _LOGD_ipll(addr_family,
                   "set state %s (was %s)",
                   nm_device_ip_state_to_string(state),
                   nm_device_ip_state_to_string(priv->ipll_data_x[IS_IPv4].state));
        priv->ipll_data_x[IS_IPv4].state = state;
    }
}

static void
_dev_ipllx_cleanup(NMDevice *self, int addr_family)
{
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);

    if (IS_IPv4) {
        if (nm_clear_pointer(&priv->ipll_data_4.v4.ipv4ll, nm_l3_ipv4ll_unref))
            nm_clear_pointer(&priv->ipll_data_4.v4.ipv4ll_registation,
                             nm_l3_ipv4ll_register_remove);
        else
            nm_assert(!priv->ipll_data_4.v4.ipv4ll_registation);

        nm_clear_g_source_inst(&priv->ipll_data_4.v4.timeout_source);
    } else {
        nm_clear_pointer(&priv->ipll_data_6.v6.ipv6ll, nm_l3_ipv6ll_destroy);
        priv->ipll_data_6.v6.llstate = NM_L3_IPV6LL_STATE_NONE;
        priv->ipll_data_6.v6.lladdr  = nm_ip_addr_zero.addr6;
        nm_clear_g_source_inst(&priv->ipll_data_6.v6.retry_source);
    }

    _dev_l3_register_l3cds_set_one(self, L3_CONFIG_DATA_TYPE_LL_X(IS_IPv4), NULL, FALSE);

    _dev_ipllx_set_state(self, addr_family, NM_DEVICE_IP_STATE_NONE);
}

/*****************************************************************************/

static void
_dev_ipll4_notify_event(NMDevice *self)
{
    NMDevicePrivate      *priv = NM_DEVICE_GET_PRIVATE(self);
    NML3IPv4LLState       ipv4ll_state;
    const NML3ConfigData *l3cd;
    NMDeviceIPState       state;

    nm_assert(NM_IS_L3_IPV4LL(priv->ipll_data_4.v4.ipv4ll));
    nm_assert(priv->ipll_data_4.state >= NM_DEVICE_IP_STATE_PENDING);

    ipv4ll_state = nm_l3_ipv4ll_get_state(priv->ipll_data_4.v4.ipv4ll);

    if (nm_l3_ipv4ll_state_is_good(ipv4ll_state)) {
        l3cd = nm_l3_ipv4ll_get_l3cd(priv->ipll_data_4.v4.ipv4ll);
        nm_assert(NM_IS_L3_CONFIG_DATA(l3cd));
        nm_assert(!nm_l3_ipv4ll_is_timed_out(priv->ipll_data_4.v4.ipv4ll));
        state = NM_DEVICE_IP_STATE_READY;
    } else if (priv->ipll_data_4.v4.ipv4ll
               && nm_l3_ipv4ll_is_timed_out(priv->ipll_data_4.v4.ipv4ll)) {
        l3cd  = NULL;
        state = NM_DEVICE_IP_STATE_FAILED;
    } else {
        l3cd  = NULL;
        state = (priv->ipll_data_4.state == NM_DEVICE_IP_STATE_PENDING) ? NM_DEVICE_IP_STATE_PENDING
                                                                        : NM_DEVICE_IP_STATE_FAILED;
    }

    _dev_ipllx_set_state(self, AF_INET, state);

    _dev_l3_register_l3cds_set_one(self, L3_CONFIG_DATA_TYPE_LL_4, l3cd, FALSE);

    _dev_ip_state_check_async(self, AF_INET);
}

static void
_dev_ipll4_start(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    guint32          timeout_msec;

    if (priv->ipll_data_4.state >= NM_DEVICE_IP_STATE_PENDING)
        return;

    _dev_ipllx_set_state(self, AF_INET, NM_DEVICE_IP_STATE_PENDING);

    timeout_msec = _prop_get_ipv4_dad_timeout(self);
    if (timeout_msec == 0)
        timeout_msec = NM_ACD_TIMEOUT_RFC5227_MSEC;

    priv->ipll_data_4.v4.ipv4ll = nm_l3cfg_access_ipv4ll(priv->l3cfg);
    priv->ipll_data_4.v4.ipv4ll_registation =
        nm_l3_ipv4ll_register_new(priv->ipll_data_4.v4.ipv4ll, timeout_msec);
}

/*****************************************************************************/

static const char *
_device_get_dhcp_anycast_address(NMDevice *self)
{
    NMDeviceClass *klass;

    nm_assert(NM_IS_DEVICE(self));

    klass = NM_DEVICE_GET_CLASS(self);

    if (klass->get_dhcp_anycast_address)
        return klass->get_dhcp_anycast_address(self);

    return NULL;
}

/*****************************************************************************/

static IPDevStateData *
_dev_ipdev_data(NMDevice *self, int addr_family)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    switch (addr_family) {
    case AF_INET:
        return &priv->ipdev_data_4;
    case AF_INET6:
        return &priv->ipdev_data_6;
    default:
        nm_assert_not_reached();
        /* fall-through */
    case AF_UNSPEC:
        return &priv->ipdev_data_unspec;
    }
}

static void
_dev_ipdev_cleanup(NMDevice *self, int addr_family)
{
    IPDevStateData *p;

    p = _dev_ipdev_data(self, addr_family);
    if (p->state != NM_DEVICE_IP_STATE_NONE) {
        _LOGD_ipdev(addr_family, "reset state");
        p->state         = NM_DEVICE_IP_STATE_NONE;
        p->failed_reason = NM_DEVICE_STATE_REASON_NONE;
    }

    _dev_l3_register_l3cds_set_one(self, L3_CONFIG_DATA_TYPE_DEVIP(addr_family), NULL, FALSE);
}

NMDeviceIPState
nm_device_devip_get_state(NMDevice *self, int addr_family)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), NM_DEVICE_IP_STATE_NONE);

    return _dev_ipdev_data(self, addr_family)->state;
}

void
nm_device_devip_set_state_full(NMDevice             *self,
                               int                   addr_family,
                               NMDeviceIPState       ip_state,
                               const NML3ConfigData *l3cd,
                               NMDeviceStateReason   failed_reason)
{
    NMDevicePrivate *priv;
    IPDevStateData  *p;

    g_return_if_fail(NM_IS_DEVICE(self));

    priv = NM_DEVICE_GET_PRIVATE(self);

    nm_assert_addr_family_or_unspec(addr_family);
    nm_assert(NM_IN_SET(ip_state,
                        NM_DEVICE_IP_STATE_NONE,
                        NM_DEVICE_IP_STATE_PENDING,
                        NM_DEVICE_IP_STATE_READY,
                        NM_DEVICE_IP_STATE_FAILED));
    nm_assert(!l3cd || NM_IS_L3_CONFIG_DATA(l3cd));

    nm_assert((ip_state != NM_DEVICE_IP_STATE_FAILED)
              == (failed_reason == NM_DEVICE_STATE_REASON_NONE));
    nm_assert(NM_IN_SET(ip_state, NM_DEVICE_IP_STATE_PENDING, NM_DEVICE_IP_STATE_READY) || !l3cd);

    p = _dev_ipdev_data(self, addr_family);

    if (p->state == ip_state && p->failed_reason == failed_reason
        && priv->l3cds[L3_CONFIG_DATA_TYPE_DEVIP(addr_family)].d == l3cd)
        return;

    if (ip_state == NM_DEVICE_IP_STATE_FAILED) {
        _LOGD_ipdev(addr_family,
                    "set state=failed (reason %s)",
                    nm_device_state_reason_to_string_a(failed_reason));
    } else {
        _LOGD_ipdev(addr_family,
                    "set state=%s%s",
                    nm_device_ip_state_to_string(ip_state),
                    l3cd ? " (has extra IP configuration)" : "");
    }
    p->state         = ip_state;
    p->failed_reason = failed_reason;
    _dev_l3_register_l3cds_set_one(self, L3_CONFIG_DATA_TYPE_DEVIP(addr_family), l3cd, FALSE);
    _dev_ip_state_check_async(self, addr_family);
}

/*****************************************************************************/

static void
_dev_ipmanual_set_state(NMDevice *self, int addr_family, NMDeviceIPState state)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    int              IS_IPv4;

    if (addr_family == AF_UNSPEC) {
        _dev_ipmanual_set_state(self, AF_INET, state);
        _dev_ipmanual_set_state(self, AF_INET6, state);
        return;
    }

    IS_IPv4 = NM_IS_IPv4(addr_family);
    if (priv->ipmanual_data.state_x[IS_IPv4] != state) {
        _LOGD_ipmanual(addr_family, "set state %s", nm_device_ip_state_to_string(state));
        priv->ipmanual_data.state_x[IS_IPv4] = state;
    }
}

static void
_dev_ipmanual_cleanup(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->ipmanual_data.state_4 == NM_DEVICE_IP_STATE_NONE
        && priv->ipmanual_data.state_6 == NM_DEVICE_IP_STATE_NONE) {
        nm_assert(!priv->l3cds[L3_CONFIG_DATA_TYPE_MANUALIP].d);
        return;
    }

    _dev_ipmanual_set_state(self, AF_UNSPEC, NM_DEVICE_IP_STATE_NONE);
    nm_clear_g_source_inst(&priv->ipmanual_data.carrier_timeout);
    priv->ipmanual_data.carrier_timeout_expired = FALSE;

    _dev_l3_register_l3cds_set_one(self, L3_CONFIG_DATA_TYPE_MANUALIP, NULL, FALSE);

    _dev_ip_state_check_async(self, AF_INET);
    _dev_ip_state_check_async(self, AF_INET6);
}

static gboolean
_dev_ipmanual_carrier_timeout(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    priv->ipmanual_data.carrier_timeout_expired = TRUE;
    nm_clear_g_source_inst(&priv->ipmanual_data.carrier_timeout);
    _dev_ipmanual_check_ready(self);

    return G_SOURCE_CONTINUE;
}

static void
_dev_ipmanual_check_ready(NMDevice *self)
{
    NMDevicePrivate       *priv = NM_DEVICE_GET_PRIVATE(self);
    const NMPlatformLink  *plink;
    gboolean               has_carrier;
    NML3CfgCheckReadyFlags flags;
    gboolean               ready;
    gs_unref_array GArray *conflicts = NULL;
    int                    IS_IPv4;

    if (priv->ipmanual_data.state_4 != NM_DEVICE_IP_STATE_PENDING
        && priv->ipmanual_data.state_6 != NM_DEVICE_IP_STATE_PENDING) {
        /* we only care about PENDING to get it READY. Currently not other
         * conditions are implemented. That is, we cannot get to FAILED
         * (maybe we should, if DAD fails) and we cannot get from anything
         * once we are READY. */
        return;
    }

    plink       = nm_l3cfg_get_pllink(priv->l3cfg, TRUE);
    has_carrier = plink && NM_FLAGS_HAS(plink->n_ifi_flags, IFF_LOWER_UP);

    if (has_carrier) {
        nm_clear_g_source_inst(&priv->ipmanual_data.carrier_timeout);
    } else {
        if (priv->ipmanual_data.carrier_timeout_expired) {
            /* go on */
        } else if (priv->ipmanual_data.carrier_timeout) {
            /* wait a bit more until timer expires */
            return;
        } else {
            priv->ipmanual_data.carrier_timeout =
                nm_g_timeout_add_source(2000, G_SOURCE_FUNC(_dev_ipmanual_carrier_timeout), self);
            return;
        }
    }

    flags = NM_L3CFG_CHECK_READY_FLAGS_NONE;
    if (has_carrier) {
        flags |= NM_L3CFG_CHECK_READY_FLAGS_IP4_ACD_READY;
        flags |= NM_L3CFG_CHECK_READY_FLAGS_IP6_DAD_READY;
    }

    for (IS_IPv4 = 0; IS_IPv4 < 2; IS_IPv4++) {
        const int addr_family = IS_IPv4 ? AF_INET : AF_INET6;

        ready = nm_l3cfg_check_ready(priv->l3cfg,
                                     priv->l3cds[L3_CONFIG_DATA_TYPE_MANUALIP].d,
                                     addr_family,
                                     flags,
                                     &conflicts);
        if (conflicts) {
            _dev_ipmanual_set_state(self, addr_family, NM_DEVICE_IP_STATE_FAILED);
            _dev_ip_state_check_async(self, AF_UNSPEC);
        } else if (ready) {
            _dev_ipmanual_set_state(self, addr_family, NM_DEVICE_IP_STATE_READY);
            _dev_ip_state_check_async(self, AF_UNSPEC);
        }
    }
}

static void
_dev_ipmanual_start(NMDevice *self)
{
    NMDevicePrivate                         *priv = NM_DEVICE_GET_PRIVATE(self);
    nm_auto_unref_l3cd const NML3ConfigData *l3cd = NULL;

    if (priv->ipmanual_data.state_4 != NM_DEVICE_IP_STATE_NONE
        || priv->ipmanual_data.state_6 != NM_DEVICE_IP_STATE_NONE)
        return;

    if (nm_device_get_ip_ifindex(self) > 0) {
        l3cd =
            nm_device_create_l3_config_data_from_connection(self,
                                                            nm_device_get_applied_connection(self));
    }

    if (!l3cd) {
        _dev_ipmanual_cleanup(self);
        return;
    }

    /* Initially we set the state to pending, because we (maybe) have to perform ACD first. */
    _dev_ipmanual_set_state(self, AF_UNSPEC, NM_DEVICE_IP_STATE_PENDING);

    _dev_l3_register_l3cds_set_one(self, L3_CONFIG_DATA_TYPE_MANUALIP, l3cd, FALSE);

    _dev_ip_state_check_async(self, AF_UNSPEC);
}

/*****************************************************************************/

static void
_dev_ipdhcpx_set_state(NMDevice *self, int addr_family, NMDeviceIPState state)
{
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);

    if (priv->ipdhcp_data_x[IS_IPv4].state != state) {
        _LOGD_ipdhcp(addr_family,
                     "set state %s (was %s)",
                     nm_device_ip_state_to_string(state),
                     nm_device_ip_state_to_string(priv->ipdhcp_data_x[IS_IPv4].state));
        priv->ipdhcp_data_x[IS_IPv4].state = state;
    }
}

static void
_dev_ipdhcpx_cleanup(NMDevice *self, int addr_family, gboolean full_cleanup, gboolean release)
{
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);

    _dev_ipdhcpx_set_state(self, addr_family, NM_DEVICE_IP_STATE_NONE);

    if (full_cleanup && !IS_IPv4) {
        priv->ipdhcp_data_6.v6.mode            = NM_NDISC_DHCP_LEVEL_NONE;
        priv->ipdhcp_data_6.v6.needed_prefixes = 0;
    }

    if (full_cleanup)
        _dev_l3_register_l3cds_set_one(self, L3_CONFIG_DATA_TYPE_DHCP_X(IS_IPv4), NULL, FALSE);

    if (priv->ipdhcp_data_x[IS_IPv4].client) {
        nm_clear_g_signal_handler(priv->ipdhcp_data_x[IS_IPv4].client,
                                  &priv->ipdhcp_data_x[IS_IPv4].notify_sigid);
        nm_dhcp_client_stop(priv->ipdhcp_data_x[IS_IPv4].client, release);
        g_clear_object(&priv->ipdhcp_data_x[IS_IPv4].client);
    }

    if (full_cleanup && priv->ipdhcp_data_x[IS_IPv4].config) {
        gs_unref_object NMDhcpConfig *config =
            g_steal_pointer(&priv->ipdhcp_data_x[IS_IPv4].config);

        _notify(self, PROP_DHCPX_CONFIG(IS_IPv4));
        nm_dbus_object_unexport_on_idle(g_steal_pointer(&config));
    }

    _dev_ip_state_check_async(self, addr_family);
}

static void
_dev_ipdhcpx_handle_fail(NMDevice *self, int addr_family, const char *reason)
{
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);

    if (priv->ipdhcp_data_x[IS_IPv4].state == NM_DEVICE_IP_STATE_FAILED)
        return;

    _LOGT_ipdhcp(addr_family, "DHCP failing: %s", reason ?: "unknown reason");

    _dev_ipdhcpx_set_state(self, addr_family, NM_DEVICE_IP_STATE_FAILED);

    _dev_l3_register_l3cds_set_one(self, L3_CONFIG_DATA_TYPE_DHCP_X(IS_IPv4), NULL, FALSE);

    if (priv->ipdhcp_data_x[IS_IPv4].config)
        nm_dhcp_config_set_lease(priv->ipdhcp_data_x[IS_IPv4].config, NULL);

    _dev_ip_state_check_async(self, addr_family);
}

static void
_dev_ipdhcpx_notify(NMDhcpClient *client, const NMDhcpClientNotifyData *notify_data, NMDevice *self)
{
    NMDevicePrivate *priv        = NM_DEVICE_GET_PRIVATE(self);
    const int        addr_family = nm_dhcp_client_get_addr_family(client);
    const int        IS_IPv4     = NM_IS_IPv4(addr_family);

    nm_assert(notify_data);
    nm_assert(priv->ipdhcp_data_x[IS_IPv4].state > NM_DEVICE_IP_STATE_NONE);
    nm_assert(client && priv->ipdhcp_data_x[IS_IPv4].client == client);

    switch (notify_data->notify_type) {
    case NM_DHCP_CLIENT_NOTIFY_TYPE_PREFIX_DELEGATED:
        nm_assert(!IS_IPv4);
        /* Just re-emit. The device just contributes the prefix to the
         * pool in NMPolicy, which decides about subnet allocation
         * on the shared devices. */
        g_signal_emit(self, signals[IP6_PREFIX_DELEGATED], 0, notify_data->prefix_delegated.prefix);
        return;

    case NM_DHCP_CLIENT_NOTIFY_TYPE_NO_LEASE_TIMEOUT:
        /* Here we also fail if we had a lease and it expired. Maybe,
         * ipv[46].dhcp-timeout should only cover the time until we get
         * a lease for the first time. How it is here, it means that a
         * connection can fail after being connected successfully for a
         * longer time. */
        _dev_ipdhcpx_handle_fail(self, addr_family, "timeout getting lease");
        return;

    case NM_DHCP_CLIENT_NOTIFY_TYPE_IT_LOOKS_BAD:
        /* Like NM_DHCP_CLIENT_NOTIFY_TYPE_NO_LEASE_TIMEOUT, this does not
         * apply only if we never got a lease, but also after being fully
         * connected. We can also fail then. */
        _dev_ipdhcpx_handle_fail(self, addr_family, notify_data->it_looks_bad.reason);
        return;

    case NM_DHCP_CLIENT_NOTIFY_TYPE_LEASE_UPDATE:

        if (!notify_data->lease_update.l3cd) {
            _LOGT_ipdhcp(addr_family, "lease lost");
            goto lease_update_out;
        }

        if (notify_data->lease_update.accepted)
            _LOGT_ipdhcp(addr_family, "lease accepted");
        else
            _LOGT_ipdhcp(addr_family, "lease update");

        nm_dhcp_config_set_lease(priv->ipdhcp_data_x[IS_IPv4].config,
                                 notify_data->lease_update.l3cd);

        /* Schedule a commit of the configuration. If the DHCP client
         * needs to accept the lease, it will send later a LEASE_UPDATE
         * notification with accepted=1 once the address appears in platform.
         * Otherwise, this notification already has accepted=1. */
        _dev_l3_register_l3cds_set_one_full(self,
                                            L3_CONFIG_DATA_TYPE_DHCP_X(IS_IPv4),
                                            notify_data->lease_update.l3cd,
                                            FALSE);

        if (notify_data->lease_update.accepted) {
            nm_manager_write_device_state(priv->manager, self, NULL);
            nm_dispatcher_call_device(NM_DISPATCHER_ACTION_DHCP_CHANGE_X(IS_IPv4),
                                      self,
                                      NULL,
                                      NULL,
                                      NULL,
                                      NULL);
            if (priv->ipdhcp_data_x[IS_IPv4].state != NM_DEVICE_IP_STATE_READY) {
                _dev_ipdhcpx_set_state(self, addr_family, NM_DEVICE_IP_STATE_READY);
                _dev_ip_state_check_async(self, addr_family);
            }
        }

lease_update_out:
        nm_device_update_metered(self);
        return;
    }

    nm_assert_not_reached();
}

/*****************************************************************************/

static void
_dev_ipdhcpx_start(NMDevice *self, int addr_family)
{
    const int              IS_IPv4 = NM_IS_IPv4(addr_family);
    NMDevicePrivate       *priv    = NM_DEVICE_GET_PRIVATE(self);
    NMConnection          *connection;
    NMSettingConnection   *s_con;
    NMSettingIPConfig     *s_ip;
    const NML3ConfigData  *previous_lease;
    gs_unref_bytes GBytes *hwaddr       = NULL;
    gboolean               enforce_duid = FALSE;
    gs_free_error GError  *error        = NULL;
    const NMPlatformLink  *pllink;
    guint                  no_lease_timeout_sec;
    int                    ifindex;
    const char            *str;
    gboolean               request_broadcast;
    const char            *fail_reason;

    if (priv->ipdhcp_data_x[IS_IPv4].state == NM_DEVICE_IP_STATE_NONE)
        _dev_ipdhcpx_set_state(self, addr_family, NM_DEVICE_IP_STATE_PENDING);
    else if (priv->ipdhcp_data_x[IS_IPv4].state > NM_DEVICE_IP_STATE_PENDING) {
        /* already succeeded or failed */
        return;
    } else if (priv->ipdhcp_data_x[IS_IPv4].client) {
        /* DHCP client already started */
        return;
    }

    if (nm_device_sys_iface_state_is_external(self)) {
        fail_reason = nm_assert_unreachable_val("cannot run DHCP on external interface");
        goto out_fail;
    }

    connection = nm_device_get_applied_connection(self);
    if (!connection) {
        fail_reason = nm_assert_unreachable_val("no applied connection for starting DHCP");
        goto out_fail;
    }

    s_con = nm_connection_get_setting_connection(connection);
    s_ip  = nm_connection_get_setting_ip_config(connection, addr_family);
    nm_assert(s_con);
    nm_assert(s_ip);

    ifindex = 0;
    pllink  = nm_l3cfg_get_pllink(priv->l3cfg, TRUE);
    if (pllink) {
        ifindex = pllink->ifindex;
        nm_assert(ifindex > 0);
        nm_assert(ifindex == nm_device_get_ip_ifindex(self));
    }
    if (ifindex <= 0) {
        fail_reason = "cannot start DHCP without interface";
        goto out_fail;
    }

    hwaddr = nmp_link_address_get_as_bytes(&pllink->l_address);

    request_broadcast = FALSE;
    if (pllink) {
        str = nmp_object_link_udev_device_get_property_value(NMP_OBJECT_UP_CAST(pllink),
                                                             "ID_NET_DHCP_BROADCAST");
        if (str && _nm_utils_ascii_str_to_bool(str, FALSE)) {
            /* Use the device property ID_NET_DHCP_BROADCAST setting, which may be set for interfaces
             * requiring that the DHCPOFFER message is being broadcast because they can't handle unicast
             * messages while not fully configured.
             */
            request_broadcast = TRUE;
        }
    }

    if (!IS_IPv4
        && NM_IN_SET(priv->ipll_data_6.state,
                     NM_DEVICE_IP_STATE_NONE,
                     NM_DEVICE_IP_STATE_PENDING)) {
        _dev_ipll6_start(self);
        return;
    }

    no_lease_timeout_sec = _prop_get_ipvx_dhcp_timeout(self, addr_family);

    if (IS_IPv4) {
        NMDhcpClientConfig     config;
        gs_unref_bytes GBytes *bcast_hwaddr            = NULL;
        gs_unref_bytes GBytes *client_id               = NULL;
        gs_unref_bytes GBytes *vendor_class_identifier = NULL;
        const char *const     *reject_servers;
        const char            *hostname;
        gboolean               hostname_is_fqdn;

        client_id = _prop_get_ipv4_dhcp_client_id(self, connection, hwaddr);
        vendor_class_identifier =
            _prop_get_ipv4_dhcp_vendor_class_identifier(self, NM_SETTING_IP4_CONFIG(s_ip));
        reject_servers = nm_setting_ip_config_get_dhcp_reject_servers(s_ip, NULL);

        bcast_hwaddr = nmp_link_address_get_as_bytes(&pllink->l_broadcast);

        hostname = nm_setting_ip4_config_get_dhcp_fqdn(NM_SETTING_IP4_CONFIG(s_ip));
        if (hostname) {
            hostname_is_fqdn = TRUE;
        } else {
            hostname_is_fqdn = FALSE;
            hostname         = nm_setting_ip_config_get_dhcp_hostname(s_ip);
        }

        config = (NMDhcpClientConfig){
            .addr_family             = AF_INET,
            .l3cfg                   = nm_device_get_l3cfg(self),
            .iface                   = nm_device_get_ip_iface(self),
            .iface_type_log          = nm_device_get_type_desc_for_log(self),
            .uuid                    = nm_connection_get_uuid(connection),
            .hwaddr                  = hwaddr,
            .bcast_hwaddr            = bcast_hwaddr,
            .send_hostname           = nm_setting_ip_config_get_dhcp_send_hostname(s_ip),
            .hostname                = hostname,
            .hostname_flags          = _prop_get_ipvx_dhcp_hostname_flags(self, AF_INET),
            .client_id               = client_id,
            .mud_url                 = _prop_get_connection_mud_url(self, s_con),
            .timeout                 = no_lease_timeout_sec,
            .anycast_address         = _device_get_dhcp_anycast_address(self),
            .vendor_class_identifier = vendor_class_identifier,
            .use_fqdn                = hostname_is_fqdn,
            .reject_servers          = reject_servers,
            .v4 =
                {
                    .request_broadcast = request_broadcast,
                    .acd_timeout_msec  = _prop_get_ipv4_dad_timeout(self),
                },
            .previous_lease = priv->l3cds[L3_CONFIG_DATA_TYPE_DHCP_X(IS_IPv4)].d,
        };

        priv->ipdhcp_data_4.client =
            nm_dhcp_manager_start_client(nm_dhcp_manager_get(), &config, &error);
    } else {
        gs_unref_bytes GBytes *duid = NULL;
        gboolean               iaid_explicit;
        guint32                iaid;
        NMDhcpClientConfig     config;
        const char            *pd_hint;

        iaid = _prop_get_ipvx_dhcp_iaid(self, AF_INET6, connection, FALSE, &iaid_explicit);
        duid = _prop_get_ipv6_dhcp_duid(self, connection, hwaddr, &enforce_duid);

        config = (NMDhcpClientConfig){
            .addr_family     = AF_INET6,
            .l3cfg           = nm_device_get_l3cfg(self),
            .iface           = nm_device_get_ip_iface(self),
            .iface_type_log  = nm_device_get_type_desc_for_log(self),
            .uuid            = nm_connection_get_uuid(connection),
            .send_hostname   = nm_setting_ip_config_get_dhcp_send_hostname(s_ip),
            .hostname        = nm_setting_ip_config_get_dhcp_hostname(s_ip),
            .hostname_flags  = _prop_get_ipvx_dhcp_hostname_flags(self, AF_INET6),
            .client_id       = duid,
            .mud_url         = _prop_get_connection_mud_url(self, s_con),
            .timeout         = no_lease_timeout_sec,
            .anycast_address = _device_get_dhcp_anycast_address(self),
            .v6 =
                {
                    .enforce_duid  = enforce_duid,
                    .iaid          = iaid,
                    .iaid_explicit = iaid_explicit,
                    .info_only     = (priv->ipdhcp_data_6.v6.mode == NM_NDISC_DHCP_LEVEL_OTHERCONF),
                    .needed_prefixes = priv->ipdhcp_data_6.v6.needed_prefixes,
                },
        };

        pd_hint = nm_setting_ip6_config_get_dhcp_pd_hint(NM_SETTING_IP6_CONFIG(s_ip));
        if (pd_hint) {
            int      pd_hint_length;
            gboolean res;

            res = nm_inet_parse_with_prefix_bin(AF_INET6,
                                                pd_hint,
                                                NULL,
                                                &config.v6.pd_hint_addr,
                                                &pd_hint_length);
            nm_assert(res);
            nm_assert(pd_hint_length > 0 && pd_hint_length <= 128);
            config.v6.pd_hint_length = pd_hint_length;
        }

        priv->ipdhcp_data_6.client =
            nm_dhcp_manager_start_client(nm_dhcp_manager_get(), &config, &error);
    }

    if (!priv->ipdhcp_data_x[IS_IPv4].client) {
        fail_reason = error->message;
        goto out_fail;
    }

    priv->ipdhcp_data_x[IS_IPv4].notify_sigid =
        g_signal_connect(priv->ipdhcp_data_x[IS_IPv4].client,
                         NM_DHCP_CLIENT_NOTIFY,
                         G_CALLBACK(_dev_ipdhcpx_notify),
                         self);

    /* Take the NML3ConfigData from the previous lease (if any) that was passed to the NMDhcpClient.
     * This may be the old lease only used during the duration of a reapply until we get the
     * new lease. */
    previous_lease = nm_dhcp_client_get_lease(priv->ipdhcp_data_x[IS_IPv4].client);

    if (!priv->ipdhcp_data_x[IS_IPv4].config) {
        priv->ipdhcp_data_x[IS_IPv4].config = nm_dhcp_config_new(addr_family, previous_lease);
        _notify(self, PROP_DHCPX_CONFIG(IS_IPv4));
    }

    if (previous_lease) {
        nm_dhcp_config_set_lease(priv->ipdhcp_data_x[IS_IPv4].config, previous_lease);
        _dev_l3_register_l3cds_set_one_full(self,
                                            L3_CONFIG_DATA_TYPE_DHCP_X(IS_IPv4),
                                            previous_lease,
                                            FALSE);
    }

    return;

out_fail:
    _dev_ipdhcpx_handle_fail(self, addr_family, fail_reason);
}

static void
_dev_ipdhcpx_start_continue(NMDevice *self, int addr_family)
{
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);

    if (priv->ipdhcp_data_x[IS_IPv4].state != NM_DEVICE_IP_STATE_NONE)
        _dev_ipdhcpx_start(self, addr_family);
}

static void
_dev_ipdhcpx_restart(NMDevice *self, int addr_family, gboolean release)
{
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);

    if (priv->ipdhcp_data_x[IS_IPv4].state != NM_DEVICE_IP_STATE_NONE) {
        _LOGI_ipdhcp(addr_family, "restarting%s", release ? " (release lease)" : "");
        _dev_ipdhcpx_cleanup(self, addr_family, FALSE, release);
    }

    _dev_ipdhcpx_start(self, addr_family);
}

void
nm_device_ip_method_dhcp4_start(NMDevice *self)
{
    _dev_ipdhcpx_start(self, AF_INET);
}

static void
_dev_ipdhcp6_set_dhcp_level(NMDevice *self, NMNDiscDHCPLevel dhcp_level)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_assert(NM_IN_SET(dhcp_level,
                        NM_NDISC_DHCP_LEVEL_NONE,
                        NM_NDISC_DHCP_LEVEL_OTHERCONF,
                        NM_NDISC_DHCP_LEVEL_MANAGED));

    if (dhcp_level == NM_NDISC_DHCP_LEVEL_NONE && priv->ipdhcp_data_6.v6.needed_prefixes > 0)
        dhcp_level = NM_NDISC_DHCP_LEVEL_OTHERCONF;

    if (priv->ipdhcp_data_6.v6.mode == dhcp_level)
        return;

    _LOGD_ipdhcp(AF_INET6, "level: set to %s", nm_ndisc_dhcp_level_to_string(dhcp_level));

    if (dhcp_level == NM_NDISC_DHCP_LEVEL_NONE) {
        _dev_ipdhcpx_cleanup(self, AF_INET6, TRUE, TRUE);
        return;
    }

    priv->ipdhcp_data_6.v6.mode = dhcp_level;
    _dev_ipdhcpx_restart(self, AF_INET6, TRUE);
}

/*
 * Called on the requesting interface when a subnet can't be obtained
 * from known prefixes for a newly active shared connection.
 */
void
nm_device_request_ip6_prefixes(NMDevice *self, guint needed_prefixes)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->ipdhcp_data_6.v6.needed_prefixes == needed_prefixes)
        return;

    _LOGD(LOGD_IP6, "ipv6-pd: asking DHCPv6 for %u prefixes", needed_prefixes);

    priv->ipdhcp_data_6.v6.needed_prefixes = needed_prefixes;

    if (priv->ipdhcp_data_6.v6.mode == NM_NDISC_DHCP_LEVEL_NONE) {
        priv->ipdhcp_data_6.v6.mode = NM_NDISC_DHCP_LEVEL_OTHERCONF;
        _LOGD_ipdhcp(AF_INET6,
                     "level: set to %s",
                     nm_ndisc_dhcp_level_to_string(NM_NDISC_DHCP_LEVEL_OTHERCONF));
    }

    _dev_ipdhcpx_restart(self, AF_INET6, TRUE);
}

/*****************************************************************************/

static gboolean
connection_ip_method_requires_carrier(NMConnection *connection,
                                      int           addr_family,
                                      gboolean     *out_ip_enabled)
{
    const char *method;

    method = nm_utils_get_ip_config_method(connection, addr_family);

    if (NM_IS_IPv4(addr_family)) {
        NM_SET_OUT(out_ip_enabled, !nm_streq(method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED));
        return NM_IN_STRSET(method,
                            NM_SETTING_IP4_CONFIG_METHOD_AUTO,
                            NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL);
    }

    NM_SET_OUT(out_ip_enabled,
               !NM_IN_STRSET(method,
                             NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
                             NM_SETTING_IP6_CONFIG_METHOD_DISABLED));
    return NM_IN_STRSET(method,
                        NM_SETTING_IP6_CONFIG_METHOD_AUTO,
                        NM_SETTING_IP6_CONFIG_METHOD_DHCP,
                        NM_SETTING_IP6_CONFIG_METHOD_SHARED,
                        NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL);
}

static gboolean
connection_requires_carrier(NMConnection *connection)
{
    NMSettingIPConfig   *s_ip4;
    NMSettingIPConfig   *s_ip6;
    NMSettingConnection *s_con;
    gboolean             ip4_carrier_wanted;
    gboolean             ip6_carrier_wanted;
    gboolean             ip4_used = FALSE;
    gboolean             ip6_used = FALSE;

    /* We can progress to IP_CONFIG now, so that we're enslaved.
     * That may actually cause carrier to go up and thus continue activation. */
    s_con = nm_connection_get_setting_connection(connection);
    if (nm_setting_connection_get_master(s_con))
        return FALSE;

    ip4_carrier_wanted = connection_ip_method_requires_carrier(connection, AF_INET, &ip4_used);
    if (ip4_carrier_wanted) {
        /* If IPv4 wants a carrier and cannot fail, the whole connection
         * requires a carrier regardless of the IPv6 method.
         */
        s_ip4 = nm_connection_get_setting_ip4_config(connection);
        if (s_ip4 && !nm_setting_ip_config_get_may_fail(s_ip4))
            return TRUE;
    }

    ip6_carrier_wanted = connection_ip_method_requires_carrier(connection, AF_INET6, &ip6_used);
    if (ip6_carrier_wanted) {
        /* If IPv6 wants a carrier and cannot fail, the whole connection
         * requires a carrier regardless of the IPv4 method.
         */
        s_ip6 = nm_connection_get_setting_ip6_config(connection);
        if (s_ip6 && !nm_setting_ip_config_get_may_fail(s_ip6))
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
have_any_ready_slaves(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    SlaveInfo       *info;

    /* Any enslaved slave is "ready" in the generic case as it's
     * at least >= NM_DEVICE_STATE_IP_CONFIG and has had Layer 2
     * properties set up.
     */
    c_list_for_each_entry (info, &priv->slaves, lst_slave) {
        if (NM_DEVICE_GET_PRIVATE(info->slave)->is_enslaved)
            return TRUE;
    }
    return FALSE;
}

/*****************************************************************************/

gboolean
nm_device_needs_ip6_subnet(NMDevice *self)
{
    return NM_DEVICE_GET_PRIVATE(self)->needs_ip6_subnet;
}

/*
 * Called on the ipv6.method=shared interface when a new subnet is allocated
 * or the prefix from which it is allocated is renewed.
 */
void
nm_device_use_ip6_subnet(NMDevice *self, const NMPlatformIP6Address *subnet)
{
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    char                                    sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    NMPlatformIP6Address                    address;

    l3cd = nm_device_create_l3_config_data(self, NM_IP_CONFIG_SOURCE_SHARED);

    /* Assign a ::1 address in the subnet for us. */
    address = *subnet;
    address.address.s6_addr32[3] |= htonl(1);

    nm_l3_config_data_add_address_6(l3cd, &address);

    _LOGD(LOGD_IP6,
          "ipv6-pd: using %s",
          nm_platform_ip6_address_to_string(&address, sbuf, sizeof(sbuf)));

    _dev_l3_register_l3cds_set_one(self, L3_CONFIG_DATA_TYPE_PD_6, l3cd, FALSE);
    _dev_l3_cfg_commit(self, TRUE);
    _dev_ipac6_ndisc_set_router_config(self);
}

/*
 * Called whenever the policy picks a default IPv6 device.
 * The ipv6.method=shared devices just reuse its DNS configuration.
 */
void
nm_device_copy_ip6_dns_config(NMDevice *self, NMDevice *from_device)
{
    NMDevicePrivate                        *priv = NM_DEVICE_GET_PRIVATE(self);
    NMDevicePrivate                        *priv_src;
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd     = NULL;
    const NML3ConfigData                   *l3cd_src = NULL;

    /* FIXME(l3cfg): this entire code an approach seems flawed. It's flawed, because the
     *   very next RA will reset the changes. */

    if (priv->l3cds[L3_CONFIG_DATA_TYPE_AC_6].d) {
        l3cd = nm_l3_config_data_new_clone(priv->l3cds[L3_CONFIG_DATA_TYPE_AC_6].d, 0);
        nm_l3_config_data_clear_nameservers(l3cd, AF_INET6);
        nm_l3_config_data_clear_searches(l3cd, AF_INET6);
    } else
        l3cd = nm_device_create_l3_config_data(self, NM_IP_CONFIG_SOURCE_SHARED);

    if (from_device) {
        priv_src = NM_DEVICE_GET_PRIVATE(from_device);
        l3cd_src = priv_src->l3cds[L3_CONFIG_DATA_TYPE_AC_6].d;
    }
    if (l3cd_src) {
        const char *const *strvarr;
        const char *const *addrs;
        guint              n;
        guint              i;

        addrs = nm_l3_config_data_get_nameservers(l3cd_src, AF_INET6, &n);
        for (i = 0; i < n; i++)
            nm_l3_config_data_add_nameserver(l3cd, AF_INET6, addrs[i]);

        strvarr = nm_l3_config_data_get_searches(l3cd_src, AF_INET6, &n);
        for (i = 0; i < n; i++)
            nm_l3_config_data_add_search(l3cd, AF_INET6, strvarr[i]);
    }

    _dev_l3_register_l3cds_set_one(self, L3_CONFIG_DATA_TYPE_AC_6, l3cd, FALSE);

    _dev_l3_cfg_commit(self, TRUE);
}

/*****************************************************************************/

static gboolean
_dev_ipll6_state_retry_cb(gpointer user_data)
{
    NMDevice        *self = user_data;
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->ipll_data_6.v6.retry_source);
    _dev_ipll6_start(self);
    return G_SOURCE_CONTINUE;
}

static void
_dev_ipll6_set_llstate(NMDevice *self, NML3IPv6LLState llstate, const struct in6_addr *lladdr)
{
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    gboolean         changed = FALSE;
    NMDeviceIPState  state;
    NMDeviceIPState  old_state;

    if (!lladdr)
        lladdr = &nm_ip_addr_zero.addr6;

    if (priv->ipll_data_6.v6.llstate != llstate
        || !IN6_ARE_ADDR_EQUAL(&priv->ipll_data_6.v6.lladdr, lladdr)) {
        changed                      = TRUE;
        priv->ipll_data_6.v6.llstate = llstate;
        priv->ipll_data_6.v6.lladdr  = *lladdr;
    }

    nm_assert((priv->ipll_data_6.v6.ipv6ll
               && NM_IN_SET(priv->ipll_data_6.v6.llstate,
                            NM_L3_IPV6LL_STATE_STARTING,
                            NM_L3_IPV6LL_STATE_DAD_IN_PROGRESS,
                            NM_L3_IPV6LL_STATE_READY,
                            NM_L3_IPV6LL_STATE_DAD_FAILED))
              || (!priv->ipll_data_6.v6.ipv6ll
                  && NM_IN_SET(priv->ipll_data_6.v6.llstate,
                               NM_L3_IPV6LL_STATE_NONE,
                               NM_L3_IPV6LL_STATE_DEFUNCT,
                               NM_L3_IPV6LL_STATE_READY)));

    switch (priv->ipll_data_6.v6.llstate) {
    case NM_L3_IPV6LL_STATE_NONE:
        state = NM_DEVICE_IP_STATE_NONE;
        break;
    case NM_L3_IPV6LL_STATE_DEFUNCT:
    case NM_L3_IPV6LL_STATE_DAD_FAILED:
        state = NM_DEVICE_IP_STATE_FAILED;
        break;
    case NM_L3_IPV6LL_STATE_READY:
        state = NM_DEVICE_IP_STATE_READY;
        break;
    case NM_L3_IPV6LL_STATE_STARTING:
    case NM_L3_IPV6LL_STATE_DAD_IN_PROGRESS:
        state = NM_DEVICE_IP_STATE_PENDING;
        break;
    default:
        state = nm_assert_unreachable_val(NM_DEVICE_IP_STATE_FAILED);
        break;
    }

    old_state = priv->ipll_data_6.state;
    if (priv->ipll_data_6.state != state) {
        priv->ipll_data_6.state = state;
        changed                 = TRUE;
    }

    if (priv->ipll_data_6.v6.llstate != NM_L3_IPV6LL_STATE_DEFUNCT)
        nm_clear_g_source_inst(&priv->ipll_data_6.v6.retry_source);
    else if (!priv->ipll_data_6.v6.retry_source) {
        /* we schedule a timer to try to recover from this... Possibly some higher layer
         * will however fail the activation... */
        priv->ipll_data_6.v6.retry_source =
            nm_g_timeout_add_source(10000, _dev_ipll6_state_retry_cb, self);
    }

    if (changed) {
        char sbuf[NM_INET_ADDRSTRLEN];

        _LOGT_ipll(AF_INET6,
                   "set state %s (was %s, llstate=%s, lladdr=%s)",
                   nm_device_ip_state_to_string(priv->ipll_data_6.state),
                   nm_device_ip_state_to_string(old_state),
                   nm_l3_ipv6ll_state_to_string(priv->ipll_data_6.v6.llstate),
                   nm_ip_addr_is_null(AF_INET6, &priv->ipll_data_6.v6.lladdr)
                       ? "(none)"
                       : nm_inet6_ntop(&priv->ipll_data_6.v6.lladdr, sbuf));
    }

    if (changed)
        _dev_ip_state_check_async(self, AF_INET6);

    if (priv->ipll_data_6.v6.llstate == NM_L3_IPV6LL_STATE_READY) {
        /* if we got an IPv6LL address, we might poke some other methods
         * to progress... */
        _dev_ipac6_start_continue(self);
        _dev_ipdhcpx_start_continue(self, AF_INET6);
    }
}

static void
_dev_ipll6_state_change_cb(NML3IPv6LL            *ipv6ll,
                           NML3IPv6LLState        llstate,
                           const struct in6_addr *lladdr,
                           gpointer               user_data)
{
    _dev_ipll6_set_llstate(user_data, llstate, lladdr);
}

static void
_dev_ipll6_start(NMDevice *self)
{
    NMDevicePrivate       *priv = NM_DEVICE_GET_PRIVATE(self);
    NMConnection          *connection;
    gboolean               assume;
    const char            *ifname;
    NML3IPv6LLState        llstate;
    const struct in6_addr *lladdr;

    if (priv->ipll_data_6.v6.ipv6ll)
        return;

    if (NM_IS_DEVICE_LOOPBACK(self)) {
        _dev_ipll6_set_llstate(self, NM_L3_IPV6LL_STATE_READY, NULL);
        return;
    }

    if (!priv->l3cfg) {
        _LOGD(LOGD_IP6, "linklocal6: no IP link for IPv6");
        goto out_fail;
    }

    ifname = nm_device_get_ip_iface(self);
    if (!ifname) {
        _LOGD(LOGD_IP6, "linklocal6: no interface name for IPv6");
        goto out_fail;
    }

    connection = nm_device_get_applied_connection(self);

    assume = nm_device_sys_iface_state_is_external_or_assume(self);

    if (_prop_get_ipv6_addr_gen_mode(self) == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY) {
        NMUtilsStableType stable_type;
        const char       *stable_id;

        stable_id = _prop_get_connection_stable_id(self, connection, &stable_type);
        priv->ipll_data_6.v6.ipv6ll =
            nm_l3_ipv6ll_new_stable_privacy(priv->l3cfg,
                                            assume,
                                            stable_type,
                                            ifname,
                                            stable_id,
                                            nm_device_get_route_table(self, AF_INET6),
                                            _dev_ipll6_state_change_cb,
                                            self);
    } else {
        NMUtilsIPv6IfaceId iid;

        if (!nm_device_get_ip_iface_identifier(self, &iid, TRUE, NULL)) {
            _LOGW(LOGD_IP6, "linklocal6: failed to get interface identifier; IPv6 cannot continue");
            goto out_fail;
        }

        priv->ipll_data_6.v6.ipv6ll =
            nm_l3_ipv6ll_new_token(priv->l3cfg,
                                   assume,
                                   &iid,
                                   nm_device_get_route_table(self, AF_INET6),
                                   _dev_ipll6_state_change_cb,
                                   self);
    }

    llstate = nm_l3_ipv6ll_get_state(priv->ipll_data_6.v6.ipv6ll, &lladdr);
    _dev_ipll6_set_llstate(self, llstate, lladdr);
    return;

out_fail:
    _dev_ipll6_set_llstate(self, NM_L3_IPV6LL_STATE_DEFUNCT, NULL);
}

/*****************************************************************************/

gint64
nm_device_get_configured_mtu_from_connection_default(NMDevice   *self,
                                                     const char *property_name,
                                                     guint32     max_mtu)
{
    return nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                       property_name,
                                                       self,
                                                       0,
                                                       max_mtu,
                                                       -1);
}

guint32
nm_device_get_configured_mtu_from_connection(NMDevice          *self,
                                             GType              setting_type,
                                             NMDeviceMtuSource *out_source)
{
    const char   *global_property_name;
    NMConnection *connection;
    NMSetting    *setting;
    gint64        mtu_default;
    guint32       mtu     = 0;
    guint32       max_mtu = G_MAXUINT32;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(out_source);

    connection = nm_device_get_applied_connection(self);
    if (!connection)
        g_return_val_if_reached(0);

    setting = nm_connection_get_setting(connection, setting_type);

    if (setting_type == NM_TYPE_SETTING_WIRED) {
        if (setting)
            mtu = nm_setting_wired_get_mtu(NM_SETTING_WIRED(setting));
        global_property_name = NM_CON_DEFAULT("ethernet.mtu");
    } else if (setting_type == NM_TYPE_SETTING_WIRELESS) {
        if (setting)
            mtu = nm_setting_wireless_get_mtu(NM_SETTING_WIRELESS(setting));
        global_property_name = NM_CON_DEFAULT("wifi.mtu");
    } else if (setting_type == NM_TYPE_SETTING_INFINIBAND) {
        if (setting)
            mtu = nm_setting_infiniband_get_mtu(NM_SETTING_INFINIBAND(setting));
        global_property_name = NM_CON_DEFAULT("infiniband.mtu");
        max_mtu              = NM_INFINIBAND_MAX_MTU;
    } else if (setting_type == NM_TYPE_SETTING_IP_TUNNEL) {
        if (setting)
            mtu = nm_setting_ip_tunnel_get_mtu(NM_SETTING_IP_TUNNEL(setting));
        global_property_name = NM_CON_DEFAULT("ip-tunnel.mtu");
    } else if (setting_type == NM_TYPE_SETTING_WIREGUARD) {
        if (setting)
            mtu = nm_setting_wireguard_get_mtu(NM_SETTING_WIREGUARD(setting));
        global_property_name = NM_CON_DEFAULT("wireguard.mtu");
    } else if (setting_type == NM_TYPE_SETTING_LOOPBACK) {
        if (setting)
            mtu = nm_setting_loopback_get_mtu(NM_SETTING_LOOPBACK(setting));
        global_property_name = NM_CON_DEFAULT("loopback.mtu");
    } else
        g_return_val_if_reached(0);

    if (mtu) {
        *out_source = NM_DEVICE_MTU_SOURCE_CONNECTION;
        return mtu;
    }

    mtu_default =
        nm_device_get_configured_mtu_from_connection_default(self, global_property_name, max_mtu);
    if (mtu_default >= 0) {
        *out_source = NM_DEVICE_MTU_SOURCE_CONNECTION;
        return (guint32) mtu_default;
    }

    *out_source = NM_DEVICE_MTU_SOURCE_NONE;
    return 0;
}

guint32
nm_device_get_configured_mtu_for_wired(NMDevice          *self,
                                       NMDeviceMtuSource *out_source,
                                       gboolean          *out_force)
{
    return nm_device_get_configured_mtu_from_connection(self, NM_TYPE_SETTING_WIRED, out_source);
}

guint32
nm_device_get_configured_mtu_wired_parent(NMDevice          *self,
                                          NMDeviceMtuSource *out_source,
                                          gboolean          *out_force)
{
    guint32 mtu        = 0;
    guint32 parent_mtu = 0;
    int     ifindex;

    ifindex = nm_device_parent_get_ifindex(self);
    if (ifindex > 0) {
        parent_mtu = nm_platform_link_get_mtu(nm_device_get_platform(self), ifindex);
        if (parent_mtu >= NM_DEVICE_GET_CLASS(self)->mtu_parent_delta)
            parent_mtu -= NM_DEVICE_GET_CLASS(self)->mtu_parent_delta;
        else
            parent_mtu = 0;
    }

    mtu = nm_device_get_configured_mtu_for_wired(self, out_source, NULL);

    if (parent_mtu && mtu > parent_mtu) {
        /* Trying to set a MTU that is out of range from configuration:
         * fall back to the parent MTU and set force flag so that it
         * overrides an MTU with higher priority already configured.
         */
        *out_source = NM_DEVICE_MTU_SOURCE_PARENT;
        *out_force  = TRUE;
        return parent_mtu;
    }

    if (*out_source != NM_DEVICE_MTU_SOURCE_NONE) {
        nm_assert(mtu > 0);
        return mtu;
    }

    /* Inherit the MTU from parent device, if any */
    if (parent_mtu) {
        mtu         = parent_mtu;
        *out_source = NM_DEVICE_MTU_SOURCE_PARENT;
    }

    return mtu;
}

/*****************************************************************************/

static void
_set_mtu(NMDevice *self, guint32 mtu)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->mtu == mtu)
        return;

    priv->mtu = mtu;
    _notify(self, PROP_MTU);

    if (priv->master) {
        /* changing the MTU of a slave, might require the master to reset
         * its MTU. Note that the master usually cannot set a MTU larger
         * then the slave's. Hence, when the slave increases the MTU,
         * master might want to retry setting the MTU. */
        nm_device_commit_mtu(priv->master);
    }
}

static gboolean
set_platform_mtu(NMDevice *self, guint32 mtu)
{
    int r;

    r = nm_platform_link_set_mtu(nm_device_get_platform(self), nm_device_get_ip_ifindex(self), mtu);
    return (r != -NME_PL_CANT_SET_MTU);
}

static void
_commit_mtu(NMDevice *self)
{
    NMDevicePrivate      *priv   = NM_DEVICE_GET_PRIVATE(self);
    NMDeviceMtuSource     source = NM_DEVICE_MTU_SOURCE_NONE;
    NMSettingIPConfig    *s_ip6;
    const NML3ConfigData *l3cd;
    guint32               ip6_mtu_orig;
    guint32               ip6_mtu = 0;
    guint32               mtu_desired_orig;
    guint32               mtu_desired;
    guint32               mtu_plat;
    struct {
        gboolean initialized;
        guint32  value;
    } ip6_mtu_sysctl = {
        0,
    };
    int      ifindex;
    char     sbuf[64];
    char     sbuf1[64];
    char     sbuf2[64];
    gboolean success = TRUE;

    ifindex = nm_device_get_ip_ifindex(self);
    if (ifindex <= 0)
        return;

    if (!nm_device_get_applied_connection(self) || nm_device_sys_iface_state_is_external(self)) {
        /* we don't tamper with the MTU of disconnected and external devices. */
        return;
    }

    l3cd = nm_l3cfg_get_combined_l3cd(priv->l3cfg, FALSE);

    {
        guint32  mtu = 0;
        guint32  mtu2;
        gboolean force = FALSE;

        /* We take the MTU from various sources: (in order of increasing
         * priority) parent link, IP configuration (which contains the
         * MTU from DHCP/PPP), connection profile.
         *
         * We could just compare it with the platform MTU and apply it
         * when different, but this would revert at random times manual
         * changes done by the user with the MTU from the connection.
         *
         * Instead, we remember the source of the currently configured
         * MTU and apply the new one only when the new source has a
         * higher priority, so that we don't set a MTU from same source
         * multiple times. An exception to this is for the PARENT
         * source, since we need to keep tracking the parent MTU when it
         * changes.
         *
         * The subclass can set the @force argument to TRUE to signal that the
         * returned MTU should be applied even if it has a lower priority. This
         * is useful when the value from a lower source should
         * preempt the one from higher ones.
         */

        if (NM_DEVICE_GET_CLASS(self)->get_configured_mtu)
            mtu = NM_DEVICE_GET_CLASS(self)->get_configured_mtu(self, &source, &force);

        if (l3cd && !force && source < NM_DEVICE_MTU_SOURCE_IP_CONFIG
            && (mtu2 = nm_l3_config_data_get_mtu(l3cd)) > 0) {
            mtu    = mtu2;
            source = NM_DEVICE_MTU_SOURCE_IP_CONFIG;
        }

        if (mtu != 0) {
            _LOGT(LOGD_DEVICE,
                  "mtu: value %u from source '%s' (%u), current source '%s' (%u)%s",
                  (guint) mtu,
                  nm_device_mtu_source_to_string(source),
                  (guint) source,
                  nm_device_mtu_source_to_string(priv->mtu_source),
                  (guint) priv->mtu_source,
                  force ? " (forced)" : "");
        }

        if (mtu != 0
            && (force || source > priv->mtu_source
                || (priv->mtu_source == NM_DEVICE_MTU_SOURCE_PARENT && source == priv->mtu_source)))
            mtu_desired = mtu;
        else {
            mtu_desired = 0;
            source      = NM_DEVICE_MTU_SOURCE_NONE;
        }
    }

    s_ip6 = nm_device_get_applied_setting(self, NM_TYPE_SETTING_IP6_CONFIG);

    if (mtu_desired && mtu_desired < 1280) {
        if (s_ip6
            && !NM_IN_STRSET(nm_setting_ip_config_get_method(s_ip6),
                             NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
                             NM_SETTING_IP6_CONFIG_METHOD_DISABLED)) {
            /* the interface has IPv6 enabled. The MTU with IPv6 cannot be smaller
             * then 1280.
             *
             * For slave-devices (that don't have @s_ip6 we) don't do this fixup because
             * it's anyway an unsolved problem when the slave configures a conflicting
             * MTU. */
            mtu_desired = 1280;
        }
    }

    if (s_ip6)
        ip6_mtu = nm_setting_ip6_config_get_mtu(NM_SETTING_IP6_CONFIG(s_ip6));

    if (!ip6_mtu)
        ip6_mtu = priv->ip6_mtu;

    if (!ip6_mtu && priv->mtu_source == NM_DEVICE_MTU_SOURCE_NONE) {
        /* initially, if the IPv6 MTU is not specified, grow it as large as the
         * link MTU @mtu_desired. Only exception is, if @mtu_desired is so small
         * to disable IPv6. */
        if (mtu_desired >= 1280)
            ip6_mtu = mtu_desired;
    }

    if (!ip6_mtu && !mtu_desired)
        return;

    mtu_desired_orig = mtu_desired;
    ip6_mtu_orig     = ip6_mtu;

    mtu_plat = nm_platform_link_get_mtu(nm_device_get_platform(self), ifindex);

    if (ip6_mtu) {
        ip6_mtu = NM_MAX(1280, ip6_mtu);

        if (!mtu_desired)
            mtu_desired = mtu_plat;

        if (mtu_desired) {
            mtu_desired = NM_MAX(1280, mtu_desired);

            if (mtu_desired < ip6_mtu)
                ip6_mtu = mtu_desired;
        }
    }

#define _IP6_MTU_SYS()                                                                         \
    ({                                                                                         \
        if (!ip6_mtu_sysctl.initialized) {                                                     \
            ip6_mtu_sysctl.value       = nm_device_sysctl_ip_conf_get_int_checked(self,        \
                                                                            AF_INET6,    \
                                                                            "mtu",       \
                                                                            10,          \
                                                                            0,           \
                                                                            G_MAXUINT32, \
                                                                            0);          \
            ip6_mtu_sysctl.initialized = TRUE;                                                 \
        }                                                                                      \
        ip6_mtu_sysctl.value;                                                                  \
    })

    if (mtu_desired && NM_DEVICE_GET_CLASS(self)->mtu_force_set && !priv->mtu_force_set_done) {
        priv->mtu_force_set_done = TRUE;
        if (mtu_desired == mtu_plat) {
            if (!priv->mtu_initial && !priv->ip6_mtu_initial) {
                /* before touching any of the MTU parameters, record the
                 * original setting to restore on deactivation. */
                priv->mtu_initial     = mtu_plat;
                priv->ip6_mtu_initial = _IP6_MTU_SYS();
            }
            mtu_plat--;
            if (NM_DEVICE_GET_CLASS(self)->set_platform_mtu(self, mtu_desired - 1)) {
                _LOGD(LOGD_DEVICE, "mtu: force-set MTU to %u", mtu_desired - 1);
            } else
                _LOGW(LOGD_DEVICE, "mtu: failure to force-set MTU to %u", mtu_desired - 1);
        }
    }

    _LOGT(LOGD_DEVICE,
          "mtu: device-mtu: %u%s, ipv6-mtu: %u%s, ifindex: %d",
          (guint) mtu_desired,
          mtu_desired == mtu_desired_orig
              ? ""
              : nm_sprintf_buf(sbuf1, " (was %u)", (guint) mtu_desired_orig),
          (guint) ip6_mtu,
          ip6_mtu == ip6_mtu_orig ? "" : nm_sprintf_buf(sbuf2, " (was %u)", (guint) ip6_mtu_orig),
          ifindex);

    if ((mtu_desired && mtu_desired != mtu_plat) || (ip6_mtu && ip6_mtu != _IP6_MTU_SYS())) {
        gboolean anticipated_failure = FALSE;

        if (!priv->mtu_initial && !priv->ip6_mtu_initial) {
            /* before touching any of the MTU parameters, record the
             * original setting to restore on deactivation. */
            priv->mtu_initial     = mtu_plat;
            priv->ip6_mtu_initial = _IP6_MTU_SYS();
        }

        if (mtu_desired && mtu_desired != mtu_plat) {
            if (!NM_DEVICE_GET_CLASS(self)->set_platform_mtu(self, mtu_desired)) {
                anticipated_failure = TRUE;
                success             = FALSE;
                _LOGW(LOGD_DEVICE,
                      "mtu: failure to set MTU. %s",
                      NM_IS_DEVICE_VLAN(self)
                          ? "Is the parent's MTU size large enough?"
                          : (!c_list_is_empty(&priv->slaves)
                                 ? "Are the MTU sizes of the slaves large enough?"
                                 : "Did you configure the MTU correctly?"));
            }
            priv->carrier_wait_until_msec =
                nm_utils_get_monotonic_timestamp_msec() + CARRIER_WAIT_TIME_AFTER_MTU_MSEC;
        }

        if (ip6_mtu && ip6_mtu != _IP6_MTU_SYS()) {
            if (!nm_device_sysctl_ip_conf_set(self,
                                              AF_INET6,
                                              "mtu",
                                              nm_sprintf_buf(sbuf, "%u", (unsigned) ip6_mtu))) {
                int         errsv = errno;
                NMLogLevel  level = LOGL_WARN;
                const char *msg   = NULL;

                success = FALSE;

                if (anticipated_failure && errsv == EINVAL) {
                    level = LOGL_DEBUG;
                    msg   = "Is the underlying MTU value successfully set?";
                } else if (!g_file_test("/proc/sys/net/ipv6", G_FILE_TEST_IS_DIR)) {
                    level   = LOGL_DEBUG;
                    msg     = "IPv6 is disabled";
                    success = TRUE;
                }

                _NMLOG(level,
                       LOGD_DEVICE,
                       "mtu: failure to set IPv6 MTU%s%s",
                       msg ? ": " : "",
                       msg ?: "");
            }
            priv->carrier_wait_until_msec =
                nm_utils_get_monotonic_timestamp_msec() + CARRIER_WAIT_TIME_AFTER_MTU_MSEC;
        }
    }

    if (success && source != NM_DEVICE_MTU_SOURCE_NONE)
        priv->mtu_source = source;

#undef _IP6_MTU_SYS
}

void
nm_device_commit_mtu(NMDevice *self)
{
    NMDeviceState state;

    g_return_if_fail(NM_IS_DEVICE(self));

    state = nm_device_get_state(self);
    if (state >= NM_DEVICE_STATE_CONFIG && state < NM_DEVICE_STATE_DEACTIVATING) {
        _LOGT(LOGD_DEVICE, "mtu: commit-mtu...");
        _commit_mtu(self);
    } else
        _LOGT(LOGD_DEVICE,
              "mtu: commit-mtu... skip due to state %s",
              nm_device_state_to_string(state));
}

/*****************************************************************************/

static void
_dev_ipac6_ndisc_set_router_config(NMDevice *self)
{
    NMDevicePrivate      *priv = NM_DEVICE_GET_PRIVATE(self);
    const NML3ConfigData *l3cd;

    if (!priv->ipac6_data.ndisc)
        return;

    if (nm_ndisc_get_node_type(priv->ipac6_data.ndisc) != NM_NDISC_NODE_TYPE_ROUTER)
        return;

    /* FIXME(l3cfg): this doesn't seem right. What is the meaning of the l3cd at this
     * point? Also, when do we need to reset the config (and call this function again?). */
    l3cd = nm_l3cfg_get_combined_l3cd(priv->l3cfg, FALSE);
    if (l3cd)
        nm_ndisc_set_config(priv->ipac6_data.ndisc, l3cd);
}

static void
_dev_ipac6_set_state(NMDevice *self, NMDeviceIPState state)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->ipac6_data.state != state) {
        _LOGD_ipac6("set state: %s (was %s)",
                    nm_device_ip_state_to_string(state),
                    nm_device_ip_state_to_string(priv->ipac6_data.state));
        priv->ipac6_data.state = state;
    }
}

static void
_dev_ipac6_ndisc_config_changed(NMNDisc              *ndisc,
                                const NMNDiscData    *rdata,
                                guint                 changed_i,
                                const NML3ConfigData *l3cd,
                                NMDevice             *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    gboolean         ready;

    /* The ndisc configuration changes when we receive a new RA or
     * when a lifetime expires; but also when DAD fails for a
     * SLAAC address and we need to regenerate new stable-privacy
     * addresses. In all these cases we update the AC6 configuration,
     * schedule a commit and update the AC state. */

    _dev_ipac6_grace_period_start(self, 0, TRUE);

    _dev_l3_register_l3cds_set_one_full(self, L3_CONFIG_DATA_TYPE_AC_6, l3cd, FALSE);

    nm_clear_l3cd(&priv->ipac6_data.l3cd);
    ready = nm_l3cfg_check_ready(priv->l3cfg,
                                 l3cd,
                                 AF_INET6,
                                 NM_L3CFG_CHECK_READY_FLAGS_IP6_DAD_READY,
                                 NULL);
    if (ready) {
        _dev_ipac6_set_state(self, NM_DEVICE_IP_STATE_READY);
    } else {
        priv->ipac6_data.l3cd = nm_l3_config_data_ref(l3cd);
    }

    _dev_ipdhcp6_set_dhcp_level(self, rdata->dhcp_level);

    _dev_l3_cfg_commit(self, FALSE);

    _dev_ip_state_check_async(self, AF_INET6);
}

static void
_dev_ipac6_handle_timeout(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    _LOGD_ipac6("timeout for autoconf (IPv6 router advertisement) reached");

    nm_clear_g_source_inst(&priv->ipac6_data.ndisc_grace_source);

    _dev_ipac6_set_state(self, NM_DEVICE_IP_STATE_FAILED);

    _dev_ip_state_check_async(self, AF_INET6);
}

static void
_dev_ipac6_ndisc_ra_timeout(NMNDisc *ndisc, NMDevice *self)
{
    _dev_ipac6_handle_timeout(self);
}

static gboolean
_dev_ipac6_grace_period_expired(gpointer user_data)
{
    _dev_ipac6_handle_timeout(user_data);
    return G_SOURCE_REMOVE;
}

static gboolean
_dev_ipac6_grace_period_start(NMDevice *self, guint32 timeout_sec, gboolean force_restart)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    gboolean         stopped;

    /* In any other case (expired lease, assumed connection, etc.),
     * wait for some time before failing the IP method.
     */
    if (!force_restart && priv->ipac6_data.ndisc_grace_source) {
        /* already pending. */
        return FALSE;
    }

    /* Start a grace period equal to the RA timeout multiplied
     * by a constant factor. */

    stopped = nm_clear_g_source_inst(&priv->ipac6_data.ndisc_grace_source);

    if (timeout_sec == 0) {
        if (stopped)
            _LOGD_ipac6("grace period stopped");
        return FALSE;
    }

    nm_assert(timeout_sec <= G_MAXINT32);

    if (timeout_sec >= G_MAXUINT / (GRACE_PERIOD_MULTIPLIER * 1000u))
        timeout_sec = NM_RA_TIMEOUT_INFINITY;

    if (timeout_sec == NM_RA_TIMEOUT_INFINITY) {
        _LOGD_ipac6("grace period starts with infinity timeout");
        priv->ipac6_data.ndisc_grace_source = g_source_ref(nm_g_source_sentinel_get(0));
    } else {
        _LOGD_ipac6("grace period starts with %u seconds", timeout_sec);
        priv->ipac6_data.ndisc_grace_source =
            nm_g_timeout_add_source(timeout_sec * (GRACE_PERIOD_MULTIPLIER * 1000u),
                                    _dev_ipac6_grace_period_expired,
                                    self);
    }

    return TRUE;
}

static void
_dev_ipac6_start(NMDevice *self)
{
    NMDevicePrivate    *priv = NM_DEVICE_GET_PRIVATE(self);
    NMConnection       *connection;
    NMSettingIP6Config *s_ip = NULL;
    NMNDiscNodeType     node_type;
    NMUtilsStableType   stable_type;
    const char         *stable_id;
    int                 max_addresses;
    int                 router_solicitations;
    int                 router_solicitation_interval;
    guint32             ra_timeout;
    guint32             default_ra_timeout;
    NMUtilsIPv6IfaceId  iid;
    gboolean            is_token;

    if (priv->ipac6_data.state == NM_DEVICE_IP_STATE_NONE) {
        if (!g_file_test("/proc/sys/net/ipv6", G_FILE_TEST_IS_DIR)) {
            _LOGI_ipac6("addrconf6: kernel does not support IPv6");
            _dev_ipac6_set_state(self, NM_DEVICE_IP_STATE_FAILED);
            _dev_ip_state_check_async(self, AF_INET6);
            return;
        }

        _dev_ipac6_set_state(self, NM_DEVICE_IP_STATE_PENDING);
    }

    if (NM_IN_SET(priv->ipll_data_6.state, NM_DEVICE_IP_STATE_NONE, NM_DEVICE_IP_STATE_PENDING)) {
        _dev_ipac6_grace_period_start(self, 30, TRUE);
        _dev_ipll6_start(self);
        return;
    }

    if (priv->ipac6_data.ndisc) {
        /* we already started. Nothing to do. */
        return;
    }

    connection = nm_device_get_applied_connection(self);
    if (connection)
        s_ip = NM_SETTING_IP6_CONFIG(nm_connection_get_setting_ip6_config(connection));

    g_return_if_fail(s_ip);

    if (nm_streq(nm_device_get_effective_ip_config_method(self, AF_INET6),
                 NM_SETTING_IP6_CONFIG_METHOD_SHARED))
        node_type = NM_NDISC_NODE_TYPE_ROUTER;
    else
        node_type = NM_NDISC_NODE_TYPE_HOST;

    nm_ndisc_get_sysctl(nm_device_get_platform(self),
                        nm_device_get_ip_iface(self),
                        &max_addresses,
                        &router_solicitations,
                        &router_solicitation_interval,
                        &default_ra_timeout);

    if (node_type == NM_NDISC_NODE_TYPE_ROUTER)
        ra_timeout = 0u;
    else {
        ra_timeout = _prop_get_ipv6_ra_timeout(self);
        if (ra_timeout == 0u)
            ra_timeout = default_ra_timeout;
    }

    stable_id = _prop_get_connection_stable_id(self, connection, &stable_type);

    {
        const NMNDiscConfig config = {
            .l3cfg                        = nm_device_get_l3cfg(self),
            .ifname                       = nm_device_get_ip_iface(self),
            .stable_type                  = stable_type,
            .network_id                   = stable_id,
            .addr_gen_mode                = _prop_get_ipv6_addr_gen_mode(self),
            .node_type                    = node_type,
            .max_addresses                = max_addresses,
            .router_solicitations         = router_solicitations,
            .router_solicitation_interval = router_solicitation_interval,
            .ra_timeout                   = ra_timeout,
            .ip6_privacy                  = _prop_get_ipv6_ip6_privacy(self),
        };

        priv->ipac6_data.ndisc = nm_lndp_ndisc_new(&config);

        priv->ipac6_data.ndisc_changed_id =
            g_signal_connect(priv->ipac6_data.ndisc,
                             NM_NDISC_CONFIG_RECEIVED,
                             G_CALLBACK(_dev_ipac6_ndisc_config_changed),
                             self);
        priv->ipac6_data.ndisc_timeout_id =
            g_signal_connect(priv->ipac6_data.ndisc,
                             NM_NDISC_RA_TIMEOUT_SIGNAL,
                             G_CALLBACK(_dev_ipac6_ndisc_ra_timeout),
                             self);
    }

    if (nm_device_get_ip_iface_identifier(self, &iid, FALSE, &is_token)) {
        char buf[INET6_ADDRSTRLEN];

        _LOGD_ipac6("using the device EUI-64 identifier %s (from %s)",
                    nm_utils_inet6_interface_identifier_to_token(&iid, buf),
                    is_token ? "token" : "address");
        nm_ndisc_set_iid(priv->ipac6_data.ndisc, iid, is_token);
    } else {
        /* Don't abort the addrconf at this point -- if ndisc needs the iid
         * it will notice this itself. */
        _LOGD_ipac6("no interface identifier; IPv6 address creation may fail");
    }

    if (nm_ndisc_get_node_type(priv->ipac6_data.ndisc) == NM_NDISC_NODE_TYPE_ROUTER) {
        gs_free char *sysctl_value = NULL;

        sysctl_value = nm_device_sysctl_ip_conf_get(self, AF_INET6, "forwarding");
        if (!nm_streq0(sysctl_value, "1")) {
            if (sysctl_value && !g_hash_table_contains(priv->ip6_saved_properties, "forwarding")) {
                g_hash_table_insert(priv->ip6_saved_properties,
                                    "forwarding",
                                    g_steal_pointer(&sysctl_value));
            }
            nm_device_sysctl_ip_conf_set(self, AF_INET6, "forwarding", "1");
        }

        priv->needs_ip6_subnet = TRUE;
        g_signal_emit(self, signals[IP6_SUBNET_NEEDED], 0);
    }

    _dev_ipac6_ndisc_set_router_config(self);

    if (node_type == NM_NDISC_NODE_TYPE_ROUTER)
        _dev_ipac6_set_state(self, NM_DEVICE_IP_STATE_READY);

    _dev_ipac6_grace_period_start(self, ra_timeout, TRUE);

    nm_ndisc_start(priv->ipac6_data.ndisc);
}

void
nm_device_ip_method_autoconf6_start(NMDevice *self)
{
    _dev_ipac6_start(self);
}

static void
_dev_ipac6_start_continue(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->ipac6_data.state != NM_DEVICE_IP_STATE_NONE)
        _dev_ipac6_start(self);
}

static void
_dev_ipac6_cleanup(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->ipac6_data.ndisc_grace_source);
    nm_clear_l3cd(&priv->ipac6_data.l3cd);

    nm_clear_g_signal_handler(priv->ipac6_data.ndisc, &priv->ipac6_data.ndisc_changed_id);
    nm_clear_g_signal_handler(priv->ipac6_data.ndisc, &priv->ipac6_data.ndisc_timeout_id);

    _dev_l3_register_l3cds_set_one(self, L3_CONFIG_DATA_TYPE_AC_6, NULL, FALSE);

    if (priv->ipac6_data.ndisc) {
        nm_ndisc_stop(priv->ipac6_data.ndisc);
        g_clear_object(&priv->ipac6_data.ndisc);
    }

    _dev_ipac6_set_state(self, NM_DEVICE_IP_STATE_NONE);
}

/*****************************************************************************/

static void
_dev_sysctl_save_ip6_properties(NMDevice *self)
{
    static const char *const ip6_properties_to_save[] = {
        "accept_ra",
        "disable_ipv6",
        "hop_limit",
        "use_tempaddr",
    };
    NMDevicePrivate *priv     = NM_DEVICE_GET_PRIVATE(self);
    NMPlatform      *platform = nm_device_get_platform(self);
    const char      *ifname;
    char            *value;
    int              i;

    g_hash_table_remove_all(priv->ip6_saved_properties);

    ifname = nm_device_get_ip_iface_from_platform(self);
    if (!ifname)
        return;

    for (i = 0; i < G_N_ELEMENTS(ip6_properties_to_save); i++) {
        value =
            nm_platform_sysctl_ip_conf_get(platform, AF_INET6, ifname, ip6_properties_to_save[i]);
        if (value) {
            g_hash_table_insert(priv->ip6_saved_properties,
                                (char *) ip6_properties_to_save[i],
                                value);
        }
    }
}

static void
_dev_sysctl_restore_ip6_properties(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    GHashTableIter   iter;
    gpointer         key;
    gpointer         value;

    g_hash_table_iter_init(&iter, priv->ip6_saved_properties);
    while (g_hash_table_iter_next(&iter, &key, &value))
        nm_device_sysctl_ip_conf_set(self, AF_INET6, key, value);
}

static void
_dev_sysctl_set_disable_ipv6(NMDevice *self, gboolean do_disable)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    /* If we previously set addrgenmode=none, we are managing
     * IPv6 in user space and we should not disable it. */
    if (do_disable && priv->addrgenmode6_data.previous_mode_has
        && priv->addrgenmode6_data.previous_mode_val == NM_IN6_ADDR_GEN_MODE_NONE)
        return;

    nm_device_sysctl_ip_conf_set(self, AF_INET6, "disable_ipv6", do_disable ? "1" : "0");
}

/*****************************************************************************/

static void
_dev_addrgenmode6_set(NMDevice *self, guint8 addr_gen_mode)
{
    NMDevicePrivate      *priv    = NM_DEVICE_GET_PRIVATE(self);
    int                   ifindex = nm_device_get_ip_ifindex(self);
    const NMPlatformLink *plink;
    int                   r;
    int                   cur_addr_gen_mode;
    char                  sbuf[100];

    if (ifindex <= 0)
        return;

    plink = nm_platform_link_get(nm_device_get_platform(self), ifindex);
    if (!plink)
        return;

    cur_addr_gen_mode = _nm_platform_link_get_inet6_addr_gen_mode(plink);
    nm_assert(cur_addr_gen_mode >= 0 && cur_addr_gen_mode <= 255);

    if (!priv->addrgenmode6_data.previous_mode_has) {
        priv->addrgenmode6_data.previous_mode_has = TRUE;
        priv->addrgenmode6_data.previous_mode_val = cur_addr_gen_mode;
        nm_assert(priv->addrgenmode6_data.previous_mode_val == cur_addr_gen_mode);
    }

    _LOGD_ip(AF_INET6,
             "addrgenmode6: set %s%s",
             nm_platform_link_inet6_addrgenmode2str(addr_gen_mode, sbuf, sizeof(sbuf)),
             (cur_addr_gen_mode == addr_gen_mode) ? " (already set)" : "");

    if (cur_addr_gen_mode != addr_gen_mode) {
        r = nm_platform_link_set_inet6_addr_gen_mode(nm_device_get_platform(self),
                                                     ifindex,
                                                     addr_gen_mode);
        if (r < 0) {
            _NMLOG_ip(NM_IN_SET(r, -NME_PL_NOT_FOUND, -NME_PL_OPNOTSUPP) ? LOGL_DEBUG : LOGL_WARN,
                      AF_INET6,
                      "addrgenmode6: failed to set %s: (%s)",
                      nm_platform_link_inet6_addrgenmode2str(addr_gen_mode, sbuf, sizeof(sbuf)),
                      nm_strerror(r));
        } else {
            priv->addrgenmode6_data.previous_mode_val = addr_gen_mode;
        }
    }

    if (addr_gen_mode == NM_IN6_ADDR_GEN_MODE_NONE) {
        gs_free char *value = NULL;

        /* Bounce IPv6 to ensure the kernel stops IPv6LL address and temporary
         * address generation */
        _LOGD_ip(AF_INET6,
                 "addrgenmode6: toggle disable_ipv6 sysctl after disabling addr-gen-mode");
        value = nm_device_sysctl_ip_conf_get(self, AF_INET6, "disable_ipv6");
        if (nm_streq0(value, "0")) {
            nm_device_sysctl_ip_conf_set(self, AF_INET6, "disable_ipv6", "1");
            nm_device_sysctl_ip_conf_set(self, AF_INET6, "disable_ipv6", "0");
        }
    }
}

/*****************************************************************************/

static gboolean
ip_requires_slaves(NMDevice *self, int addr_family)
{
    const char *method;

    method = nm_device_get_effective_ip_config_method(self, addr_family);

    if (NM_IS_IPv4(addr_family))
        return nm_streq(method, NM_SETTING_IP4_CONFIG_METHOD_AUTO);

    /* SLAAC, DHCP, and Link-Local depend on connectivity (and thus slaves)
     * to complete addressing.  SLAAC and DHCP need a peer to provide a prefix.
     */
    return NM_IN_STRSET(method,
                        NM_SETTING_IP6_CONFIG_METHOD_AUTO,
                        NM_SETTING_IP6_CONFIG_METHOD_DHCP);
}

static const char *
get_ip_method_auto(NMDevice *self, int addr_family)
{
    return NM_IS_IPv4(addr_family) ? NM_SETTING_IP4_CONFIG_METHOD_AUTO
                                   : NM_SETTING_IP6_CONFIG_METHOD_AUTO;
}

static void
activate_stage3_ip_config_for_addr_family(NMDevice *self, int addr_family, const char *method)
{
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    NMDeviceClass   *klass   = NM_DEVICE_GET_CLASS(self);
    NMConnection    *connection;
    int              ip_ifindex;

    if (nm_device_sys_iface_state_is_external(self))
        goto out;

    connection = nm_device_get_applied_connection(self);
    g_return_if_fail(connection);

    ip_ifindex = nm_device_get_ip_ifindex(self);

    if (connection_ip_method_requires_carrier(connection, addr_family, NULL)
        && nm_device_is_master(self) && !priv->carrier) {
        if (!priv->ip_data_x[IS_IPv4].wait_for_carrier) {
            _LOGT_ip(addr_family, "waiting until carrier is on");
            priv->ip_data_x[IS_IPv4].wait_for_carrier = TRUE;
        }
        goto out;
    }
    if (priv->ip_data_x[IS_IPv4].wait_for_carrier) {
        _LOGT_ip(addr_family, "waiting until carrier completed");
        priv->ip_data_x[IS_IPv4].wait_for_carrier = FALSE;
    }

    if (nm_device_is_master(self) && ip_requires_slaves(self, addr_family)) {
        /* If the master has no ready slaves, and depends on slaves for
         * a successful IP configuration attempt, then postpone IP addressing.
         */
        if (!have_any_ready_slaves(self)) {
            if (!priv->ip_data_x[IS_IPv4].wait_for_ports) {
                _LOGT_ip(addr_family, "waiting for ports");
                priv->ip_data_x[IS_IPv4].wait_for_ports = TRUE;
            }
            goto out;
        }
    }
    if (priv->ip_data_x[IS_IPv4].wait_for_ports) {
        _LOGT_ip(addr_family, "waiting until ports completed");
        priv->ip_data_x[IS_IPv4].wait_for_ports = FALSE;
    }

    if (klass->ready_for_ip_config && !klass->ready_for_ip_config(self, FALSE))
        goto out_devip;

    if (IS_IPv4) {
        if (_prop_get_ipv4_link_local(self) == NM_SETTING_IP4_LL_ENABLED)
            _dev_ipll4_start(self);

        if (nm_streq(method, NM_SETTING_IP4_CONFIG_METHOD_AUTO))
            _dev_ipdhcpx_start(self, AF_INET);
        else if (nm_streq(method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL)) {
            /* pass */
        } else if (nm_streq(method, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
            _dev_ipshared4_start(self);
        else if (nm_streq(method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED))
            priv->ip_data_x[IS_IPv4].is_disabled = TRUE;
        else if (nm_streq(method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
            /* pass */
        } else
            nm_assert_not_reached();
    }

    if (!IS_IPv4) {
        if (nm_streq(method, NM_SETTING_IP6_CONFIG_METHOD_DISABLED)) {
            if (!priv->ip_data_x[IS_IPv4].is_disabled) {
                priv->ip_data_x[IS_IPv4].is_disabled = TRUE;
                nm_device_sysctl_ip_conf_set(self, AF_INET6, "disable_ipv6", "1");
            }
        } else if (nm_streq(method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)) {
            if (!priv->ip_data_x[IS_IPv4].is_ignore) {
                priv->ip_data_x[IS_IPv4].is_ignore = TRUE;
                if (priv->master) {
                    /* If a device only has an IPv6 link-local address,
                     * we don't generate an assumed connection. Therefore,
                     * when a new slave connection (without IP configuration)
                     * is activated on the device, the link-local address
                     * remains configured. The IP configuration of an activated
                     * slave should not depend on the previous state. Flush
                     * addresses and routes on activation.
                     */
                    if (ip_ifindex > 0) {
                        nm_platform_ip_route_flush(nm_device_get_platform(self),
                                                   AF_INET6,
                                                   ip_ifindex);
                        nm_platform_ip_address_flush(nm_device_get_platform(self),
                                                     AF_INET6,
                                                     ip_ifindex);
                    }
                } else {
                    /* When activating an IPv6 'ignore' connection we need to revert back
                     * to kernel IPv6LL, but the kernel won't actually assign an address
                     * to the interface until disable_ipv6 is bounced.
                     */
                    _dev_addrgenmode6_set(self, NM_IN6_ADDR_GEN_MODE_EUI64);
                    _dev_sysctl_set_disable_ipv6(self, TRUE);
                    _dev_sysctl_restore_ip6_properties(self);
                }
            }
        } else {
            _dev_ipll6_start(self);

            if (NM_IN_STRSET(method, NM_SETTING_IP6_CONFIG_METHOD_AUTO))
                _dev_ipac6_start(self);
            else if (NM_IN_STRSET(method, NM_SETTING_IP6_CONFIG_METHOD_SHARED))
                _dev_ipshared6_start(self);
            else if (nm_streq(method, NM_SETTING_IP6_CONFIG_METHOD_DHCP)) {
                priv->ipdhcp_data_6.v6.mode = NM_NDISC_DHCP_LEVEL_MANAGED;
                _dev_ipdhcpx_start(self, AF_INET6);
            } else
                nm_assert(NM_IN_STRSET(method,
                                       NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
                                       NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL));
        }
    }

out_devip:
    if (klass->act_stage3_ip_config)
        klass->act_stage3_ip_config(self, addr_family);

out:
    _dev_ip_state_check_async(self, addr_family);
}

static void
fw_change_zone_cb(NMFirewalldManager       *firewalld_manager,
                  NMFirewalldManagerCallId *call_id,
                  GError                   *error,
                  gpointer                  user_data)
{
    NMDevice        *self = user_data;
    NMDevicePrivate *priv;

    g_return_if_fail(NM_IS_DEVICE(self));

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->fw_call != call_id)
        g_return_if_reached();

    priv->fw_call = NULL;

    if (nm_utils_error_is_cancelled(error))
        return;

    switch (priv->fw_state) {
    case FIREWALL_STATE_WAIT_STAGE_3:
        priv->fw_state = FIREWALL_STATE_INITIALIZED;
        nm_device_activate_schedule_stage3_ip_config(self, TRUE);
        break;
    case FIREWALL_STATE_WAIT_IP_CONFIG:
        priv->fw_state = FIREWALL_STATE_INITIALIZED;
        if (priv->ip_data_4.state == NM_DEVICE_IP_STATE_READY
            || priv->ip_data_6.state == NM_DEVICE_IP_STATE_READY)
            nm_device_start_ip_check(self);
        break;
    case FIREWALL_STATE_INITIALIZED:
        break;
    default:
        g_return_if_reached();
    }
}

static void
fw_change_zone(NMDevice *self)
{
    NMDevicePrivate     *priv = NM_DEVICE_GET_PRIVATE(self);
    NMConnection        *applied_connection;
    NMSettingConnection *s_con;
    const char          *zone;

    nm_assert(priv->fw_state >= FIREWALL_STATE_INITIALIZED);

    applied_connection = nm_device_get_applied_connection(self);
    nm_assert(applied_connection);

    s_con = nm_connection_get_setting_connection(applied_connection);
    nm_assert(s_con);

    if (priv->fw_call) {
        nm_firewalld_manager_cancel_call(priv->fw_call);
        nm_assert(!priv->fw_call);
    }

    if (G_UNLIKELY(!priv->fw_mgr))
        priv->fw_mgr = g_object_ref(nm_firewalld_manager_get());

    zone = nm_setting_connection_get_zone(s_con);
#if WITH_FIREWALLD_ZONE
    if (!zone || zone[0] == '\0') {
        if (nm_streq0(nm_device_get_effective_ip_config_method(self, AF_INET),
                      NM_SETTING_IP4_CONFIG_METHOD_SHARED)
            || nm_streq0(nm_device_get_effective_ip_config_method(self, AF_INET6),
                         NM_SETTING_IP6_CONFIG_METHOD_SHARED))
            zone = "nm-shared";
    }
#endif
    priv->fw_call = nm_firewalld_manager_add_or_change_zone(priv->fw_mgr,
                                                            nm_device_get_ip_iface(self),
                                                            zone,
                                                            FALSE, /* change zone */
                                                            fw_change_zone_cb,
                                                            self);
}

static void
activate_stage3_ip_config(NMDevice *self)
{
    NMDevicePrivate *priv  = NM_DEVICE_GET_PRIVATE(self);
    NMDeviceClass   *klass = NM_DEVICE_GET_CLASS(self);
    int              ifindex;
    const char      *ipv4_method;
    const char      *ipv6_method;

    /* stage3 is different from stage1+2.
     *
     * What is true in all cases is that when we start a stage, we call the corresponding
     * nm_device_activate_schedule_stage*() function. But usually the stage cannot complete
     * right away but needs to wait for some things to happen. So the activate_stage*() function
     * returns, and will be later proceeded by calling *the same* stage again. That means,
     * activate_stage*() must be re-entrant and be called repeatedly until we can proceed
     * to the next stage. Only when the stage is completed, we schedule the next one.
     *
     * stage3 is different. It does IP configuration and as such (the stage handling itself)
     * cannot fail. If a failure happens (for example for DHCP), we remember that (in priv->ipdhcp_data_x)
     * and issue _dev_ip_state_check_async(). That one combines the DHCP state to determine the
     * overall per-address-family state (priv->ip_data_x). Those states are then combined
     * further into priv->combinedip_state, which then leads to nm_device_state_changed()
     * (which for example can make the device fully ACTIVATED or FAILED).
     *
     * The difference between stage1+2 and stage3 is that IP configuration is running continuously
     * while the device is active. As such the activate_stage3_ip_config() does not fail directly,
     * unlike the other stages which can abort via NM_ACT_STAGE_RETURN_FAILURE. */

    g_return_if_fail(priv->act_request.obj);

    ifindex = nm_device_get_ip_ifindex(self);

    ipv4_method = nm_device_get_effective_ip_config_method(self, AF_INET);
    if (nm_streq(ipv4_method, NM_SETTING_IP4_CONFIG_METHOD_AUTO)) {
        /* "auto" usually means DHCPv4 or autoconf6, but it doesn't have to be. Subclasses
         * can overwrite it. For example, you cannot run DHCPv4 on PPP/WireGuard links. */
        ipv4_method = klass->get_ip_method_auto(self, AF_INET);
    }

    ipv6_method = nm_device_get_effective_ip_config_method(self, AF_INET6);

    if (nm_streq(ipv6_method, NM_SETTING_IP6_CONFIG_METHOD_AUTO)) {
        ipv6_method = klass->get_ip_method_auto(self, AF_INET6);
    }

    if (priv->ip_data_4.do_reapply) {
        _LOGD_ip(AF_INET, "reapply...");
        priv->ip_data_4.do_reapply = FALSE;
        _cleanup_ip_pre(self,
                        AF_INET,
                        CLEANUP_TYPE_KEEP_REAPPLY,
                        nm_streq(ipv4_method, NM_SETTING_IP4_CONFIG_METHOD_AUTO));
    }
    if (priv->ip_data_6.do_reapply) {
        _LOGD_ip(AF_INET6, "reapply...");
        priv->ip_data_6.do_reapply = FALSE;
        _cleanup_ip_pre(self,
                        AF_INET6,
                        CLEANUP_TYPE_KEEP_REAPPLY,
                        nm_streq(ipv6_method, NM_SETTING_IP6_CONFIG_METHOD_AUTO));
    }

    /* Add the interface to the specified firewall zone */
    switch (priv->fw_state) {
    case FIREWALL_STATE_UNMANAGED:
        if (nm_device_sys_iface_state_is_external(self)) {
            /* fake success */
            priv->fw_state = FIREWALL_STATE_INITIALIZED;
        } else if (ifindex > 0) {
            priv->fw_state = FIREWALL_STATE_WAIT_STAGE_3;
            fw_change_zone(self);
            return;
        }
        /* no ifindex, nothing to do for now */
        break;
    case FIREWALL_STATE_WAIT_STAGE_3:
        /* a firewall call for stage3 is pending. Return and wait. */
        return;
    default:
        nm_assert(NM_IN_SET((FirewallState) priv->fw_state,
                            FIREWALL_STATE_INITIALIZED,
                            FIREWALL_STATE_WAIT_IP_CONFIG));
        break;
    }
    nm_assert(ifindex <= 0 || priv->fw_state == FIREWALL_STATE_INITIALIZED);

    if (priv->state < NM_DEVICE_STATE_IP_CONFIG) {
        _dev_ip_state_req_timeout_schedule(self, AF_INET);
        _dev_ip_state_req_timeout_schedule(self, AF_INET6);

        _active_connection_set_state_flags(self, NM_ACTIVATION_STATE_FLAG_LAYER2_READY);

        nm_device_state_changed(self, NM_DEVICE_STATE_IP_CONFIG, NM_DEVICE_STATE_REASON_NONE);

        /* Device should be up before we can do anything with it */
        if (!nm_device_sys_iface_state_is_external(self) && ifindex > 0
            && !nm_platform_link_is_up(nm_device_get_platform(self), ifindex))
            _LOGW(LOGD_DEVICE,
                  "interface %s not up for IP configuration",
                  nm_device_get_ip_iface(self));
    }

    /* We currently will attach ports in the state change NM_DEVICE_STATE_IP_CONFIG above.
     * Note that kernel changes the MTU of bond ports, so we want to commit the MTU
     * afterwards!
     *
     * This might reset the MTU to something different from the bond controller and
     * it might not be a working configuration. But it's what the user asked for, so
     * let's do it! */
    _commit_mtu(self);

    if (!nm_device_sys_iface_state_is_external(self)
        && (!klass->ready_for_ip_config || klass->ready_for_ip_config(self, TRUE))) {
        if (priv->ipmanual_data.state_6 == NM_DEVICE_IP_STATE_NONE
            && !NM_IN_STRSET(ipv6_method,
                             NM_SETTING_IP6_CONFIG_METHOD_DISABLED,
                             NM_SETTING_IP6_CONFIG_METHOD_IGNORE)) {
            /* Ensure the MTU makes sense. If it was below 1280 the kernel would not
             * expose any ipv6 sysctls or allow presence of any addresses on the interface,
             * including LL, which * would make it impossible to autoconfigure MTU to a
             * correct value. */
            _commit_mtu(self);

            /* Any method past this point requires an IPv6LL address. Use NM-controlled
             * IPv6LL if this is not an assumed connection, since assumed connections
             * will already have IPv6 set up.
             */
            if (!nm_device_sys_iface_state_is_external_or_assume(self))
                _dev_addrgenmode6_set(self, NM_IN6_ADDR_GEN_MODE_NONE);

            /* Re-enable IPv6 on the interface */
            nm_device_sysctl_ip_conf_set(self, AF_INET6, "accept_ra", "0");
            _dev_sysctl_set_disable_ipv6(self, FALSE);
        }

        _dev_ipmanual_start(self);
    }

    activate_stage3_ip_config_for_addr_family(self, AF_INET, ipv4_method);
    activate_stage3_ip_config_for_addr_family(self, AF_INET6, ipv6_method);
}

void
nm_device_activate_schedule_stage3_ip_config(NMDevice *self, gboolean do_sync)
{
    activation_source_invoke_or_schedule(self, activate_stage3_ip_config, do_sync);
}

/*****************************************************************************/

static void
_dev_ipsharedx_set_state(NMDevice *self, int addr_family, NMDeviceIPState state)
{
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);

    if (priv->ipshared_data_x[IS_IPv4].state != state) {
        _LOGD_ipshared(addr_family,
                       "set state %s (was %s)",
                       nm_device_ip_state_to_string(state),
                       nm_device_ip_state_to_string(priv->ipshared_data_x[IS_IPv4].state));
        priv->ipshared_data_x[IS_IPv4].state = state;
    }
}

static void
_dev_ipsharedx_cleanup(NMDevice *self, int addr_family)
{
    NMDevicePrivate *priv    = NM_DEVICE_GET_PRIVATE(self);
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);

    if (IS_IPv4) {
        if (priv->ipshared_data_4.v4.dnsmasq_manager) {
            nm_clear_g_signal_handler(priv->ipshared_data_4.v4.dnsmasq_manager,
                                      &priv->ipshared_data_4.v4.dnsmasq_state_id);
            nm_dnsmasq_manager_stop(priv->ipshared_data_4.v4.dnsmasq_manager);
            g_clear_object(&priv->ipshared_data_4.v4.dnsmasq_manager);
        }

        if (priv->ipshared_data_4.v4.firewall_config) {
            nm_firewall_config_apply_sync(priv->ipshared_data_4.v4.firewall_config, FALSE);
            nm_clear_pointer(&priv->ipshared_data_4.v4.firewall_config, nm_firewall_config_free);
        }

        nm_clear_pointer(&priv->ipshared_data_4.v4.shared_ip_handle, nm_netns_shared_ip_release);
        nm_clear_l3cd(&priv->ipshared_data_4.v4.l3cd);

        _dev_l3_register_l3cds_set_one(self, L3_CONFIG_DATA_TYPE_SHARED_4, NULL, FALSE);
    }

    _dev_ipsharedx_set_state(self, addr_family, NM_DEVICE_IP_STATE_NONE);
}

/*****************************************************************************/

static const NML3ConfigData *
_dev_ipshared4_new_l3cd(NMDevice *self, NMConnection *connection, NMPlatformIP4Address *out_addr4)
{
    NMDevicePrivate                        *priv = NM_DEVICE_GET_PRIVATE(self);
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    NMSettingIPConfig                      *s_ip4;
    NMPlatformIP4Address                    address = {
                           .addr_source = NM_IP_CONFIG_SOURCE_SHARED,
    };

    g_return_val_if_fail(self, NULL);
    g_return_val_if_fail(connection, NULL);

    s_ip4 = nm_connection_get_setting_ip4_config(connection);
    if (s_ip4 && nm_setting_ip_config_get_num_addresses(s_ip4) > 0) {
        /* Use the first user-supplied address */
        NMIPAddress *user = nm_setting_ip_config_get_address(s_ip4, 0);
        in_addr_t    a;

        nm_ip_address_get_address_binary(user, &a);
        nm_platform_ip4_address_set_addr(&address, a, nm_ip_address_get_prefix(user));
        nm_clear_pointer(&priv->ipshared_data_4.v4.shared_ip_handle, nm_netns_shared_ip_release);
    } else {
        if (!priv->ipshared_data_4.v4.shared_ip_handle)
            priv->ipshared_data_4.v4.shared_ip_handle =
                nm_netns_shared_ip_reserve(nm_device_get_netns(self));
        nm_platform_ip4_address_set_addr(&address,
                                         priv->ipshared_data_4.v4.shared_ip_handle->addr,
                                         24);
    }

    l3cd = nm_device_create_l3_config_data(self, NM_IP_CONFIG_SOURCE_SHARED);
    nm_l3_config_data_add_address_4(l3cd, &address);

    NM_SET_OUT(out_addr4, address);

    return nm_l3_config_data_seal(g_steal_pointer(&l3cd));
}

static gboolean
_dev_ipshared4_init(NMDevice *self)
{
    static const char *const modules_iptables[] = {"ip_tables", "iptable_nat"};
    static const char *const modules_nftables[] =
        {"nf_nat_ftp", "nf_nat_irc", "nf_nat_sip", "nf_nat_tftp", "nf_nat_pptp", "nf_nat_h323"};
    int   errsv;
    guint i;

    switch (nm_firewall_utils_get_backend()) {
    case NM_FIREWALL_BACKEND_IPTABLES:
        for (i = 0; i < G_N_ELEMENTS(modules_iptables); i++)
            nmp_utils_modprobe(NULL, FALSE, modules_iptables[i], NULL);
        break;
    case NM_FIREWALL_BACKEND_NFTABLES:
        for (i = 0; i < G_N_ELEMENTS(modules_nftables); i++)
            nmp_utils_modprobe(NULL, FALSE, modules_nftables[i], NULL);
        break;
    case NM_FIREWALL_BACKEND_NONE:
        /* do not modify network settings like ip forwarding */
        return TRUE;
    default:
        nm_assert_not_reached();
        break;
    }

    if (nm_platform_sysctl_get_int32(nm_device_get_platform(self),
                                     NMP_SYSCTL_PATHID_ABSOLUTE("/proc/sys/net/ipv4/ip_forward"),
                                     -1)
        == 1) {
        /* nothing to do. */
    } else if (!nm_platform_sysctl_set(nm_device_get_platform(self),
                                       NMP_SYSCTL_PATHID_ABSOLUTE("/proc/sys/net/ipv4/ip_forward"),
                                       "1")) {
        errsv = errno;
        _LOGW_ipshared(AF_INET, "error enabling IPv4 forwarding: %s", nm_strerror_native(errsv));
        return FALSE;
    }

    if (nm_platform_sysctl_get_int32(nm_device_get_platform(self),
                                     NMP_SYSCTL_PATHID_ABSOLUTE("/proc/sys/net/ipv4/ip_dynaddr"),
                                     -1)
        == 1) {
        /* nothing to do. */
    } else if (!nm_platform_sysctl_set(nm_device_get_platform(self),
                                       NMP_SYSCTL_PATHID_ABSOLUTE("/proc/sys/net/ipv4/ip_dynaddr"),
                                       "1")) {
        errsv = errno;
        _LOGD_ipshared(AF_INET,
                       "share: error enabling dynamic addresses: %s",
                       nm_strerror_native(errsv));
    }

    return TRUE;
}

static void
_dev_ipshared4_dnsmasq_state_changed_cb(NMDnsMasqManager *manager, guint status, gpointer user_data)
{
    NMDevice *self = NM_DEVICE(user_data);

    if (status != NM_DNSMASQ_STATUS_DEAD)
        return;

    _dev_ipsharedx_set_state(self, AF_INET, NM_DEVICE_IP_STATE_FAILED);
    _dev_ip_state_check_async(self, AF_INET);
}

static void
_dev_ipshared4_start(NMDevice *self)
{
    nm_auto_unref_l3cd const NML3ConfigData *l3cd = NULL;
    NMPlatformIP4Address                     ip4_addr;
    NMDevicePrivate                         *priv = NM_DEVICE_GET_PRIVATE(self);
    const char                              *ip_iface;
    NMConnection                            *applied;

    if (priv->ipshared_data_4.state != NM_DEVICE_IP_STATE_NONE)
        return;

    nm_assert(!priv->ipshared_data_4.v4.firewall_config);
    nm_assert(!priv->ipshared_data_4.v4.dnsmasq_manager);
    nm_assert(priv->ipshared_data_4.v4.dnsmasq_state_id == 0);

    ip_iface = nm_device_get_ip_iface(self);
    g_return_if_fail(ip_iface);

    applied = nm_device_get_applied_connection(self);
    g_return_if_fail(applied);

    _dev_ipsharedx_set_state(self, AF_INET, NM_DEVICE_IP_STATE_PENDING);

    l3cd = _dev_ipshared4_new_l3cd(self, applied, &ip4_addr);
    if (!l3cd) {
        nm_assert_not_reached();
        goto out_fail;
    }

    if (!_dev_ipshared4_init(self))
        goto out_fail;

    priv->ipshared_data_4.v4.firewall_config =
        nm_firewall_config_new_shared(ip_iface, ip4_addr.address, ip4_addr.plen);
    nm_firewall_config_apply_sync(priv->ipshared_data_4.v4.firewall_config, TRUE);

    priv->ipshared_data_4.v4.l3cd = nm_l3_config_data_ref(l3cd);
    _dev_l3_register_l3cds_set_one(self, L3_CONFIG_DATA_TYPE_SHARED_4, l3cd, FALSE);

    /* Wait that the address gets committed before spawning dnsmasq */
    return;
out_fail:
    _dev_ipsharedx_set_state(self, AF_INET, NM_DEVICE_IP_STATE_FAILED);
    _dev_ip_state_check_async(self, AF_INET);
}

static void
_dev_ipshared4_spawn_dnsmasq(NMDevice *self)
{
    NMDevicePrivate      *priv = NM_DEVICE_GET_PRIVATE(self);
    const char           *ip_iface;
    gs_free_error GError *error = NULL;
    NMSettingConnection  *s_con;
    gboolean              announce_android_metered;
    NMConnection         *applied;

    nm_assert(priv->ipshared_data_4.v4.firewall_config);
    nm_assert(priv->ipshared_data_4.v4.dnsmasq_state_id == 0);
    nm_assert(!priv->ipshared_data_4.v4.dnsmasq_manager);
    nm_assert(priv->ipshared_data_4.v4.l3cd);

    ip_iface = nm_device_get_ip_iface(self);
    g_return_if_fail(ip_iface);

    applied = nm_device_get_applied_connection(self);
    g_return_if_fail(applied);
    s_con = nm_connection_get_setting_connection(applied);

    switch (nm_setting_connection_get_metered(s_con)) {
    case NM_METERED_YES:
        /* honor the metered flag. Note that reapply on the device does not affect
         * the metered setting. This is different from other profiles, where the
         * metered flag of an activated profile can be changed (reapplied). */
        announce_android_metered = TRUE;
        break;
    case NM_METERED_UNKNOWN:
        /* we pick up the current value and announce it. But again, we cannot update
         * the announced setting without restarting dnsmasq. That means, if the default
         * route changes w.r.t. being metered, then the shared connection does not get
         * updated before reactivating. */
        announce_android_metered =
            NM_IN_SET(nm_manager_get_metered(NM_MANAGER_GET), NM_METERED_YES, NM_METERED_GUESS_YES);
        break;
    default:
        announce_android_metered = FALSE;
        break;
    }

    priv->ipshared_data_4.v4.dnsmasq_manager = nm_dnsmasq_manager_new(ip_iface);
    if (!nm_dnsmasq_manager_start(priv->ipshared_data_4.v4.dnsmasq_manager,
                                  priv->ipshared_data_4.v4.l3cd,
                                  announce_android_metered,
                                  &error)) {
        _LOGW_ipshared(AF_INET, "could not start dnsmasq: %s", error->message);
        goto out_fail;
    }

    priv->ipshared_data_4.v4.dnsmasq_state_id =
        g_signal_connect(priv->ipshared_data_4.v4.dnsmasq_manager,
                         NM_DNS_MASQ_MANAGER_STATE_CHANGED,
                         G_CALLBACK(_dev_ipshared4_dnsmasq_state_changed_cb),
                         self);

    _dev_ipsharedx_set_state(self, AF_INET, NM_DEVICE_IP_STATE_READY);
    _dev_ip_state_check_async(self, AF_INET);
    return;

out_fail:
    _dev_ipsharedx_set_state(self, AF_INET, NM_DEVICE_IP_STATE_FAILED);
    _dev_ip_state_check_async(self, AF_INET);
}

/*****************************************************************************/

static void
_dev_ipshared6_start(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    _dev_ipac6_start(self);

    if (priv->ipshared_data_6.state != NM_DEVICE_IP_STATE_NONE)
        return;

    if (!nm_platform_sysctl_set(
            nm_device_get_platform(self),
            NMP_SYSCTL_PATHID_ABSOLUTE("/proc/sys/net/ipv6/conf/all/forwarding"),
            "1")) {
        _LOGW_ipshared(AF_INET6, "failure to enable ipv6 forwarding");
        _dev_ipsharedx_set_state(self, AF_INET6, NM_DEVICE_IP_STATE_FAILED);
        _dev_ip_state_check_async(self, AF_INET6);
        return;
    }

    _dev_ipsharedx_set_state(self, AF_INET6, NM_DEVICE_IP_STATE_READY);
    _dev_ip_state_check_async(self, AF_INET6);
}

/*****************************************************************************/

static void
act_request_set(NMDevice *self, NMActRequest *act_request)
{
    NMDevicePrivate *priv;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(!act_request || NM_IS_ACT_REQUEST(act_request));

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (!priv->act_request.visible && priv->act_request.obj == act_request)
        return;

    /* always clear the public flag. The few callers that set a new @act_request
     * don't want that the property is public yet.  */
    nm_dbus_track_obj_path_set(&priv->act_request, act_request, FALSE);

    if (act_request) {
        switch (nm_active_connection_get_activation_type(NM_ACTIVE_CONNECTION(act_request))) {
        case NM_ACTIVATION_TYPE_EXTERNAL:
            break;
        case NM_ACTIVATION_TYPE_ASSUME:
            if (priv->sys_iface_state == NM_DEVICE_SYS_IFACE_STATE_EXTERNAL)
                nm_device_sys_iface_state_set(self, NM_DEVICE_SYS_IFACE_STATE_ASSUME);
            break;
        case NM_ACTIVATION_TYPE_MANAGED:
            if (NM_IN_SET_TYPED(NMDeviceSysIfaceState,
                                priv->sys_iface_state,
                                NM_DEVICE_SYS_IFACE_STATE_EXTERNAL,
                                NM_DEVICE_SYS_IFACE_STATE_ASSUME))
                nm_device_sys_iface_state_set(self, NM_DEVICE_SYS_IFACE_STATE_MANAGED);
            break;
        }
    }
}

gboolean
nm_device_is_nm_owned(NMDevice *self)
{
    return NM_DEVICE_GET_PRIVATE(self)->nm_owned;
}

/*
 * delete_on_deactivate_link_delete
 *
 * Function will be queued with g_idle_add to call
 * nm_platform_link_delete for the underlying resources
 * of the device.
 */
static gboolean
delete_on_deactivate_link_delete(gpointer user_data)
{
    nm_auto_unref_object NMDevice *self  = user_data;
    NMDevicePrivate               *priv  = NM_DEVICE_GET_PRIVATE(self);
    gs_free_error GError          *error = NULL;

    _LOGD(LOGD_DEVICE, "delete_on_deactivate: cleanup and delete virtual link");

    nm_clear_g_source_inst(&priv->delete_on_deactivate_idle_source);

    if (!nm_device_unrealize(self, TRUE, &error))
        _LOGD(LOGD_DEVICE, "delete_on_deactivate: unrealizing failed (%s)", error->message);

    if (nm_dbus_object_is_exported(NM_DBUS_OBJECT(self))) {
        /* The device is still alive. We may need to autoactivate virtual
         * devices again. */
        nm_device_recheck_auto_activate_schedule(self);
    }

    return G_SOURCE_CONTINUE;
}

static void
delete_on_deactivate_unschedule(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (nm_clear_g_source_inst(&priv->delete_on_deactivate_idle_source)) {
        _LOGD(LOGD_DEVICE, "delete_on_deactivate: cancel cleanup and delete virtual link");
        g_object_unref(self);
    }
}

static void
delete_on_deactivate_check_and_schedule(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (!priv->nm_owned)
        return;
    if (priv->queued_act_request)
        return;
    if (!nm_device_is_software(self) || !nm_device_is_real(self))
        return;
    if (nm_device_get_state(self) == NM_DEVICE_STATE_UNMANAGED)
        return;

    g_object_ref(self);
    delete_on_deactivate_unschedule(self); /* always cancel and reschedule */
    priv->delete_on_deactivate_idle_source =
        nm_g_idle_add_source(delete_on_deactivate_link_delete, self);

    _LOGD(LOGD_DEVICE, "delete_on_deactivate: schedule cleanup and delete virtual link");
}

static void
_cleanup_ip_pre(NMDevice *self, int addr_family, CleanupType cleanup_type, gboolean preserve_dhcp)
{
    const int        IS_IPv4      = NM_IS_IPv4(addr_family);
    NMDevicePrivate *priv         = NM_DEVICE_GET_PRIVATE(self);
    gboolean         keep_reapply = (cleanup_type == CLEANUP_TYPE_KEEP_REAPPLY);

    _dev_ipsharedx_cleanup(self, addr_family);

    _dev_ipdev_cleanup(self, AF_UNSPEC);
    _dev_ipdev_cleanup(self, addr_family);

    _dev_ipdhcpx_cleanup(self, addr_family, !preserve_dhcp || !keep_reapply, FALSE);

    if (!IS_IPv4)
        _dev_ipac6_cleanup(self);

    _dev_ipllx_cleanup(self, addr_family);

    _dev_ipmanual_cleanup(self);

    nm_clear_g_signal_handler(nm_manager_get_dns_manager(priv->manager),
                              &priv->ip_data.dnsmgr_update_pending_signal_id);

    _dev_ip_state_cleanup(self, AF_UNSPEC, keep_reapply);
    _dev_ip_state_cleanup(self, addr_family, keep_reapply);
}

gboolean
_nm_device_hash_check_invalid_keys(GHashTable        *hash,
                                   const char        *setting_name,
                                   GError           **error,
                                   const char *const *whitelist)
{
    guint found_whitelisted_keys = 0;
    guint i;

    nm_assert(hash && g_hash_table_size(hash) > 0);
    nm_assert(whitelist && whitelist[0]);

#if NM_MORE_ASSERTS > 10
    /* Require whitelist to only contain unique keys. */
    {
        gs_unref_hashtable GHashTable *check_dups =
            g_hash_table_new_full(nm_str_hash, g_str_equal, NULL, NULL);

        for (i = 0; whitelist[i]; i++) {
            if (!g_hash_table_add(check_dups, (char *) whitelist[i]))
                nm_assert(FALSE);
        }
        nm_assert(g_hash_table_size(check_dups) > 0);
    }
#endif

    for (i = 0; whitelist[i]; i++) {
        if (g_hash_table_contains(hash, whitelist[i]))
            found_whitelisted_keys++;
    }

    if (found_whitelisted_keys == g_hash_table_size(hash)) {
        /* Good, there are only whitelisted keys in the hash. */
        return TRUE;
    }

    if (error) {
        GHashTableIter iter;
        const char    *k                 = NULL;
        const char    *first_invalid_key = NULL;

        g_hash_table_iter_init(&iter, hash);
        while (g_hash_table_iter_next(&iter, (gpointer *) &k, NULL)) {
            if (nm_strv_find_first(whitelist, -1, k) < 0) {
                first_invalid_key = k;
                break;
            }
        }
        if (setting_name) {
            g_set_error(error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
                        "Can't reapply changes to '%s.%s' setting",
                        setting_name,
                        first_invalid_key);
        } else {
            g_set_error(error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
                        "Can't reapply any changes to '%s' setting",
                        first_invalid_key);
        }
        g_return_val_if_fail(first_invalid_key, FALSE);
    }

    return FALSE;
}

static void
_pacrunner_manager_add(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_pacrunner_manager_remove_clear(&priv->pacrunner_conf_id);

    priv->pacrunner_conf_id = nm_pacrunner_manager_add(nm_pacrunner_manager_get(),
                                                       nm_device_get_ip_iface(self),
                                                       nm_device_get_l3cd(self, TRUE));
}

static void
reactivate_proxy_config(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->pacrunner_conf_id)
        _pacrunner_manager_add(self);
}

/*****************************************************************************/

static gboolean
can_reapply_change(NMDevice   *self,
                   const char *setting_name,
                   NMSetting  *s_old,
                   NMSetting  *s_new,
                   GHashTable *diffs,
                   GError    **error)
{
    if (nm_streq(setting_name, NM_SETTING_CONNECTION_SETTING_NAME)) {
        /* Whitelist allowed properties from "connection" setting which are
         * allowed to differ.
         *
         * This includes UUID, there is no principal problem with reapplying a
         * connection and changing its UUID. In fact, disallowing it makes it
         * cumbersome for the user to reapply any connection but the original
         * settings-connection. */
        return nm_device_hash_check_invalid_keys(diffs,
                                                 NM_SETTING_CONNECTION_SETTING_NAME,
                                                 error,
                                                 NM_SETTING_CONNECTION_ID,
                                                 NM_SETTING_CONNECTION_UUID,
                                                 NM_SETTING_CONNECTION_STABLE_ID,
                                                 NM_SETTING_CONNECTION_AUTOCONNECT,
                                                 NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES,
                                                 NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY,
                                                 NM_SETTING_CONNECTION_ZONE,
                                                 NM_SETTING_CONNECTION_METERED,
                                                 NM_SETTING_CONNECTION_LLDP,
                                                 NM_SETTING_CONNECTION_MDNS,
                                                 NM_SETTING_CONNECTION_LLMNR,
                                                 NM_SETTING_CONNECTION_DNS_OVER_TLS,
                                                 NM_SETTING_CONNECTION_MPTCP_FLAGS,
                                                 NM_SETTING_CONNECTION_WAIT_ACTIVATION_DELAY);
    }

    if (NM_IN_STRSET(setting_name,
                     NM_SETTING_USER_SETTING_NAME,
                     NM_SETTING_PROXY_SETTING_NAME,
                     NM_SETTING_IP4_CONFIG_SETTING_NAME,
                     NM_SETTING_IP6_CONFIG_SETTING_NAME,
                     NM_SETTING_LINK_SETTING_NAME))
        return TRUE;

    if (nm_streq(setting_name, NM_SETTING_WIRED_SETTING_NAME)) {
        if (NM_IN_SET(NM_DEVICE_GET_CLASS(self)->get_configured_mtu,
                      nm_device_get_configured_mtu_wired_parent,
                      nm_device_get_configured_mtu_for_wired)) {
            return nm_device_hash_check_invalid_keys(diffs,
                                                     NM_SETTING_WIRED_SETTING_NAME,
                                                     error,
                                                     NM_SETTING_WIRED_MTU);
        }
        goto out_fail;
    }

    if (NM_IN_STRSET(setting_name,
                     NM_SETTING_OVS_EXTERNAL_IDS_SETTING_NAME,
                     NM_SETTING_OVS_OTHER_CONFIG_SETTING_NAME)
        && NM_DEVICE_GET_CLASS(self)->can_reapply_change_ovs_external_ids) {
        /* TODO: this means, you cannot reapply changes to the external-ids for
         * OVS system interfaces. */
        return TRUE;
    }

out_fail:
    g_set_error(error,
                NM_DEVICE_ERROR,
                NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
                "Can't reapply any changes to '%s' setting",
                setting_name);
    return FALSE;
}

static void
reapply_connection(NMDevice *self, NMConnection *con_old, NMConnection *con_new)
{}

/* check_and_reapply_connection:
 * @connection: the new connection settings to be applied or %NULL to reapply
 *   the current settings connection
 * @version_id: either zero, or the current version id for the applied
 *   connection.
 * @reapply_flags: the #NMDeviceReapplyFlags.
 * @audit_args: on return, a string representing the changes
 * @error: the error if %FALSE is returned
 *
 * Change configuration of an already configured device if possible.
 * Updates the device's applied connection upon success.
 *
 * Returns: %FALSE if the new configuration can not be reapplied.
 */
static gboolean
check_and_reapply_connection(NMDevice            *self,
                             NMConnection        *connection,
                             guint64              version_id,
                             NMDeviceReapplyFlags reapply_flags,
                             char               **audit_args,
                             GError             **error)
{
    NMDeviceClass                 *klass         = NM_DEVICE_GET_CLASS(self);
    NMDevicePrivate               *priv          = NM_DEVICE_GET_PRIVATE(self);
    NMConnection                  *applied       = nm_device_get_applied_connection(self);
    gs_unref_object NMConnection  *applied_clone = NULL;
    gs_unref_hashtable GHashTable *diffs         = NULL;
    NMConnection                  *con_old;
    NMConnection                  *con_new;
    GHashTableIter                 iter;
    NMSettingsConnection          *sett_conn;

    if (priv->state < NM_DEVICE_STATE_PREPARE || priv->state > NM_DEVICE_STATE_ACTIVATED) {
        g_set_error_literal(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_NOT_ACTIVE,
                            "Device is not activated");
        return FALSE;
    }

    nm_connection_diff(connection,
                       applied,
                       NM_SETTING_COMPARE_FLAG_IGNORE_TIMESTAMP
                           | NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS,
                       &diffs);

    if (audit_args) {
        if (diffs && nm_audit_manager_audit_enabled(nm_audit_manager_get()))
            *audit_args = nm_utils_format_con_diff_for_audit(diffs);
        else
            *audit_args = NULL;
    }

    /**************************************************************************
     * check for unsupported changes and reject to reapply
     *************************************************************************/
    if (diffs) {
        char       *setting_name;
        GHashTable *setting_diff;

        g_hash_table_iter_init(&iter, diffs);
        while (
            g_hash_table_iter_next(&iter, (gpointer *) &setting_name, (gpointer *) &setting_diff)) {
            if (!klass->can_reapply_change(
                    self,
                    setting_name,
                    nm_connection_get_setting_by_name(applied, setting_name),
                    nm_connection_get_setting_by_name(connection, setting_name),
                    setting_diff,
                    error))
                return FALSE;
        }
    }

    if (version_id != 0
        && version_id
               != nm_active_connection_version_id_get(
                   (NMActiveConnection *) priv->act_request.obj)) {
        g_set_error_literal(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_VERSION_ID_MISMATCH,
                            "Reapply failed because device changed in the meantime and the "
                            "version-id mismatches");
        return FALSE;
    }

    /**************************************************************************
     * Update applied connection
     *************************************************************************/

    if (diffs)
        nm_active_connection_version_id_bump((NMActiveConnection *) priv->act_request.obj);

    _LOGD(LOGD_DEVICE,
          "reapply (version-id %llu%s)",
          (unsigned long long) nm_active_connection_version_id_get(
              ((NMActiveConnection *) priv->act_request.obj)),
          diffs ? "" : " (unmodified)");

    if (diffs) {
        NMConnection                 *connection_clean      = connection;
        gs_unref_object NMConnection *connection_clean_free = NULL;

        {
            NMSettingConnection *s_con_a, *s_con_n;

            /* we allow re-applying a connection with differing ID, UUID, STABLE_ID and AUTOCONNECT.
             * This is for convenience but these values are not actually changeable. So, check
             * if they changed, and if the did revert to the original values. */
            s_con_a = nm_connection_get_setting_connection(applied);
            s_con_n = nm_connection_get_setting_connection(connection);

            if (!nm_streq(nm_setting_connection_get_id(s_con_a),
                          nm_setting_connection_get_id(s_con_n))
                || !nm_streq(nm_setting_connection_get_uuid(s_con_a),
                             nm_setting_connection_get_uuid(s_con_n))
                || nm_setting_connection_get_autoconnect(s_con_a)
                       != nm_setting_connection_get_autoconnect(s_con_n)
                || !nm_streq0(nm_setting_connection_get_stable_id(s_con_a),
                              nm_setting_connection_get_stable_id(s_con_n))) {
                connection_clean_free = nm_simple_connection_new_clone(connection);
                connection_clean      = connection_clean_free;
                s_con_n               = nm_connection_get_setting_connection(connection_clean);
                g_object_set(s_con_n,
                             NM_SETTING_CONNECTION_ID,
                             nm_setting_connection_get_id(s_con_a),
                             NM_SETTING_CONNECTION_UUID,
                             nm_setting_connection_get_uuid(s_con_a),
                             NM_SETTING_CONNECTION_AUTOCONNECT,
                             nm_setting_connection_get_autoconnect(s_con_a),
                             NM_SETTING_CONNECTION_STABLE_ID,
                             nm_setting_connection_get_stable_id(s_con_a),
                             NULL);
            }
        }

        con_old = applied_clone = nm_simple_connection_new_clone(applied);
        con_new                 = applied;
        /* FIXME(applied-connection-immutable): we should not modify the applied
         *   connection but replace it with a new (immutable) instance. */
        nm_connection_replace_settings_from_connection(applied, connection_clean);
        nm_connection_clear_secrets(applied);
    } else
        con_old = con_new = applied;

    priv->v4_route_table_initialized = FALSE;
    priv->v6_route_table_initialized = FALSE;
    priv->l3config_merge_flags_has   = FALSE;

    /**************************************************************************
     * Reapply changes
     *
     * Note that reapply_connection() is called as very first. This is for example
     * important for NMDeviceWireGuard, which implements coerce_route_table()
     * and get_extra_rules().
     * That is because NMDeviceWireGuard caches settings, so during reapply that
     * cache must be updated *first*.
     *************************************************************************/
    klass->reapply_connection(self, con_old, con_new);

    nm_device_link_properties_set(self, TRUE);

    if (priv->state >= NM_DEVICE_STATE_CONFIG)
        lldp_setup(self, NM_TERNARY_DEFAULT);

    if (priv->state >= NM_DEVICE_STATE_IP_CONFIG) {
        /* Allow reapply of MTU */
        priv->mtu_source = NM_DEVICE_MTU_SOURCE_NONE;

        if (nm_g_hash_table_lookup(diffs, NM_SETTING_IP4_CONFIG_SETTING_NAME))
            priv->ip_data_4.do_reapply = TRUE;
        if (nm_g_hash_table_lookup(diffs, NM_SETTING_IP6_CONFIG_SETTING_NAME))
            priv->ip_data_6.do_reapply = TRUE;

        if (nm_g_hash_table_contains_any(
                nm_g_hash_table_lookup(diffs, NM_SETTING_CONNECTION_SETTING_NAME),
                NM_SETTING_CONNECTION_LLDP,
                NM_SETTING_CONNECTION_MDNS,
                NM_SETTING_CONNECTION_LLMNR,
                NM_SETTING_CONNECTION_DNS_OVER_TLS,
                NM_SETTING_CONNECTION_MPTCP_FLAGS)) {
            priv->ip_data_4.do_reapply = TRUE;
            priv->ip_data_6.do_reapply = TRUE;
        }

        nm_device_activate_schedule_stage3_ip_config(self, FALSE);

        _routing_rules_sync(self, NM_TERNARY_TRUE);

        reactivate_proxy_config(self);

        nm_device_l3cfg_commit(
            self,
            NM_FLAGS_HAS(reapply_flags, NM_DEVICE_REAPPLY_FLAGS_PRESERVE_EXTERNAL_IP)
                ? NM_L3_CFG_COMMIT_TYPE_UPDATE
                : NM_L3_CFG_COMMIT_TYPE_REAPPLY,
            FALSE);
    }

    if (priv->state >= NM_DEVICE_STATE_IP_CHECK)
        nm_device_update_firewall_zone(self);

    if (priv->state >= NM_DEVICE_STATE_ACTIVATED)
        nm_device_update_metered(self);

    sett_conn = nm_device_get_settings_connection(self);
    if (sett_conn) {
        nm_settings_connection_autoconnect_blocked_reason_set(
            sett_conn,
            NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_USER_REQUEST,
            FALSE);
    }

    /* Notify dispatcher when re-applied */
    _LOGD(LOGD_DEVICE, "Notifying re-apply complete");
    nm_dispatcher_call_device(NM_DISPATCHER_ACTION_REAPPLY, self, NULL, NULL, NULL, NULL);

    return TRUE;
}

gboolean
nm_device_reapply(NMDevice *self, NMConnection *connection, GError **error)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    return check_and_reapply_connection(self,
                                        connection,
                                        0,
                                        NM_DEVICE_REAPPLY_FLAGS_NONE,
                                        NULL,
                                        error);
}

typedef struct {
    NMConnection        *connection;
    guint64              version_id;
    NMDeviceReapplyFlags reapply_flags;
} ReapplyData;

static void
reapply_cb(NMDevice              *self,
           GDBusMethodInvocation *context,
           NMAuthSubject         *subject,
           GError                *error,
           gpointer               user_data)
{
    ReapplyData                  *reapply_data = user_data;
    guint64                       version_id;
    gs_unref_object NMConnection *connection = NULL;
    NMDeviceReapplyFlags          reapply_flags;
    GError                       *local      = NULL;
    gs_free char                 *audit_args = NULL;

    connection    = reapply_data->connection;
    version_id    = reapply_data->version_id;
    reapply_flags = reapply_data->reapply_flags;
    nm_g_slice_free(reapply_data);

    if (error) {
        nm_audit_log_device_op(NM_AUDIT_OP_DEVICE_REAPPLY,
                               self,
                               FALSE,
                               NULL,
                               subject,
                               error->message);
        g_dbus_method_invocation_return_gerror(context, error);
        return;
    }

    if (nm_device_sys_iface_state_is_external(self))
        nm_device_sys_iface_state_set(self, NM_DEVICE_SYS_IFACE_STATE_MANAGED);

    if (!check_and_reapply_connection(self,
                                      connection
                                          ?: nm_device_get_settings_connection_get_connection(self),
                                      version_id,
                                      reapply_flags,
                                      &audit_args,
                                      &local)) {
        nm_audit_log_device_op(NM_AUDIT_OP_DEVICE_REAPPLY,
                               self,
                               FALSE,
                               audit_args,
                               subject,
                               local->message);
        g_dbus_method_invocation_take_error(context, g_steal_pointer(&local));
        return;
    }

    nm_audit_log_device_op(NM_AUDIT_OP_DEVICE_REAPPLY, self, TRUE, audit_args, subject, NULL);
    g_dbus_method_invocation_return_value(context, NULL);
}

static void
impl_device_reapply(NMDBusObject                      *obj,
                    const NMDBusInterfaceInfoExtended *interface_info,
                    const NMDBusMethodInfoExtended    *method_info,
                    GDBusConnection                   *dbus_connection,
                    const char                        *sender,
                    GDBusMethodInvocation             *invocation,
                    GVariant                          *parameters)
{
    NMDevice                  *self = NM_DEVICE(obj);
    NMDevicePrivate           *priv = NM_DEVICE_GET_PRIVATE(self);
    NMSettingsConnection      *settings_connection;
    NMConnection              *connection = NULL;
    GError                    *error      = NULL;
    ReapplyData               *reapply_data;
    gs_unref_variant GVariant *settings = NULL;
    guint64                    version_id;
    guint32                    reapply_flags_u;
    NMDeviceReapplyFlags       reapply_flags;

    g_variant_get(parameters, "(@a{sa{sv}}tu)", &settings, &version_id, &reapply_flags_u);

    if (NM_FLAGS_ANY(reapply_flags_u, ~((guint32) NM_DEVICE_REAPPLY_FLAGS_PRESERVE_EXTERNAL_IP))) {
        error =
            g_error_new_literal(NM_DEVICE_ERROR, NM_DEVICE_ERROR_FAILED, "Invalid flags specified");
        nm_audit_log_device_op(NM_AUDIT_OP_DEVICE_REAPPLY,
                               self,
                               FALSE,
                               NULL,
                               invocation,
                               error->message);
        g_dbus_method_invocation_take_error(invocation, error);
        return;
    }

    reapply_flags = reapply_flags_u;
    nm_assert(reapply_flags_u == reapply_flags);

    if (priv->state < NM_DEVICE_STATE_PREPARE || priv->state > NM_DEVICE_STATE_ACTIVATED) {
        error = g_error_new_literal(NM_DEVICE_ERROR,
                                    NM_DEVICE_ERROR_NOT_ACTIVE,
                                    "Device is not activated");
        nm_audit_log_device_op(NM_AUDIT_OP_DEVICE_REAPPLY,
                               self,
                               FALSE,
                               NULL,
                               invocation,
                               error->message);
        g_dbus_method_invocation_take_error(invocation, error);
        return;
    }

    settings_connection = nm_device_get_settings_connection(self);
    g_return_if_fail(settings_connection);

    if (settings && g_variant_n_children(settings)) {
        /* New settings specified inline. */
        connection = _nm_simple_connection_new_from_dbus(settings,
                                                         NM_SETTING_PARSE_FLAGS_STRICT
                                                             | NM_SETTING_PARSE_FLAGS_NORMALIZE,
                                                         &error);
        if (!connection) {
            g_prefix_error(&error, "The settings specified are invalid: ");
            nm_audit_log_device_op(NM_AUDIT_OP_DEVICE_REAPPLY,
                                   self,
                                   FALSE,
                                   NULL,
                                   invocation,
                                   error->message);
            g_dbus_method_invocation_take_error(invocation, error);
            return;
        }
        nm_connection_clear_secrets(connection);
    }

    reapply_data  = g_slice_new(ReapplyData);
    *reapply_data = (ReapplyData){
        .connection    = connection,
        .version_id    = version_id,
        .reapply_flags = reapply_flags,
    };

    nm_device_auth_request(self,
                           invocation,
                           nm_device_get_applied_connection(self),
                           NM_AUTH_PERMISSION_NETWORK_CONTROL,
                           TRUE,
                           NULL,
                           reapply_cb,
                           reapply_data);
}

/*****************************************************************************/

static void
impl_device_get_applied_connection(NMDBusObject                      *obj,
                                   const NMDBusInterfaceInfoExtended *interface_info,
                                   const NMDBusMethodInfoExtended    *method_info,
                                   GDBusConnection                   *connection,
                                   const char                        *sender,
                                   GDBusMethodInvocation             *invocation,
                                   GVariant                          *parameters)
{
    NMDevice             *self  = NM_DEVICE(obj);
    NMDevicePrivate      *priv  = NM_DEVICE_GET_PRIVATE(self);
    gs_free_error GError *error = NULL;
    NMConnection         *applied_connection;
    guint32               flags;
    GVariant             *var_settings;

    g_variant_get(parameters, "(u)", &flags);

    /* No flags supported as of now. */
    if (flags != 0) {
        g_dbus_method_invocation_return_error_literal(invocation,
                                                      NM_DEVICE_ERROR,
                                                      NM_DEVICE_ERROR_INVALID_ARGUMENT,
                                                      "Invalid flags specified");
        return;
    }

    applied_connection = nm_device_get_applied_connection(self);
    if (!applied_connection) {
        g_dbus_method_invocation_return_error_literal(invocation,
                                                      NM_DEVICE_ERROR,
                                                      NM_DEVICE_ERROR_NOT_ACTIVE,
                                                      "Device is not activated");
        return;
    }

    if (!nm_auth_is_invocation_in_acl_set_error(applied_connection,
                                                invocation,
                                                NM_MANAGER_ERROR,
                                                NM_MANAGER_ERROR_PERMISSION_DENIED,
                                                NULL,
                                                &error)) {
        g_dbus_method_invocation_take_error(invocation, g_steal_pointer(&error));
        return;
    }

    var_settings =
        nm_connection_to_dbus(applied_connection, NM_CONNECTION_SERIALIZE_WITH_NON_SECRET);
    if (!var_settings)
        var_settings = nm_g_variant_singleton_aLsaLsvII();

    g_dbus_method_invocation_return_value(
        invocation,
        g_variant_new(
            "(@a{sa{sv}}t)",
            var_settings,
            nm_active_connection_version_id_get((NMActiveConnection *) priv->act_request.obj)));
}

/*****************************************************************************/

static void
disconnect_cb(NMDevice              *self,
              GDBusMethodInvocation *context,
              NMAuthSubject         *subject,
              GError                *error,
              gpointer               user_data)
{
    NMDevicePrivate *priv  = NM_DEVICE_GET_PRIVATE(self);
    GError          *local = NULL;

    if (error) {
        g_dbus_method_invocation_return_gerror(context, error);
        nm_audit_log_device_op(NM_AUDIT_OP_DEVICE_DISCONNECT,
                               self,
                               FALSE,
                               NULL,
                               subject,
                               error->message);
        return;
    }

    /* Authorized */
    if (priv->state <= NM_DEVICE_STATE_DISCONNECTED) {
        local = g_error_new_literal(NM_DEVICE_ERROR,
                                    NM_DEVICE_ERROR_NOT_ACTIVE,
                                    "Device is not active");
        nm_audit_log_device_op(NM_AUDIT_OP_DEVICE_DISCONNECT,
                               self,
                               FALSE,
                               NULL,
                               subject,
                               local->message);
        g_dbus_method_invocation_take_error(context, local);
    } else {
        nm_device_autoconnect_blocked_set(self, NM_DEVICE_AUTOCONNECT_BLOCKED_MANUAL_DISCONNECT);

        nm_device_state_changed(self,
                                NM_DEVICE_STATE_DEACTIVATING,
                                NM_DEVICE_STATE_REASON_USER_REQUESTED);
        g_dbus_method_invocation_return_value(context, NULL);
        nm_audit_log_device_op(NM_AUDIT_OP_DEVICE_DISCONNECT, self, TRUE, NULL, subject, NULL);
    }
}

static void
_clear_queued_act_request(NMDevicePrivate *priv, NMActiveConnectionStateReason active_reason)
{
    if (priv->queued_act_request) {
        gs_unref_object NMActRequest *ac = NULL;

        ac = g_steal_pointer(&priv->queued_act_request);
        nm_active_connection_set_state_fail((NMActiveConnection *) ac, active_reason, NULL);
    }
}

static void
impl_device_disconnect(NMDBusObject                      *obj,
                       const NMDBusInterfaceInfoExtended *interface_info,
                       const NMDBusMethodInfoExtended    *method_info,
                       GDBusConnection                   *dbus_connection,
                       const char                        *sender,
                       GDBusMethodInvocation             *invocation,
                       GVariant                          *parameters)
{
    NMDevice        *self = NM_DEVICE(obj);
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    NMConnection    *connection;

    if (!priv->act_request.obj) {
        g_dbus_method_invocation_return_error_literal(invocation,
                                                      NM_DEVICE_ERROR,
                                                      NM_DEVICE_ERROR_NOT_ACTIVE,
                                                      "This device is not active");
        return;
    }

    connection = nm_device_get_applied_connection(self);
    nm_assert(connection);

    nm_device_auth_request(self,
                           invocation,
                           connection,
                           NM_AUTH_PERMISSION_NETWORK_CONTROL,
                           TRUE,
                           NULL,
                           disconnect_cb,
                           NULL);
}

static void
delete_cb(NMDevice              *self,
          GDBusMethodInvocation *context,
          NMAuthSubject         *subject,
          GError                *error,
          gpointer               user_data)
{
    NMSettingsConnection *sett_conn;
    GError               *local = NULL;

    if (error) {
        g_dbus_method_invocation_return_gerror(context, error);
        nm_audit_log_device_op(NM_AUDIT_OP_DEVICE_DELETE,
                               self,
                               FALSE,
                               NULL,
                               subject,
                               error->message);
        return;
    }

    /* Authorized */
    nm_audit_log_device_op(NM_AUDIT_OP_DEVICE_DELETE, self, TRUE, NULL, subject, NULL);

    sett_conn = nm_device_get_settings_connection(self);
    if (sett_conn) {
        /* Block profile from autoconnecting. We block the profile, which may
         * be ugly/wrong with multi-connect profiles. However, it's not
         * obviously wrong, because profiles for software devices tend not to
         * work with multi-connect anyway, because they describe a (unique)
         * interface by name. */
        nm_settings_connection_autoconnect_blocked_reason_set(
            sett_conn,
            NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_USER_REQUEST,
            TRUE);
    }

    if (!nm_device_unrealize(self, TRUE, &local)) {
        g_dbus_method_invocation_take_error(context, local);
        return;
    }

    g_dbus_method_invocation_return_value(context, NULL);
}

static void
impl_device_delete(NMDBusObject                      *obj,
                   const NMDBusInterfaceInfoExtended *interface_info,
                   const NMDBusMethodInfoExtended    *method_info,
                   GDBusConnection                   *connection,
                   const char                        *sender,
                   GDBusMethodInvocation             *invocation,
                   GVariant                          *parameters)
{
    NMDevice *self = NM_DEVICE(obj);

    if (!nm_device_is_software(self) || !nm_device_is_real(self)) {
        g_dbus_method_invocation_return_error_literal(
            invocation,
            NM_DEVICE_ERROR,
            NM_DEVICE_ERROR_NOT_SOFTWARE,
            "This device is not a software device or is not realized");
        return;
    }

    nm_device_auth_request(self,
                           invocation,
                           NULL,
                           NM_AUTH_PERMISSION_NETWORK_CONTROL,
                           TRUE,
                           NULL,
                           delete_cb,
                           NULL);
}

static void
_device_activate(NMDevice *self, NMActRequest *req)
{
    NMConnection *connection;

    g_return_if_fail(NM_IS_DEVICE(self));
    g_return_if_fail(NM_IS_ACT_REQUEST(req));
    nm_assert(nm_device_is_real(self));

    /* Ensure the activation request is still valid; the master may have
     * already failed in which case activation of this device should not proceed.
     */
    if (nm_active_connection_get_state(NM_ACTIVE_CONNECTION(req))
        >= NM_ACTIVE_CONNECTION_STATE_DEACTIVATING)
        return;

    if (!nm_device_get_managed(self, FALSE)) {
        /* It's unclear why the device would be unmanaged at this point.
         * Just to be sure, handle it and error out. */
        _LOGE(LOGD_DEVICE,
              "Activation: failed activating connection '%s' because device is still unmanaged",
              nm_active_connection_get_settings_connection_id((NMActiveConnection *) req));
        nm_active_connection_set_state_fail((NMActiveConnection *) req,
                                            NM_ACTIVE_CONNECTION_STATE_REASON_UNKNOWN,
                                            NULL);
        return;
    }

    connection = nm_act_request_get_applied_connection(req);
    nm_assert(connection);

    _LOGI(LOGD_DEVICE,
          "Activation: starting connection '%s' (%s)",
          nm_connection_get_id(connection),
          nm_connection_get_uuid(connection));

    delete_on_deactivate_unschedule(self);

    act_request_set(self, req);

    nm_device_activate_schedule_stage1_device_prepare(self, FALSE);
}

static void
_carrier_wait_check_queued_act_request(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (!priv->queued_act_request || !priv->queued_act_request_is_waiting_for_carrier)
        return;

    priv->queued_act_request_is_waiting_for_carrier = FALSE;
    if (!priv->carrier) {
        _LOGD(LOGD_DEVICE, "Cancel queued activation request as we have no carrier after timeout");
        _clear_queued_act_request(priv, NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED);
    } else if (priv->state == NM_DEVICE_STATE_DISCONNECTED) {
        gs_unref_object NMActRequest *queued_req = NULL;

        _LOGD(LOGD_DEVICE, "Activate queued activation request as we now have carrier");
        queued_req = g_steal_pointer(&priv->queued_act_request);
        _device_activate(self, queued_req);
    }
}

static gboolean
_carrier_wait_check_act_request_must_queue(NMDevice *self, NMActRequest *req)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    NMConnection    *connection;

    /* If we have carrier or if we are not waiting for it, the activation
     * request is not blocked waiting for carrier. */
    if (priv->carrier)
        return FALSE;
    if (!priv->carrier_wait_source)
        return FALSE;

    connection = nm_act_request_get_applied_connection(req);
    if (!connection_requires_carrier(connection))
        return FALSE;

    if (!nm_device_check_connection_available(self,
                                              connection,
                                              NM_DEVICE_CHECK_CON_AVAILABLE_ALL,
                                              NULL,
                                              NULL)) {
        /* We passed all @flags we have, and no @specific_object.
         * This equals maximal availability, if a connection is not available
         * in this case, it is not waiting for carrier.
         *
         * Actually, why are we even trying to activate it? Strange, but whatever
         * the reason, don't wait for carrier.
         */
        return FALSE;
    }

    if (nm_device_check_connection_available(
            self,
            connection,
            NM_DEVICE_CHECK_CON_AVAILABLE_ALL
                & ~_NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_WAITING_CARRIER,
            NULL,
            NULL)) {
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
nm_device_disconnect_active_connection(NMActiveConnection           *active,
                                       NMDeviceStateReason           device_reason,
                                       NMActiveConnectionStateReason active_reason)
{
    NMDevice        *self;
    NMDevicePrivate *priv;

    g_return_if_fail(NM_IS_ACTIVE_CONNECTION(active));

    self = nm_active_connection_get_device(active);
    if (!self) {
        /* hm, no device? Just fail the active connection. */
        goto do_fail;
    }

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (NM_ACTIVE_CONNECTION(priv->queued_act_request) == active) {
        _clear_queued_act_request(priv, active_reason);
        return;
    }

    if (NM_ACTIVE_CONNECTION(priv->act_request.obj) == active) {
        if (priv->state < NM_DEVICE_STATE_DEACTIVATING) {
            /* When the user actively deactivates a profile, we set
             * the sys-iface-state to managed so that we deconfigure/cleanup the interface.
             * But for external connections that go down otherwise, we don't want to touch the interface. */
            if (nm_device_sys_iface_state_is_external(self))
                nm_device_sys_iface_state_set(self, NM_DEVICE_SYS_IFACE_STATE_MANAGED);

            nm_device_state_changed(self, NM_DEVICE_STATE_DEACTIVATING, device_reason);
        } else {
            /* @active is the current ac of @self, but it's going down already.
             * Nothing to do. */
        }
        return;
    }

    /* the active connection references this device, but it's neither the
     * queued_act_request nor the current act_request. Just set it to fail... */
do_fail:
    nm_active_connection_set_state_fail(active, active_reason, NULL);
}

void
nm_device_queue_activation(NMDevice *self, NMActRequest *req)
{
    NMDevicePrivate *priv;
    gboolean         must_queue;

    g_return_if_fail(NM_IS_DEVICE(self));
    g_return_if_fail(NM_IS_ACT_REQUEST(req));

    nm_keep_alive_arm(nm_active_connection_get_keep_alive(NM_ACTIVE_CONNECTION(req)));

    if (nm_active_connection_get_state(NM_ACTIVE_CONNECTION(req))
        >= NM_ACTIVE_CONNECTION_STATE_DEACTIVATING) {
        /* it's already deactivating. Nothing to do. */
        nm_assert(
            NM_IN_SET(nm_active_connection_get_device(NM_ACTIVE_CONNECTION(req)), NULL, self));
        return;
    }

    nm_assert(self == nm_active_connection_get_device(NM_ACTIVE_CONNECTION(req)));

    priv = NM_DEVICE_GET_PRIVATE(self);

    must_queue = _carrier_wait_check_act_request_must_queue(self, req);

    if (!priv->act_request.obj && !must_queue && nm_device_is_real(self)) {
        _device_activate(self, req);
        return;
    }

    /* supersede any already-queued request */
    _clear_queued_act_request(priv, NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED);
    priv->queued_act_request                        = g_object_ref(req);
    priv->queued_act_request_is_waiting_for_carrier = must_queue;

    _LOGD(LOGD_DEVICE,
          "queue activation request waiting for %s",
          must_queue ? "carrier" : "currently active connection to disconnect");

    /* Deactivate existing activation request first */
    if (priv->act_request.obj) {
        _LOGI(LOGD_DEVICE, "disconnecting for new activation request.");
        nm_device_state_changed(self,
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
nm_device_is_activating(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    NMDeviceState    state;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    state = nm_device_get_state(self);
    if (state >= NM_DEVICE_STATE_PREPARE && state <= NM_DEVICE_STATE_SECONDARIES)
        return TRUE;

    /* There's a small race between the time when stage 1 is scheduled
     * and when the device actually sets STATE_PREPARE when the activation
     * handler is actually run.  If there's an activation handler scheduled
     * we're activating anyway.
     */
    return !!priv->activation_idle_source;
}

NMDhcpConfig *
nm_device_get_dhcp_config(NMDevice *self, int addr_family)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), NULL);

    return NM_DEVICE_GET_PRIVATE(self)->ipdhcp_data_x[NM_IS_IPv4(addr_family)].config;
}

NML3Cfg *
nm_device_get_l3cfg(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), NULL);

    return NM_DEVICE_GET_PRIVATE(self)->l3cfg;
}

const NML3ConfigData *
nm_device_get_l3cd(NMDevice *self, gboolean get_commited)
{
    NMDevicePrivate *priv;

    g_return_val_if_fail(NM_IS_DEVICE(self), NULL);

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (!priv->l3cfg)
        return NULL;

    return nm_l3cfg_get_combined_l3cd(priv->l3cfg, get_commited);
}

/*****************************************************************************/

static gboolean
_dispatcher_cleanup(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->delay_activation_source);

    if (!priv->dispatcher.call_id)
        return FALSE;

    nm_dispatcher_call_cancel(g_steal_pointer(&priv->dispatcher.call_id));
    priv->dispatcher.post_state        = NM_DEVICE_STATE_UNKNOWN;
    priv->dispatcher.post_state_reason = NM_DEVICE_STATE_REASON_NONE;

    return TRUE;
}

static void
_queue_dispatcher_post_state(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_device_queue_state(self, priv->dispatcher.post_state, priv->dispatcher.post_state_reason);
    priv->dispatcher.post_state        = NM_DEVICE_STATE_UNKNOWN;
    priv->dispatcher.post_state_reason = NM_DEVICE_STATE_REASON_NONE;
}

static gboolean
_wait_activation_delay_timeout(gpointer user_data)
{
    NMDevice        *self = user_data;
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->delay_activation_source);

    _LOGD(LOGD_DEVICE, "finished waiting on activation delay");
    _queue_dispatcher_post_state(self);

    return G_SOURCE_REMOVE;
}

static void
_dispatcher_complete_proceed_state(NMDispatcherCallId *call_id, gpointer user_data)
{
    NMDevice            *self = NM_DEVICE(user_data);
    NMDevicePrivate     *priv = NM_DEVICE_GET_PRIVATE(self);
    NMConnection        *conn;
    NMSettingConnection *s_conn;
    gint32               delay_timeout;

    g_return_if_fail(call_id == priv->dispatcher.call_id);
    nm_assert(!priv->delay_activation_source);

    priv->dispatcher.call_id = NULL;
    conn                     = nm_device_get_applied_connection(self);
    if (conn) {
        s_conn = nm_connection_get_setting_connection(conn);
        if (s_conn) {
            delay_timeout = nm_setting_connection_get_wait_activation_delay(s_conn);
            if (delay_timeout > 0) {
                priv->delay_activation_source =
                    nm_g_timeout_add_source(delay_timeout, _wait_activation_delay_timeout, self);
                return;
            }
        }
    }

    _queue_dispatcher_post_state(self);
}

/*****************************************************************************/

static void
ip_check_pre_up(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (_dispatcher_cleanup(self))
        nm_assert_not_reached();

    priv->dispatcher.post_state        = NM_DEVICE_STATE_SECONDARIES;
    priv->dispatcher.post_state_reason = NM_DEVICE_STATE_REASON_NONE;
    if (!nm_dispatcher_call_device(NM_DISPATCHER_ACTION_PRE_UP,
                                   self,
                                   NULL,
                                   _dispatcher_complete_proceed_state,
                                   self,
                                   &priv->dispatcher.call_id)) {
        /* Just proceed on errors */
        _dispatcher_complete_proceed_state(0, self);
    }
}

static void
ip_check_gw_ping_cleanup(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_clear_g_source(&priv->gw_ping.watch);
    nm_clear_g_source(&priv->gw_ping.timeout);

    if (priv->gw_ping.pid) {
        nm_utils_kill_child_async(priv->gw_ping.pid,
                                  SIGTERM,
                                  priv->gw_ping.log_domain,
                                  "ping",
                                  1000,
                                  NULL,
                                  NULL);
        priv->gw_ping.pid = 0;
    }

    nm_clear_g_free(&priv->gw_ping.binary);
    nm_clear_g_free(&priv->gw_ping.address);
}

static gboolean
spawn_ping(NMDevice *self)
{
    NMDevicePrivate      *priv        = NM_DEVICE_GET_PRIVATE(self);
    gs_free char         *str_timeout = NULL;
    gs_free char         *tmp_str     = NULL;
    const char           *args[]      = {priv->gw_ping.binary,
                                         "-I",
                                         nm_device_get_ip_iface(self),
                                         "-c",
                                         "1",
                                         "-w",
                                         NULL,
                                         priv->gw_ping.address,
                                         NULL};
    gs_free_error GError *error       = NULL;
    gboolean              ret;

    args[6] = str_timeout = g_strdup_printf("%u", priv->gw_ping.deadline);
    tmp_str               = g_strjoinv(" ", (char **) args);
    _LOGD(priv->gw_ping.log_domain, "ping: running '%s'", tmp_str);

    ret = g_spawn_async("/",
                        (char **) args,
                        NULL,
                        G_SPAWN_DO_NOT_REAP_CHILD,
                        NULL,
                        NULL,
                        &priv->gw_ping.pid,
                        &error);

    if (!ret) {
        _LOGW(priv->gw_ping.log_domain,
              "ping: could not spawn %s: %s",
              priv->gw_ping.binary,
              error->message);
    }

    return ret;
}

static gboolean
respawn_ping_cb(gpointer user_data)
{
    NMDevice        *self = NM_DEVICE(user_data);
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    priv->gw_ping.watch = 0;

    if (spawn_ping(self)) {
        priv->gw_ping.watch = g_child_watch_add(priv->gw_ping.pid, ip_check_ping_watch_cb, self);
    } else {
        ip_check_gw_ping_cleanup(self);
        ip_check_pre_up(self);
    }

    return FALSE;
}

static void
ip_check_ping_watch_cb(GPid pid, int status, gpointer user_data)
{
    NMDevice        *self       = NM_DEVICE(user_data);
    NMDevicePrivate *priv       = NM_DEVICE_GET_PRIVATE(self);
    NMLogDomain      log_domain = priv->gw_ping.log_domain;
    gboolean         success    = FALSE;

    if (!priv->gw_ping.watch)
        return;
    priv->gw_ping.watch = 0;
    priv->gw_ping.pid   = 0;

    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == 0) {
            _LOGD(log_domain, "ping: gateway ping succeeded");
            success = TRUE;
        } else {
            _LOGW(log_domain, "ping: gateway ping failed with error code %d", WEXITSTATUS(status));
        }
    } else
        _LOGW(log_domain, "ping: stopped unexpectedly with status %d", status);

    if (success) {
        /* We've got connectivity, proceed to pre_up */
        ip_check_gw_ping_cleanup(self);
        ip_check_pre_up(self);
    } else {
        /* If ping exited with an error it may have returned early,
         * wait 1 second and restart it */
        priv->gw_ping.watch = g_timeout_add_seconds(1, respawn_ping_cb, self);
    }
}

static gboolean
ip_check_ping_timeout_cb(gpointer user_data)
{
    NMDevice        *self = NM_DEVICE(user_data);
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    priv->gw_ping.timeout = 0;

    _LOGW(priv->gw_ping.log_domain, "ping: gateway ping timed out");

    ip_check_gw_ping_cleanup(self);
    ip_check_pre_up(self);
    return FALSE;
}

static gboolean
start_ping(NMDevice   *self,
           NMLogDomain log_domain,
           const char *binary,
           const char *address,
           guint       timeout)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    g_return_val_if_fail(priv->gw_ping.watch == 0, FALSE);
    g_return_val_if_fail(priv->gw_ping.timeout == 0, FALSE);

    priv->gw_ping.log_domain = log_domain;
    priv->gw_ping.address    = g_strdup(address);
    priv->gw_ping.binary     = g_strdup(binary);
    priv->gw_ping.deadline   = timeout + 10; /* the proper termination is enforced by a timer */

    if (spawn_ping(self)) {
        priv->gw_ping.watch   = g_child_watch_add(priv->gw_ping.pid, ip_check_ping_watch_cb, self);
        priv->gw_ping.timeout = g_timeout_add_seconds(timeout, ip_check_ping_timeout_cb, self);
        return TRUE;
    }

    ip_check_gw_ping_cleanup(self);
    return FALSE;
}

static void
nm_device_start_ip_check(NMDevice *self)
{
    NMDevicePrivate     *priv = NM_DEVICE_GET_PRIVATE(self);
    NMConnection        *connection;
    NMSettingConnection *s_con;
    guint                timeout     = 0;
    const char          *ping_binary = NULL;
    char                 buf[NM_INET_ADDRSTRLEN];
    NMLogDomain          log_domain = LOGD_IP4;

    /* Shouldn't be any active ping here, since IP_CHECK happens after the
     * first IP method completes.  Any subsequently completing IP method doesn't
     * get checked.
     */
    g_return_if_fail(!priv->gw_ping.watch);
    g_return_if_fail(!priv->gw_ping.timeout);
    g_return_if_fail(!priv->gw_ping.pid);
    g_return_if_fail(priv->ip_data_4.state == NM_DEVICE_IP_STATE_READY
                     || priv->ip_data_6.state == NM_DEVICE_IP_STATE_READY);

    connection = nm_device_get_applied_connection(self);
    g_assert(connection);

    s_con = nm_connection_get_setting_connection(connection);
    g_assert(s_con);
    timeout = nm_setting_connection_get_gateway_ping_timeout(s_con);

    buf[0] = '\0';
    if (timeout) {
        const NMPObject      *gw;
        const NML3ConfigData *l3cd;

        l3cd = priv->l3cfg ? nm_l3cfg_get_combined_l3cd(priv->l3cfg, TRUE) : NULL;
        if (!l3cd) {
            /* pass */
        } else if (priv->ip_data_4.state == NM_DEVICE_IP_STATE_READY) {
            gw = nm_l3_config_data_get_best_default_route(l3cd, AF_INET);
            if (gw) {
                nm_inet4_ntop(NMP_OBJECT_CAST_IP4_ROUTE(gw)->gateway, buf);
                ping_binary = nm_utils_find_helper("ping", "/usr/bin/ping", NULL);
                log_domain  = LOGD_IP4;
            }
        } else if (priv->ip_data_6.state == NM_DEVICE_IP_STATE_READY) {
            gw = nm_l3_config_data_get_best_default_route(l3cd, AF_INET6);
            if (gw) {
                nm_inet6_ntop(&NMP_OBJECT_CAST_IP6_ROUTE(gw)->gateway, buf);
                ping_binary = nm_utils_find_helper("ping6", "/usr/bin/ping6", NULL);
                log_domain  = LOGD_IP6;
            }
        }
    }

    if (buf[0])
        start_ping(self, log_domain, ping_binary, buf, timeout);

    /* If no ping was started, just advance to pre_up */
    if (!priv->gw_ping.pid)
        ip_check_pre_up(self);
}

/*****************************************************************************/

static gboolean
carrier_wait_timeout(gpointer user_data)
{
    NMDevice        *self = NM_DEVICE(user_data);
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_clear_g_source_inst(&priv->carrier_wait_source);
    nm_device_remove_pending_action(self, NM_PENDING_ACTION_CARRIER_WAIT, FALSE);
    if (!priv->carrier)
        _carrier_wait_check_queued_act_request(self);
    return G_SOURCE_CONTINUE;
}

static gboolean
nm_device_is_up(NMDevice *self)
{
    int ifindex;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    ifindex = nm_device_get_ip_ifindex(self);
    return ifindex > 0 ? nm_platform_link_is_up(nm_device_get_platform(self), ifindex) : TRUE;
}

static gint64
_get_carrier_wait_ms(NMDevice *self)
{
    return nm_config_data_get_device_config_int64_by_device(
        NM_CONFIG_GET_DATA,
        NM_CONFIG_KEYFILE_KEY_DEVICE_CARRIER_WAIT_TIMEOUT,
        self,
        10,
        0,
        G_MAXINT32,
        CARRIER_WAIT_TIME_MS,
        CARRIER_WAIT_TIME_MS);
}

/*
 * Devices that support carrier detect must be IFF_UP to report carrier
 * changes; so after setting the device IFF_UP we must suppress startup
 * complete (via a pending action) until either the carrier turns on, or
 * a timeout is reached.
 */
static void
carrier_detect_wait(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    gint64           now_ms, until_ms;

    if (!nm_device_has_capability(self, NM_DEVICE_CAP_CARRIER_DETECT))
        return;

    /* we start a grace period of 5 seconds during which we will schedule
     * a pending action whenever we have no carrier.
     *
     * If during that time carrier goes away, we declare the interface
     * as not ready. */
    nm_clear_g_source_inst(&priv->carrier_wait_source);
    if (!priv->carrier)
        nm_device_add_pending_action(self, NM_PENDING_ACTION_CARRIER_WAIT, FALSE);

    now_ms   = nm_utils_get_monotonic_timestamp_msec();
    until_ms = NM_MAX(now_ms + _get_carrier_wait_ms(self), priv->carrier_wait_until_msec);
    priv->carrier_wait_source =
        nm_g_timeout_add_source(until_ms - now_ms, carrier_wait_timeout, self);
}

gboolean
nm_device_bring_up_full(NMDevice *self,
                        gboolean  block,
                        gboolean  update_carrier,
                        gboolean *no_firmware)
{
    gboolean             device_is_up = FALSE;
    NMDeviceCapabilities capabilities;
    int                  ifindex;
    int                  r;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    NM_SET_OUT(no_firmware, FALSE);

    if (!nm_device_get_enabled(self)) {
        _LOGD(LOGD_PLATFORM, "bringing up device ignored due to disabled");
        return FALSE;
    }

    ifindex = nm_device_get_ip_ifindex(self);
    _LOGD(LOGD_PLATFORM, "bringing up device %d", ifindex);
    if (ifindex <= 0) {
        /* assume success. */
    } else {
        r = nm_platform_link_change_flags(nm_device_get_platform(self), ifindex, IFF_UP, TRUE);
        NM_SET_OUT(no_firmware, (r == -NME_PL_NO_FIRMWARE));
        if (r < 0)
            return FALSE;
    }

    if (update_carrier)
        nm_device_set_carrier_from_platform(self);

    device_is_up = nm_device_is_up(self);
    if (block && !device_is_up) {
        gint64 wait_until = nm_utils_get_monotonic_timestamp_usec() + 10000 /* microseconds */;

        do {
            g_usleep(200);
            if (!nm_platform_link_refresh(nm_device_get_platform(self), ifindex))
                return FALSE;
            device_is_up = nm_device_is_up(self);
        } while (!device_is_up && nm_utils_get_monotonic_timestamp_usec() < wait_until);
    }

    if (!device_is_up) {
        if (block)
            _LOGW(LOGD_PLATFORM, "device not up after timeout!");
        else
            _LOGD(LOGD_PLATFORM, "device not up immediately");
        return FALSE;
    }

    /* some ethernet devices fail to report capabilities unless the device
     * is up. Re-read the capabilities. */
    capabilities = 0;
    if (NM_DEVICE_GET_CLASS(self)->get_generic_capabilities)
        capabilities |= NM_DEVICE_GET_CLASS(self)->get_generic_capabilities(self);
    _add_capabilities(self, capabilities);

    carrier_detect_wait(self);

    /* Can only get HW address of some devices when they are up */
    nm_device_update_hw_address(self);

    _dev_l3_cfg_commit(self, TRUE);

    return TRUE;
}

gboolean
nm_device_bring_up(NMDevice *self)
{
    return nm_device_bring_up_full(self, TRUE, TRUE, NULL);
}

void
nm_device_take_down(NMDevice *self, gboolean block)
{
    int      ifindex;
    gboolean device_is_up;

    g_return_if_fail(NM_IS_DEVICE(self));

    ifindex = nm_device_get_ip_ifindex(self);
    _LOGD(LOGD_PLATFORM, "taking down device %d", ifindex);
    if (ifindex <= 0) {
        /* devices without ifindex are always up. */
        return;
    }

    if (!nm_platform_link_change_flags(nm_device_get_platform(self), ifindex, IFF_UP, FALSE))
        return;

    device_is_up = nm_device_is_up(self);
    if (block && device_is_up) {
        gint64 wait_until = nm_utils_get_monotonic_timestamp_usec() + 10000 /* microseconds */;

        do {
            g_usleep(200);
            if (!nm_platform_link_refresh(nm_device_get_platform(self), ifindex))
                return;
            device_is_up = nm_device_is_up(self);
        } while (device_is_up && nm_utils_get_monotonic_timestamp_usec() < wait_until);
    }

    if (device_is_up) {
        if (block)
            _LOGW(LOGD_PLATFORM, "device not down after timeout!");
        else
            _LOGD(LOGD_PLATFORM, "device not down immediately");
    }
}

void
nm_device_set_firmware_missing(NMDevice *self, gboolean new_missing)
{
    NMDevicePrivate *priv;

    g_return_if_fail(NM_IS_DEVICE(self));

    priv = NM_DEVICE_GET_PRIVATE(self);
    if (priv->firmware_missing != new_missing) {
        priv->firmware_missing = new_missing;
        _notify(self, PROP_FIRMWARE_MISSING);
    }
}

gboolean
nm_device_get_firmware_missing(NMDevice *self)
{
    return NM_DEVICE_GET_PRIVATE(self)->firmware_missing;
}

/*****************************************************************************/

NM_UTILS_FLAGS2STR_DEFINE(nm_unmanaged_flags2str,
                          NMUnmanagedFlags,
                          NM_UTILS_FLAGS2STR(NM_UNMANAGED_SLEEPING, "sleeping"),
                          NM_UTILS_FLAGS2STR(NM_UNMANAGED_QUITTING, "quitting"),
                          NM_UTILS_FLAGS2STR(NM_UNMANAGED_PLATFORM_INIT, "platform-init"),
                          NM_UTILS_FLAGS2STR(NM_UNMANAGED_USER_EXPLICIT, "user-explicit"),
                          NM_UTILS_FLAGS2STR(NM_UNMANAGED_BY_DEFAULT, "by-default"),
                          NM_UTILS_FLAGS2STR(NM_UNMANAGED_USER_SETTINGS, "user-settings"),
                          NM_UTILS_FLAGS2STR(NM_UNMANAGED_USER_CONF, "user-conf"),
                          NM_UTILS_FLAGS2STR(NM_UNMANAGED_USER_UDEV, "user-udev"),
                          NM_UTILS_FLAGS2STR(NM_UNMANAGED_EXTERNAL_DOWN, "external-down"),
                          NM_UTILS_FLAGS2STR(NM_UNMANAGED_IS_SLAVE, "is-slave"), );

static const char *
_unmanaged_flags2str(NMUnmanagedFlags flags, NMUnmanagedFlags mask, char *buf, gsize len)
{
    char  buf2[512];
    char *b;
    char *tmp, *tmp2;
    gsize l;

    nm_utils_to_string_buffer_init(&buf, &len);
    if (!len)
        return buf;

    b = buf;

    mask |= flags;

    nm_unmanaged_flags2str(flags, b, len);
    l = strlen(b);
    b += l;
    len -= l;

    nm_unmanaged_flags2str(mask & ~flags, buf2, sizeof(buf2));
    if (buf2[0]) {
        gboolean add_separator = l > 0;

        tmp = buf2;
        while (TRUE) {
            if (add_separator)
                nm_strbuf_append_c(&b, &len, ',');
            add_separator = TRUE;

            tmp2 = strchr(tmp, ',');
            if (tmp2)
                tmp2[0] = '\0';

            nm_strbuf_append_c(&b, &len, '!');
            nm_strbuf_append_str(&b, &len, tmp);
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
         * then it is also managed for an explicit user-request.
         *
         * Effectively, this check is redundant, as the code below already
         * already ensures that. Still, express this invariant explicitly here. */
        if (_get_managed_by_flags(flags, mask, FALSE))
            return TRUE;

        /* A for-user-request, is effectively the same as pretending
         * that user-explicit flag is cleared. */
        mask |= NM_UNMANAGED_USER_EXPLICIT;
        flags &= ~NM_UNMANAGED_USER_EXPLICIT;
    }

    if (NM_FLAGS_ANY(mask, NM_UNMANAGED_USER_SETTINGS)
        && !NM_FLAGS_ANY(flags, NM_UNMANAGED_USER_SETTINGS)) {
        /* NM_UNMANAGED_USER_SETTINGS can only explicitly unmanage a device. It cannot
         * *manage* it. Having NM_UNMANAGED_USER_SETTINGS explicitly not set, is the
         * same as having it not set at all. */
        mask &= ~NM_UNMANAGED_USER_SETTINGS;
    }

    if (NM_FLAGS_ANY(mask, NM_UNMANAGED_USER_UDEV)) {
        /* configuration from udev or nm-config overwrites the by-default flag
         * which is based on the device type.
         * configuration from udev overwrites external-down */
        flags &= ~(NM_UNMANAGED_BY_DEFAULT | NM_UNMANAGED_EXTERNAL_DOWN);
    }

    if (NM_FLAGS_ANY(mask, NM_UNMANAGED_USER_CONF)) {
        /* configuration from NetworkManager.conf overwrites the by-default flag
         * which is based on the device type.
         * It also overwrites the udev configuration and external-down */
        flags &= ~(NM_UNMANAGED_BY_DEFAULT | NM_UNMANAGED_USER_UDEV | NM_UNMANAGED_EXTERNAL_DOWN);
    }

    if (NM_FLAGS_HAS(mask, NM_UNMANAGED_IS_SLAVE) && !NM_FLAGS_HAS(flags, NM_UNMANAGED_IS_SLAVE)) {
        /* for an enslaved device, by-default doesn't matter */
        flags &= ~NM_UNMANAGED_BY_DEFAULT;
    }

    if (NM_FLAGS_HAS(mask, NM_UNMANAGED_USER_EXPLICIT)) {
        /* if the device is managed by user-decision, certain other flags
         * are ignored. */
        flags &= ~(NM_UNMANAGED_BY_DEFAULT | NM_UNMANAGED_USER_UDEV | NM_UNMANAGED_USER_CONF
                   | NM_UNMANAGED_EXTERNAL_DOWN);
    }

    return flags == NM_UNMANAGED_NONE;
}

/**
 * nm_device_get_managed:
 * @self: the #NMDevice
 * @for_user_request: whether to check the flags for an explicit user-request
 *   Setting this to %TRUE has the same effect as if %NM_UNMANAGED_USER_EXPLICIT
 *   unmanaged flag would be unset (meaning: explicitly not-unmanaged).
 *   If this parameter is %TRUE, the device can only appear more managed.
 *
 * Whether the device is unmanaged according to the unmanaged flags.
 *
 * Returns: %TRUE if the device is unmanaged because of the flags.
 */
gboolean
nm_device_get_managed(NMDevice *self, gboolean for_user_request)
{
    NMDevicePrivate *priv;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    if (!nm_device_is_real(self)) {
        /* a unrealized device is always considered unmanaged. */
        return FALSE;
    }

    priv = NM_DEVICE_GET_PRIVATE(self);

    return _get_managed_by_flags(priv->unmanaged_flags, priv->unmanaged_mask, for_user_request);
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
nm_device_get_unmanaged_mask(NMDevice *self, NMUnmanagedFlags flag)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), NM_UNMANAGED_NONE);
    g_return_val_if_fail(flag != NM_UNMANAGED_NONE, NM_UNMANAGED_NONE);

    return NM_DEVICE_GET_PRIVATE(self)->unmanaged_mask & flag;
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
nm_device_get_unmanaged_flags(NMDevice *self, NMUnmanagedFlags flag)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), NM_UNMANAGED_NONE);
    g_return_val_if_fail(flag != NM_UNMANAGED_NONE, NM_UNMANAGED_NONE);

    return NM_DEVICE_GET_PRIVATE(self)->unmanaged_flags & flag;
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
_set_unmanaged_flags(NMDevice           *self,
                     NMUnmanagedFlags    flags,
                     NMUnmanFlagOp       set_op,
                     gboolean            allow_state_transition,
                     gboolean            now,
                     NMDeviceStateReason reason)
{
    NMDevicePrivate *priv;
    gboolean         was_managed, transition_state;
    NMUnmanagedFlags old_flags, old_mask;
    NMDeviceState    new_state;
    const char      *operation = NULL;
    char             str1[512];
    char             str2[512];
    gboolean         do_notify_has_pending_actions = FALSE;
    gboolean         had_pending_actions           = FALSE;

    g_return_if_fail(NM_IS_DEVICE(self));
    g_return_if_fail(flags);

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (!priv->real)
        allow_state_transition = FALSE;
    was_managed = allow_state_transition && nm_device_get_managed(self, FALSE);

    if (NM_FLAGS_HAS(priv->unmanaged_flags, NM_UNMANAGED_PLATFORM_INIT)
        && NM_FLAGS_HAS(flags, NM_UNMANAGED_PLATFORM_INIT)
        && NM_IN_SET(set_op, NM_UNMAN_FLAG_OP_SET_MANAGED)) {
        /* we are clearing the platform-init flags. This triggers additional actions. */
        if (!NM_FLAGS_HAS(flags, NM_UNMANAGED_USER_SETTINGS)) {
            gboolean unmanaged;

            unmanaged = nm_device_spec_match_list(
                self,
                nm_settings_get_unmanaged_specs(NM_DEVICE_GET_PRIVATE(self)->settings));
            nm_device_set_unmanaged_flags(self, NM_UNMANAGED_USER_SETTINGS, !!unmanaged);
        }

        if (priv->pending_actions.len == 0) {
            do_notify_has_pending_actions = TRUE;
            had_pending_actions           = nm_device_has_pending_action(self);
        }
    }

    old_flags = priv->unmanaged_flags;
    old_mask  = priv->unmanaged_mask;

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
        g_return_if_reached();
    }

    if (old_flags == priv->unmanaged_flags && old_mask == priv->unmanaged_mask)
        return;

    transition_state =
        allow_state_transition && was_managed != nm_device_get_managed(self, FALSE)
        && (was_managed
            || (!was_managed && nm_device_get_state(self) == NM_DEVICE_STATE_UNMANAGED));

    _LOGD(LOGD_DEVICE,
          "unmanaged: flags set to [%s%s0x%0x/0x%x/%s%s], %s [%s=0x%0x]%s%s%s)",
          _unmanaged_flags2str(priv->unmanaged_flags, priv->unmanaged_mask, str1, sizeof(str1)),
          (priv->unmanaged_flags | priv->unmanaged_mask) ? "=" : "",
          (guint) priv->unmanaged_flags,
          (guint) priv->unmanaged_mask,
          (_get_managed_by_flags(priv->unmanaged_flags, priv->unmanaged_mask, FALSE)
               ? "managed"
               : (_get_managed_by_flags(priv->unmanaged_flags, priv->unmanaged_mask, TRUE)
                      ? "manageable"
                      : "unmanaged")),
          priv->real ? "" : "/unrealized",
          operation,
          nm_unmanaged_flags2str(flags, str2, sizeof(str2)),
          flags,
          NM_PRINT_FMT_QUOTED(allow_state_transition,
                              ", reason ",
                              nm_device_state_reason_to_string_a(reason),
                              transition_state ? ", transition-state" : "",
                              ""));

    if (do_notify_has_pending_actions && had_pending_actions != nm_device_has_pending_action(self))
        _notify(self, PROP_HAS_PENDING_ACTION);

    if (transition_state) {
        new_state = was_managed ? NM_DEVICE_STATE_UNMANAGED : NM_DEVICE_STATE_UNAVAILABLE;
        if (new_state == NM_DEVICE_STATE_UNMANAGED) {
            _cancel_activation(self);
        } else {
            /* The assume check should happen before the device transitions to
            * UNAVAILABLE, because in UNAVAILABLE we already clean up the IP
            * configuration. Therefore, this function should never trigger a
            * sync state transition.
            */
            nm_device_queue_recheck_assume(self);
        }

        if (now)
            nm_device_state_changed(self, new_state, reason);
        else
            nm_device_queue_state(self, new_state, reason);
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
nm_device_set_unmanaged_flags(NMDevice *self, NMUnmanagedFlags flags, NMUnmanFlagOp set_op)
{
    _set_unmanaged_flags(self, flags, set_op, FALSE, FALSE, NM_DEVICE_STATE_REASON_NONE);
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
nm_device_set_unmanaged_by_flags(NMDevice           *self,
                                 NMUnmanagedFlags    flags,
                                 NMUnmanFlagOp       set_op,
                                 NMDeviceStateReason reason)
{
    _set_unmanaged_flags(self, flags, set_op, TRUE, TRUE, reason);
}

void
nm_device_set_unmanaged_by_flags_queue(NMDevice           *self,
                                       NMUnmanagedFlags    flags,
                                       NMUnmanFlagOp       set_op,
                                       NMDeviceStateReason reason)
{
    _set_unmanaged_flags(self, flags, set_op, TRUE, FALSE, reason);
}

/**
 * nm_device_check_unrealized_device_managed:
 *
 * Checks if a unrealized device is managed from user settings
 * or user configuration.
 */
gboolean
nm_device_check_unrealized_device_managed(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_assert(!nm_device_is_real(self));

    if (!nm_config_data_get_device_config_boolean_by_device(NM_CONFIG_GET_DATA,
                                                            NM_CONFIG_KEYFILE_KEY_DEVICE_MANAGED,
                                                            self,
                                                            TRUE,
                                                            TRUE))
        return FALSE;

    if (nm_device_spec_match_list(self, nm_settings_get_unmanaged_specs(priv->settings)))
        return FALSE;

    return TRUE;
}

void
nm_device_set_unmanaged_by_user_settings(NMDevice *self, gboolean now)
{
    gboolean unmanaged;

    g_return_if_fail(NM_IS_DEVICE(self));

    if (nm_device_get_unmanaged_flags(self, NM_UNMANAGED_PLATFORM_INIT)) {
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

    unmanaged = nm_device_spec_match_list(
        self,
        nm_settings_get_unmanaged_specs(NM_DEVICE_GET_PRIVATE(self)->settings));

    _set_unmanaged_flags(self,
                         NM_UNMANAGED_USER_SETTINGS,
                         !!unmanaged,
                         TRUE,
                         now,
                         unmanaged ? NM_DEVICE_STATE_REASON_NOW_UNMANAGED
                                   : NM_DEVICE_STATE_REASON_NOW_MANAGED);
}

void
nm_device_set_unmanaged_by_user_udev(NMDevice *self)
{
    int      ifindex;
    gboolean platform_unmanaged = FALSE;

    ifindex = self->_priv->ifindex;

    if (ifindex <= 0
        || !nm_platform_link_get_unmanaged(nm_device_get_platform(self),
                                           ifindex,
                                           &platform_unmanaged))
        return;

    nm_device_set_unmanaged_by_flags(self,
                                     NM_UNMANAGED_USER_UDEV,
                                     platform_unmanaged,
                                     NM_DEVICE_STATE_REASON_USER_REQUESTED);
}

void
nm_device_set_unmanaged_by_user_conf(NMDevice *self)
{
    gboolean      value;
    NMUnmanFlagOp set_op;

    value = nm_config_data_get_device_config_boolean_by_device(NM_CONFIG_GET_DATA,
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

    nm_device_set_unmanaged_by_flags(self,
                                     NM_UNMANAGED_USER_CONF,
                                     set_op,
                                     NM_DEVICE_STATE_REASON_USER_REQUESTED);
}

void
nm_device_set_unmanaged_by_quitting(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    gboolean         need_deactivate =
        nm_device_is_activating(self) || priv->state == NM_DEVICE_STATE_ACTIVATED;

    /* It's OK to block here because we're quitting */
    if (need_deactivate)
        _set_state_full(self,
                        NM_DEVICE_STATE_DEACTIVATING,
                        NM_DEVICE_STATE_REASON_NOW_UNMANAGED,
                        TRUE);

    nm_device_set_unmanaged_by_flags(self,
                                     NM_UNMANAGED_QUITTING,
                                     NM_UNMAN_FLAG_OP_SET_UNMANAGED,
                                     need_deactivate ? NM_DEVICE_STATE_REASON_REMOVED
                                                     : NM_DEVICE_STATE_REASON_NOW_UNMANAGED);
}

/*****************************************************************************/

void
nm_device_reapply_settings_immediately(NMDevice *self)
{
    NMConnection         *applied_connection;
    NMSettingsConnection *settings_connection;
    NMDeviceState         state;
    NMSettingConnection  *s_con_settings;
    NMSettingConnection  *s_con_applied;
    const char           *zone;
    NMMetered             metered;
    guint64               version_id;

    g_return_if_fail(NM_IS_DEVICE(self));

    state = nm_device_get_state(self);
    if (state <= NM_DEVICE_STATE_DISCONNECTED || state > NM_DEVICE_STATE_ACTIVATED)
        return;

    applied_connection  = nm_device_get_applied_connection(self);
    settings_connection = nm_device_get_settings_connection(self);

    if (!nm_settings_connection_has_unmodified_applied_connection(
            settings_connection,
            applied_connection,
            NM_SETTING_COMPARE_FLAG_IGNORE_REAPPLY_IMMEDIATELY))
        return;

    s_con_settings = nm_connection_get_setting_connection(
        nm_settings_connection_get_connection(settings_connection));
    s_con_applied = nm_connection_get_setting_connection(applied_connection);

    if (!nm_streq0((zone = nm_setting_connection_get_zone(s_con_settings)),
                   nm_setting_connection_get_zone(s_con_applied))) {
        version_id = nm_active_connection_version_id_bump(
            (NMActiveConnection *) self->_priv->act_request.obj);
        _LOGD(LOGD_DEVICE,
              "reapply setting: zone = %s%s%s (version-id %llu)",
              NM_PRINT_FMT_QUOTE_STRING(zone),
              (unsigned long long) version_id);

        g_object_set(G_OBJECT(s_con_applied), NM_SETTING_CONNECTION_ZONE, zone, NULL);

        nm_device_update_firewall_zone(self);
    }

    if ((metered = nm_setting_connection_get_metered(s_con_settings))
        != nm_setting_connection_get_metered(s_con_applied)) {
        version_id = nm_active_connection_version_id_bump(
            (NMActiveConnection *) self->_priv->act_request.obj);
        _LOGD(LOGD_DEVICE,
              "reapply setting: metered = %d (version-id %llu)",
              (int) metered,
              (unsigned long long) version_id);

        g_object_set(G_OBJECT(s_con_applied), NM_SETTING_CONNECTION_METERED, metered, NULL);

        nm_device_update_metered(self);
    }
}

void
nm_device_update_firewall_zone(NMDevice *self)
{
    NMDevicePrivate *priv;

    g_return_if_fail(NM_IS_DEVICE(self));

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->fw_state >= FIREWALL_STATE_INITIALIZED
        && !nm_device_sys_iface_state_is_external(self))
        fw_change_zone(self);
}

void
nm_device_update_metered(NMDevice *self)
{
#define NM_METERED_INVALID ((NMMetered) -1)
    NMDevicePrivate     *priv = NM_DEVICE_GET_PRIVATE(self);
    NMSettingConnection *setting;
    NMMetered            conn_value, value = NM_METERED_INVALID;
    NMConnection        *connection = NULL;
    NMDeviceState        state;

    g_return_if_fail(NM_IS_DEVICE(self));

    state = nm_device_get_state(self);
    if (state <= NM_DEVICE_STATE_DISCONNECTED || state > NM_DEVICE_STATE_ACTIVATED)
        value = NM_METERED_UNKNOWN;

    if (value == NM_METERED_INVALID) {
        connection = nm_device_get_applied_connection(self);
        if (connection) {
            setting = nm_connection_get_setting_connection(connection);
            if (setting) {
                conn_value = nm_setting_connection_get_metered(setting);
                if (conn_value != NM_METERED_UNKNOWN)
                    value = conn_value;
            }
        }
    }

    if (value == NM_METERED_INVALID && NM_DEVICE_GET_CLASS(self)->get_guessed_metered
        && NM_DEVICE_GET_CLASS(self)->get_guessed_metered(self))
        value = NM_METERED_GUESS_YES;

    /* Try to guess a value using the metered flag in IP configuration */
    if (value == NM_METERED_INVALID) {
        if (priv->l3cfg) {
            const NML3ConfigData *l3cd;

            l3cd = nm_l3cfg_get_combined_l3cd(priv->l3cfg, TRUE);
            if (l3cd && nm_l3_config_data_get_metered(l3cd) == NM_TERNARY_TRUE)
                value = NM_METERED_GUESS_YES;
        }
    }

    /* Otherwise, look at connection type. For Bluetooth, we look at the type of
     * Bluetooth sharing: for PANU/DUN (where we are receiving internet from
     * another device) we set GUESS_YES; for NAP (where we are sharing internet
     * to another device) we set GUESS_NO. We ignore WiMAX here as it’s no
     * longer supported by NetworkManager. */
    if (value == NM_METERED_INVALID
        && nm_connection_is_type(connection, NM_SETTING_BLUETOOTH_SETTING_NAME)) {
        if (_nm_connection_get_setting_bluetooth_for_nap(connection)) {
            /* NAP types are not metered, but other types are. */
            value = NM_METERED_GUESS_NO;
        } else
            value = NM_METERED_GUESS_YES;
    }

    if (value == NM_METERED_INVALID) {
        if (nm_connection_is_type(connection, NM_SETTING_GSM_SETTING_NAME)
            || nm_connection_is_type(connection, NM_SETTING_CDMA_SETTING_NAME))
            value = NM_METERED_GUESS_YES;
        else
            value = NM_METERED_GUESS_NO;
    }

    if (value != priv->metered) {
        _LOGD(LOGD_DEVICE, "set metered value %d", value);
        priv->metered = value;
        _notify(self, PROP_METERED);
    }
}

static NMDeviceCheckDevAvailableFlags
_device_check_dev_available_flags_from_con(NMDeviceCheckConAvailableFlags con_flags)
{
    NMDeviceCheckDevAvailableFlags dev_flags;

    dev_flags = NM_DEVICE_CHECK_DEV_AVAILABLE_NONE;

    if (NM_FLAGS_HAS(con_flags, _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_WAITING_CARRIER))
        dev_flags |= _NM_DEVICE_CHECK_DEV_AVAILABLE_IGNORE_CARRIER;

    return dev_flags;
}

static gboolean
_nm_device_check_connection_available(NMDevice                      *self,
                                      NMConnection                  *connection,
                                      NMDeviceCheckConAvailableFlags flags,
                                      const char                    *specific_object,
                                      GError                       **error)
{
    NMDeviceState state;
    GError       *local = NULL;

    /* an unrealized software device is always available, hardware devices never. */
    if (!nm_device_is_real(self)) {
        if (nm_device_is_software(self)) {
            if (!nm_device_check_connection_compatible(self,
                                                       connection,
                                                       TRUE,
                                                       error ? &local : NULL)) {
                if (error) {
                    g_return_val_if_fail(local, FALSE);
                    nm_utils_error_set(error,
                                       local->domain == NM_UTILS_ERROR ? local->code
                                                                       : NM_UTILS_ERROR_UNKNOWN,
                                       "profile is not compatible with software device (%s)",
                                       local->message);
                    g_error_free(local);
                }
                return FALSE;
            }
            return TRUE;
        }
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_UNMANAGED_DEVICE,
                                   "hardware device is not realized");
        return FALSE;
    }

    state = nm_device_get_state(self);
    if (state < NM_DEVICE_STATE_UNMANAGED) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_CONNECTION_AVAILABLE_UNMANAGED_DEVICE,
                                   "device is in unknown state");
        return FALSE;
    }
    if (state < NM_DEVICE_STATE_UNAVAILABLE) {
        if (nm_device_get_managed(self, FALSE)) {
            /* device is managed, both for user-requests and non-user-requests alike. */
        } else {
            if (!nm_device_get_managed(self, TRUE)) {
                /* device is strictly unmanaged by authoritative unmanaged reasons. */
                nm_utils_error_set_literal(
                    error,
                    NM_UTILS_ERROR_CONNECTION_AVAILABLE_STRICTLY_UNMANAGED_DEVICE,
                    "device is strictly unmanaged");
                return FALSE;
            }
            if (!NM_FLAGS_HAS(flags,
                              _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_OVERRULE_UNMANAGED)) {
                /* device could be managed for an explict user-request, but this is not such a request. */
                nm_utils_error_set_literal(error,
                                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_UNMANAGED_DEVICE,
                                           "device is currently unmanaged");
                return FALSE;
            }
        }
    }
    if (state < NM_DEVICE_STATE_DISCONNECTED && !nm_device_is_software(self)) {
        if (!nm_device_is_available(self, _device_check_dev_available_flags_from_con(flags))) {
            if (NM_FLAGS_HAS(flags, _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST)) {
                nm_utils_error_set_literal(error,
                                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                           "device is not available");
            } else {
                nm_utils_error_set_literal(error,
                                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                           "device is not available for internal request");
            }
            return FALSE;
        }
    }

    if (!nm_device_check_connection_compatible(self, connection, TRUE, error ? &local : NULL)) {
        if (error) {
            nm_utils_error_set(error,
                               local->domain == NM_UTILS_ERROR ? local->code
                                                               : NM_UTILS_ERROR_UNKNOWN,
                               "profile is not compatible with device (%s)",
                               local->message);
            g_error_free(local);
        }
        return FALSE;
    }

    return NM_DEVICE_GET_CLASS(self)->check_connection_available(self,
                                                                 connection,
                                                                 flags,
                                                                 specific_object,
                                                                 error);
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
 * @error: optionally give reason why not available.
 *
 * Check if @connection is available to be activated on @self.
 *
 * Returns: %TRUE if @connection can be activated on @self
 */
gboolean
nm_device_check_connection_available(NMDevice                      *self,
                                     NMConnection                  *connection,
                                     NMDeviceCheckConAvailableFlags flags,
                                     const char                    *specific_object,
                                     GError                       **error)
{
    gboolean available;

    available =
        _nm_device_check_connection_available(self, connection, flags, specific_object, error);

#if NM_MORE_ASSERTS >= 2
    {
        /* The meaning of the flags is so that *adding* a flag relaxes a condition, thus making
         * the device *more* available. Assert against that requirement by testing all the flags. */
        NMDeviceCheckConAvailableFlags i, j, k;
        gboolean available_all[NM_DEVICE_CHECK_CON_AVAILABLE_ALL + 1] = {FALSE};

        for (i = 0; i <= NM_DEVICE_CHECK_CON_AVAILABLE_ALL; i++)
            available_all[i] =
                _nm_device_check_connection_available(self, connection, i, specific_object, NULL);

        for (i = 0; i <= NM_DEVICE_CHECK_CON_AVAILABLE_ALL; i++) {
            for (j = 1; j <= NM_DEVICE_CHECK_CON_AVAILABLE_ALL; j <<= 1) {
                if (NM_FLAGS_ANY(i, j)) {
                    k = i & ~j;
                    nm_assert(available_all[i] == available_all[k] || available_all[i]);
                }
            }
        }
    }
#endif

    return available;
}

static gboolean
available_connections_del_all(NMDevice *self)
{
    if (g_hash_table_size(self->_priv->available_connections) == 0)
        return FALSE;
    g_hash_table_remove_all(self->_priv->available_connections);
    return TRUE;
}

static gboolean
available_connections_add(NMDevice *self, NMSettingsConnection *sett_conn)
{
    return g_hash_table_add(self->_priv->available_connections, g_object_ref(sett_conn));
}

static gboolean
available_connections_del(NMDevice *self, NMSettingsConnection *sett_conn)
{
    return g_hash_table_remove(self->_priv->available_connections, sett_conn);
}

static gboolean
check_connection_available(NMDevice                      *self,
                           NMConnection                  *connection,
                           NMDeviceCheckConAvailableFlags flags,
                           const char                    *specific_object,
                           GError                       **error)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->carrier)
        return TRUE;

    if (NM_FLAGS_HAS(flags, _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST_WAITING_CARRIER)
        && priv->carrier_wait_source) {
        /* The device has no carrier though the connection requires it.
         *
         * If we are still waiting for carrier, the connection is available
         * for an explicit user-request. */
        return TRUE;
    }

    if (!priv->up) {
        /* If the device is !IFF_UP it also has no carrier. But we assume that if we
         * would start activating the device (and thereby set the device IFF_UP),
         * that we would get a carrier. We only know after we set the device up,
         * and we only set it up after we start activating it. So presumably, this
         * profile would be available (but we just don't know). */
        return TRUE;
    }

    if (!connection_requires_carrier(connection)) {
        /* Connections that don't require carrier are available. */
        return TRUE;
    }

    if (nm_device_is_master(self)) {
        /* master types are always available even without carrier.
         * Making connection non-available would un-enslave slaves which
         * is not desired. */
        return TRUE;
    }

    nm_utils_error_set_literal(error,
                               NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                               "device has no carrier");
    return FALSE;
}

void
nm_device_recheck_available_connections(NMDevice *self)
{
    NMDevicePrivate               *priv;
    NMSettingsConnection *const   *connections;
    gboolean                       changed = FALSE;
    GHashTableIter                 h_iter;
    NMSettingsConnection          *sett_conn;
    guint                          i;
    gs_unref_hashtable GHashTable *prune_list = NULL;

    g_return_if_fail(NM_IS_DEVICE(self));

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (g_hash_table_size(priv->available_connections) > 0) {
        prune_list = g_hash_table_new(nm_direct_hash, NULL);
        g_hash_table_iter_init(&h_iter, priv->available_connections);
        while (g_hash_table_iter_next(&h_iter, (gpointer *) &sett_conn, NULL))
            g_hash_table_add(prune_list, sett_conn);
    }

    connections = nm_settings_get_connections(priv->settings, NULL);
    for (i = 0; connections[i]; i++) {
        sett_conn = connections[i];

        if (nm_device_check_connection_available(self,
                                                 nm_settings_connection_get_connection(sett_conn),
                                                 _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST,
                                                 NULL,
                                                 NULL)) {
            if (available_connections_add(self, sett_conn))
                changed = TRUE;
            if (prune_list)
                g_hash_table_remove(prune_list, sett_conn);
        }
    }

    if (prune_list) {
        g_hash_table_iter_init(&h_iter, prune_list);
        while (g_hash_table_iter_next(&h_iter, (gpointer *) &sett_conn, NULL)) {
            if (available_connections_del(self, sett_conn))
                changed = TRUE;
        }
    }

    if (changed)
        _notify(self, PROP_AVAILABLE_CONNECTIONS);
    available_connections_check_delete_unrealized(self);
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
nm_device_get_best_connection(NMDevice *self, const char *specific_object, GError **error)
{
    NMDevicePrivate      *priv      = NM_DEVICE_GET_PRIVATE(self);
    NMSettingsConnection *sett_conn = NULL;
    NMSettingsConnection *candidate;
    guint64               best_timestamp = 0;
    GHashTableIter        iter;

    g_hash_table_iter_init(&iter, priv->available_connections);
    while (g_hash_table_iter_next(&iter, (gpointer) &candidate, NULL)) {
        guint64 candidate_timestamp = 0;

        /* If a specific object is given, only include connections that are
         * compatible with it.
         */
        if (specific_object /* << Optimization: we know that the connection is available without @specific_object.  */
            && !nm_device_check_connection_available(
                self,
                nm_settings_connection_get_connection(candidate),
                _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST,
                specific_object,
                NULL))
            continue;

        nm_settings_connection_get_timestamp(candidate, &candidate_timestamp);
        if (!sett_conn || (candidate_timestamp > best_timestamp)) {
            sett_conn      = candidate;
            best_timestamp = candidate_timestamp;
        }
    }

    if (!sett_conn) {
        g_set_error(error,
                    NM_MANAGER_ERROR,
                    NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
                    "The device '%s' has no connections available for activation.",
                    nm_device_get_iface(self));
    }

    return sett_conn;
}

static void
cp_connection_added_or_updated(NMDevice *self, NMSettingsConnection *sett_conn)
{
    gboolean changed;

    g_return_if_fail(NM_IS_DEVICE(self));
    g_return_if_fail(NM_IS_SETTINGS_CONNECTION(sett_conn));

    if (nm_device_check_connection_available(self,
                                             nm_settings_connection_get_connection(sett_conn),
                                             _NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST,
                                             NULL,
                                             NULL))
        changed = available_connections_add(self, sett_conn);
    else
        changed = available_connections_del(self, sett_conn);

    if (changed) {
        _notify(self, PROP_AVAILABLE_CONNECTIONS);
        available_connections_check_delete_unrealized(self);
    }
}

static void
cp_connection_added(NMSettings *settings, NMSettingsConnection *sett_conn, gpointer user_data)
{
    cp_connection_added_or_updated(user_data, sett_conn);
}

static void
cp_connection_updated(NMSettings           *settings,
                      NMSettingsConnection *sett_conn,
                      guint                 update_reason_u,
                      gpointer              user_data)
{
    cp_connection_added_or_updated(user_data, sett_conn);
}

static void
cp_connection_removed(NMSettings *settings, NMSettingsConnection *sett_conn, gpointer user_data)
{
    NMDevice *self = user_data;

    g_return_if_fail(NM_IS_DEVICE(self));

    if (available_connections_del(self, sett_conn)) {
        _notify(self, PROP_AVAILABLE_CONNECTIONS);
        available_connections_check_delete_unrealized(self);
    }
}

gboolean
nm_device_supports_vlans(NMDevice *self)
{
    return nm_platform_link_supports_vlans(nm_device_get_platform(self),
                                           nm_device_get_ifindex(self));
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
nm_device_add_pending_action(NMDevice *self, const char *action, gboolean assert_not_yet_pending)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    gssize           idx;

    g_return_val_if_fail(action, FALSE);

    idx = nm_strv_find_binary_search(priv->pending_actions.arr, priv->pending_actions.len, action);
    if (idx >= 0) {
        if (assert_not_yet_pending) {
            _LOGW(LOGD_DEVICE,
                  "add_pending_action (%u): '%s' already pending",
                  priv->pending_actions.len,
                  action);
            g_return_val_if_reached(FALSE);
        } else {
            _LOGT(LOGD_DEVICE,
                  "add_pending_action (%u): '%s' already pending (expected)",
                  priv->pending_actions.len,
                  action);
        }
        return FALSE;
    }

    if (priv->pending_actions.len == priv->pending_actions.alloc) {
        nm_assert(priv->pending_actions.alloc < G_MAXUINT / 2u);
        priv->pending_actions.alloc = NM_MAX(priv->pending_actions.alloc * 2u, 4u);
        priv->pending_actions.arr =
            g_renew(const char *, priv->pending_actions.arr, priv->pending_actions.alloc);
    }
    nm_arr_insert_at(priv->pending_actions.arr, priv->pending_actions.len, ~idx, action);
    priv->pending_actions.len++;

    _LOGD(LOGD_DEVICE, "add_pending_action (%u): '%s'", priv->pending_actions.len, action);

    if (priv->pending_actions.len == 1)
        _notify(self, PROP_HAS_PENDING_ACTION);

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
nm_device_remove_pending_action(NMDevice *self, const char *action, gboolean assert_is_pending)
{
    NMDevicePrivate *priv;
    gssize           idx;

    g_return_val_if_fail(self, FALSE);
    g_return_val_if_fail(action, FALSE);

    priv = NM_DEVICE_GET_PRIVATE(self);

    idx = nm_strv_find_binary_search(priv->pending_actions.arr, priv->pending_actions.len, action);
    if (idx >= 0) {
        _LOGD(LOGD_DEVICE,
              "remove_pending_action (%u): '%s'",
              priv->pending_actions.len - 1u,
              action);
        nm_arr_remove_at(priv->pending_actions.arr, priv->pending_actions.len, idx);
        priv->pending_actions.len--;
        if (priv->pending_actions.len == 0)
            _notify(self, PROP_HAS_PENDING_ACTION);
        return TRUE;
    }

    if (assert_is_pending) {
        _LOGW(LOGD_DEVICE,
              "remove_pending_action (%u): '%s' not pending",
              priv->pending_actions.len,
              action);
        g_return_val_if_reached(FALSE);
    } else {
        _LOGT(LOGD_DEVICE,
              "remove_pending_action (%u): '%s' not pending (expected)",
              priv->pending_actions.len,
              action);
    }

    return FALSE;
}

const char *
nm_device_has_pending_action_reason(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->pending_actions.len > 0) {
        if (priv->pending_actions.len == 1 && nm_device_get_state(self) == NM_DEVICE_STATE_ACTIVATED
            && nm_streq(priv->pending_actions.arr[0], NM_PENDING_ACTION_CARRIER_WAIT)) {
            /* if the device is already in activated state, and the only reason
             * why it appears still busy is "carrier-wait", then we are already complete. */
            return NULL;
        }

        return priv->pending_actions.arr[0];
    }

    if (nm_device_is_real(self)
        && nm_device_get_unmanaged_flags(self, NM_UNMANAGED_PLATFORM_INIT)) {
        /* as long as the platform link is not yet initialized, we have a pending
         * action. */
        return NM_PENDING_ACTION_LINK_INIT;
    }

    return NULL;
}

/*****************************************************************************/

static void
_cancel_activation(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->fw_call) {
        nm_firewalld_manager_cancel_call(priv->fw_call);
        nm_assert(!priv->fw_call);
        priv->fw_call  = NULL;
        priv->fw_state = FIREWALL_STATE_INITIALIZED;
    }

    _dispatcher_cleanup(self);
    ip_check_gw_ping_cleanup(self);

    _dev_ip_state_cleanup(self, AF_INET, FALSE);
    _dev_ip_state_cleanup(self, AF_INET6, FALSE);

    /* Break the activation chain */
    activation_source_clear(self);
}

static void
_cleanup_generic_pre(NMDevice *self, CleanupType cleanup_type)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    guint            i;

    _cancel_activation(self);

    priv->stage1_sriov_state = NM_DEVICE_STAGE_STATE_INIT;

    if (cleanup_type != CLEANUP_TYPE_KEEP) {
        nm_manager_device_route_metric_clear(NM_MANAGER_GET, nm_device_get_ip_ifindex(self));
    }

    if (cleanup_type == CLEANUP_TYPE_DECONFIGURE && priv->fw_state >= FIREWALL_STATE_INITIALIZED
        && priv->fw_mgr && !nm_device_sys_iface_state_is_external(self)) {
        nm_firewalld_manager_remove_from_zone(priv->fw_mgr,
                                              nm_device_get_ip_iface(self),
                                              NULL,
                                              NULL,
                                              NULL);
    }
    priv->fw_state = FIREWALL_STATE_UNMANAGED;
    g_clear_object(&priv->fw_mgr);

    queued_state_clear(self);

    for (i = 0; i < 2; i++)
        nm_clear_pointer(&priv->hostname_resolver_x[i], _hostname_resolver_free);

    _cleanup_ip_pre(self, AF_INET, cleanup_type, FALSE);
    _cleanup_ip_pre(self, AF_INET6, cleanup_type, FALSE);

    _dev_ip_state_req_timeout_cancel(self, AF_UNSPEC);
}

static void
_cleanup_generic_post(NMDevice *self, NMDeviceStateReason reason, CleanupType cleanup_type)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    priv->v4_route_table_initialized = FALSE;
    priv->v6_route_table_initialized = FALSE;
    priv->l3config_merge_flags_has   = FALSE;

    priv->v4_route_table_all_sync_before = FALSE;
    priv->v6_route_table_all_sync_before = FALSE;

    priv->mtu_force_set_done = FALSE;

    priv->needs_ip6_subnet = FALSE;

    if (priv->act_request.obj) {
        nm_active_connection_set_default(NM_ACTIVE_CONNECTION(priv->act_request.obj),
                                         AF_INET,
                                         FALSE);
        nm_clear_g_signal_handler(priv->act_request.obj, &priv->master_ready_id);
        act_request_set(self, NULL);
    }

    if (cleanup_type == CLEANUP_TYPE_DECONFIGURE
        && ((reason == NM_DEVICE_STATE_REASON_CARRIER && nm_device_is_master(self))
            || !NM_IN_SET(reason,
                          NM_DEVICE_STATE_REASON_NOW_MANAGED,
                          NM_DEVICE_STATE_REASON_CARRIER))) {
        /* Check if the device was deactivated, and if so, delete_link.
         * Don't call delete_link synchronously because we are currently
         * handling a state change -- which is not reentrant. */
        delete_on_deactivate_check_and_schedule(self);
    }

    /* ip_iface should be cleared after flushing all routes and addresses, since
     * those are identified by ip_iface, not by iface (which might be a tty
     * or ATM device).
     */
    _set_ip_ifindex(self, 0, NULL);

    nm_clear_g_source_inst(&priv->ip_data_4.check_async_source);
    nm_clear_g_source_inst(&priv->ip_data_6.check_async_source);
}

/*
 * nm_device_cleanup
 *
 * Remove a device's routing table entries and IP addresses.
 *
 */
static void
nm_device_cleanup(NMDevice *self, NMDeviceStateReason reason, CleanupType cleanup_type)
{
    NMDevicePrivate *priv;
    int              ifindex;

    g_return_if_fail(NM_IS_DEVICE(self));

    if (reason == NM_DEVICE_STATE_REASON_NOW_MANAGED)
        _LOGD(LOGD_DEVICE, "preparing device");
    else
        _LOGD(LOGD_DEVICE,
              "deactivating device (reason '%s') [%d]",
              nm_device_state_reason_to_string_a(reason),
              reason);

    /* Save whether or not we tried IPv6 for later */
    priv = NM_DEVICE_GET_PRIVATE(self);

    _cleanup_generic_pre(self, cleanup_type);

    /* Turn off kernel IPv6 */
    if (cleanup_type == CLEANUP_TYPE_DECONFIGURE) {
        _dev_sysctl_set_disable_ipv6(self, TRUE);
        nm_device_sysctl_ip_conf_set(self, AF_INET6, "use_tempaddr", "0");
    }

    /* Call device type-specific deactivation */
    if (NM_DEVICE_GET_CLASS(self)->deactivate)
        NM_DEVICE_GET_CLASS(self)->deactivate(self);

    ifindex = nm_device_get_ip_ifindex(self);

    if (cleanup_type == CLEANUP_TYPE_DECONFIGURE) {
        /* master: release slaves */
        nm_device_master_release_slaves_all(self);

        /* Take out any entries in the routing table and any IP address the device had. */
        if (ifindex > 0) {
            NMPlatform *platform = nm_device_get_platform(self);

            nm_device_l3cfg_commit(self, NM_L3_CFG_COMMIT_TYPE_REAPPLY, TRUE);

            if (nm_device_get_applied_setting(self, NM_TYPE_SETTING_TC_CONFIG)) {
                nm_platform_tc_sync(platform, ifindex, NULL, NULL);
            }
        }
    }

    priv->tc_committed = FALSE;

    _routing_rules_sync(self,
                        cleanup_type == CLEANUP_TYPE_KEEP ? NM_TERNARY_DEFAULT : NM_TERNARY_FALSE);

    if (ifindex > 0)
        nm_platform_ip4_dev_route_blacklist_set(nm_device_get_platform(self), ifindex, NULL);

    /* slave: mark no longer enslaved */
    if (priv->master && priv->ifindex > 0
        && nm_platform_link_get_master(nm_device_get_platform(self), priv->ifindex) <= 0) {
        nm_device_master_release_slave(priv->master,
                                       self,
                                       RELEASE_SLAVE_TYPE_NO_CONFIG,
                                       NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
    }

    lldp_setup(self, NM_TERNARY_FALSE);

    nm_device_update_metered(self);

    if (ifindex > 0) {
        /* during device cleanup, we want to reset the MAC address of the device
         * to the initial state.
         *
         * We certainly want to do that when reaching the UNMANAGED state... */
        if (nm_device_get_state(self) <= NM_DEVICE_STATE_UNMANAGED)
            nm_device_hw_addr_reset(self, "unmanage");
        else {
            /* for other device states (UNAVAILABLE, DISCONNECTED), allow the
             * device to overwrite the reset behavior, so that Wi-Fi can set
             * a randomized MAC address used during scanning. */
            NM_DEVICE_GET_CLASS(self)->deactivate_reset_hw_addr(self);
        }
    }

    priv->mtu_source = NM_DEVICE_MTU_SOURCE_NONE;
    priv->ip6_mtu    = 0;
    if (priv->mtu_initial || priv->ip6_mtu_initial) {
        ifindex = nm_device_get_ip_ifindex(self);

        if (ifindex > 0 && cleanup_type == CLEANUP_TYPE_DECONFIGURE) {
            _LOGT(LOGD_DEVICE,
                  "mtu: reset device-mtu: %u, ipv6-mtu: %u, ifindex: %d",
                  (guint) priv->mtu_initial,
                  (guint) priv->ip6_mtu_initial,
                  ifindex);
            if (priv->mtu_initial) {
                nm_platform_link_set_mtu(nm_device_get_platform(self), ifindex, priv->mtu_initial);
                priv->carrier_wait_until_msec =
                    nm_utils_get_monotonic_timestamp_msec() + CARRIER_WAIT_TIME_AFTER_MTU_MSEC;
            }
            if (priv->ip6_mtu_initial) {
                char sbuf[64];

                nm_device_sysctl_ip_conf_set(
                    self,
                    AF_INET6,
                    "mtu",
                    nm_sprintf_buf(sbuf, "%u", (unsigned) priv->ip6_mtu_initial));
            }
        }
        priv->mtu_initial     = 0;
        priv->ip6_mtu_initial = 0;
    }

    _ethtool_state_reset(self);
    link_properties_reset(self);

    if (priv->promisc_reset != NM_OPTION_BOOL_DEFAULT && ifindex > 0) {
        nm_platform_link_change_flags(nm_device_get_platform(self),
                                      ifindex,
                                      IFF_PROMISC,
                                      !!priv->promisc_reset);
        priv->promisc_reset = NM_OPTION_BOOL_DEFAULT;
    }

    _cleanup_generic_post(self, reason, cleanup_type);
}

static void
deactivate_reset_hw_addr(NMDevice *self)
{
    nm_device_hw_addr_reset(self, "deactivate");
}

/*****************************************************************************/

static void
ip6_managed_setup(NMDevice *self)
{
    _dev_addrgenmode6_set(self, NM_IN6_ADDR_GEN_MODE_NONE);
    _dev_sysctl_set_disable_ipv6(self, FALSE);
    nm_device_sysctl_ip_conf_set(self, AF_INET6, "accept_ra", "0");
    nm_device_sysctl_ip_conf_set(self, AF_INET6, "use_tempaddr", "0");
}

static void
deactivate_ready(NMDevice *self, NMDeviceStateReason reason)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->port_detach_count > 0)
        return;

    if (priv->dispatcher.call_id)
        return;

    if (priv->sriov_reset_pending > 0)
        return;

    if (priv->state == NM_DEVICE_STATE_DEACTIVATING)
        nm_device_queue_state(self, NM_DEVICE_STATE_DISCONNECTED, reason);
}

static void
sriov_reset_on_deactivate_cb(GError *error, gpointer user_data)
{
    NMDevice        *self;
    NMDevicePrivate *priv;
    gpointer         reason;

    nm_utils_user_data_unpack(user_data, &self, &reason);
    priv = NM_DEVICE_GET_PRIVATE(self);
    nm_assert(priv->sriov_reset_pending > 0);
    priv->sriov_reset_pending--;

    if (nm_utils_error_is_cancelled(error))
        return;

    deactivate_ready(self, GPOINTER_TO_INT(reason));
}

static void
sriov_reset_on_failure_cb(GError *error, gpointer user_data)
{
    NMDevice        *self = user_data;
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    nm_assert(priv->sriov_reset_pending > 0);
    priv->sriov_reset_pending--;

    if (nm_utils_error_is_cancelled(error))
        return;

    if (priv->state == NM_DEVICE_STATE_FAILED) {
        nm_device_queue_state(self, NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_NONE);
    }
}

static void
deactivate_async_ready(NMDevice *self, GError *error, gpointer user_data)
{
    NMDevicePrivate    *priv   = NM_DEVICE_GET_PRIVATE(self);
    NMDeviceStateReason reason = GPOINTER_TO_UINT(user_data);

    if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
        _LOGD(LOGD_DEVICE, "Deactivation cancelled");
        return;
    }

    g_clear_object(&priv->deactivating_cancellable);

    /* In every other case, transition to the DISCONNECTED state */
    if (error) {
        _LOGW(LOGD_DEVICE, "Deactivation failed: %s", error->message);
    }

    deactivate_ready(self, reason);
}

static void
deactivate_dispatcher_complete(NMDispatcherCallId *call_id, gpointer user_data)
{
    NMDevice           *self = NM_DEVICE(user_data);
    NMDevicePrivate    *priv = NM_DEVICE_GET_PRIVATE(self);
    NMDeviceStateReason reason;

    g_return_if_fail(call_id == priv->dispatcher.call_id);
    g_return_if_fail(priv->dispatcher.post_state == NM_DEVICE_STATE_DISCONNECTED);

    reason = priv->state_reason;

    priv->dispatcher.call_id           = NULL;
    priv->dispatcher.post_state        = NM_DEVICE_STATE_UNKNOWN;
    priv->dispatcher.post_state_reason = NM_DEVICE_STATE_REASON_NONE;

    if (nm_clear_g_cancellable(&priv->deactivating_cancellable))
        nm_assert_not_reached();

    if (NM_DEVICE_GET_CLASS(self)->deactivate_async) {
        /* FIXME: the virtual function deactivate_async() has only this caller here.
         * And the NMDevice subtypes are well aware of the circumstances when they
         * are called. We shall make the function less generic and thus (as the scope
         * is narrower) more convenient.
         *
         * - Drop the callback argument. Instead, when deactivate_async() completes, the
         *   subtype shall call a method _nm_device_deactivate_async_done(). Because as
         *   it is currently, subtypes need to pretend this callback and the user-data
         *   would be opaque, and carry it around. When it's in fact very clear what this
         *   is.
         *
         * - Also drop the GCancellable argument. Upon cancellation, NMDevice shall
         *   call another virtual function deactivate_async_abort(). As it is currently,
         *   callers need to register to the cancelled signal of the cancellable. It
         *   seems simpler to just implement the deactivate_async_abort() function.
         *   On the other hand, some implementations actually use the GCancellable.
         *   So, NMDevice shall do both: it shall both pass a cancellable, but also
         *   invoke deactivate_async_abort(). It allow the implementation to honor
         *   whatever is simpler for their purpose.
         *
         * - sometimes, the subclass can complete right away. Scheduling the completion
         *   in an idle handler is cumbersome. Allow the function to return FALSE to
         *   indicate that the device is already deactivated and the callback (or
         *   _nm_device_deactivate_async_done()) won't be invoked.
         */
        priv->deactivating_cancellable = g_cancellable_new();
        NM_DEVICE_GET_CLASS(self)->deactivate_async(self,
                                                    priv->deactivating_cancellable,
                                                    deactivate_async_ready,
                                                    GUINT_TO_POINTER(reason));
    } else
        deactivate_ready(self, reason);
}

static void
_set_state_full(NMDevice *self, NMDeviceState state, NMDeviceStateReason reason, gboolean quitting)
{
    gs_unref_object NMActRequest *req = NULL;
    NMDevicePrivate              *priv;
    NMDeviceState                 old_state;
    gboolean                      no_firmware = FALSE;
    NMSettingsConnection         *sett_conn;
    NMSettingSriov               *s_sriov;
    gboolean                      concheck_now;

    g_return_if_fail(NM_IS_DEVICE(self));

    priv = NM_DEVICE_GET_PRIVATE(self);

    g_return_if_fail(priv->in_state_changed == 0);

    old_state = priv->state;

    if (state == NM_DEVICE_STATE_FAILED && nm_device_sys_iface_state_is_external_or_assume(self)) {
        /* Avoid tearing down assumed connection, assume it's connected */
        state  = NM_DEVICE_STATE_ACTIVATED;
        reason = NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED;
    }

    /* Do nothing if state isn't changing, but as a special case allow
     * re-setting UNAVAILABLE if the device is missing firmware so that we
     * can retry device initialization.
     */
    if ((priv->state == state)
        && (state != NM_DEVICE_STATE_UNAVAILABLE || !priv->firmware_missing)) {
        _LOGD(LOGD_DEVICE,
              "state change: %s -> %s (reason '%s', sys-iface-state: '%s'%s)",
              nm_device_state_to_string(old_state),
              nm_device_state_to_string(state),
              nm_device_state_reason_to_string_a(reason),
              nm_device_sys_iface_state_to_string(priv->sys_iface_state),
              priv->firmware_missing ? ", missing firmware" : "");
        return;
    }

    _LOGI(LOGD_DEVICE,
          "state change: %s -> %s (reason '%s', sys-iface-state: '%s')",
          nm_device_state_to_string(old_state),
          nm_device_state_to_string(state),
          nm_device_state_reason_to_string_a(reason),
          nm_device_sys_iface_state_to_string(priv->sys_iface_state));

    /* in order to prevent triggering any callback caused
     * by the device not having any pending action anymore
     * we add one here that gets removed at the end of the function */
    nm_device_add_pending_action(self, NM_PENDING_ACTION_IN_STATE_CHANGE, TRUE);
    priv->in_state_changed++;

    priv->state        = state;
    priv->state_reason = reason;

    queued_state_clear(self);

    _dispatcher_cleanup(self);

    nm_clear_g_cancellable(&priv->deactivating_cancellable);

    /* Cache the activation request for the dispatcher */
    req = nm_g_object_ref(priv->act_request.obj);

    if (state > NM_DEVICE_STATE_UNMANAGED && state <= NM_DEVICE_STATE_ACTIVATED
        && nm_device_state_reason_check(reason) == NM_DEVICE_STATE_REASON_NOW_MANAGED
        && NM_IN_SET_TYPED(NMDeviceSysIfaceState,
                           priv->sys_iface_state,
                           NM_DEVICE_SYS_IFACE_STATE_EXTERNAL,
                           NM_DEVICE_SYS_IFACE_STATE_ASSUME))
        nm_device_sys_iface_state_set(self, NM_DEVICE_SYS_IFACE_STATE_MANAGED);

    if (state <= NM_DEVICE_STATE_DISCONNECTED || state >= NM_DEVICE_STATE_ACTIVATED)
        priv->auth_retries = NM_DEVICE_AUTH_RETRIES_UNSET;

    if (state > NM_DEVICE_STATE_DISCONNECTED)
        nm_device_assume_state_reset(self);

    if (state < NM_DEVICE_STATE_UNAVAILABLE
        || (state >= NM_DEVICE_STATE_IP_CONFIG && state < NM_DEVICE_STATE_ACTIVATED)) {
        /* preserve-external-ports is used by NMCheckpoint to activate a master
         * device, and preserve already attached ports. This means, this state is only
         * relevant during the deactivation and the following activation of the
         * right profile. Once we are sufficiently far in the activation of the
         * intended profile, we clear the state again. */
        nm_device_activation_state_set_preserve_external_ports(self, FALSE);
    }

    if (state <= NM_DEVICE_STATE_UNAVAILABLE) {
        if (available_connections_del_all(self))
            _notify(self, PROP_AVAILABLE_CONNECTIONS);
        if (old_state > NM_DEVICE_STATE_UNAVAILABLE) {
            _clear_queued_act_request(priv, NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED);
        }
    }

    /* Update the available connections list when a device first becomes available */
    if (state >= NM_DEVICE_STATE_DISCONNECTED && old_state < NM_DEVICE_STATE_DISCONNECTED)
        nm_device_recheck_available_connections(self);

    if (state <= NM_DEVICE_STATE_DISCONNECTED || state > NM_DEVICE_STATE_DEACTIVATING) {
        if (nm_clear_g_free(&priv->current_stable_id))
            _LOGT(LOGD_DEVICE, "stable-id: clear");
    }

    /* Handle the new state here; but anything that could trigger
     * another state change should be done below.
     */
    switch (state) {
    case NM_DEVICE_STATE_UNMANAGED:
        nm_device_set_firmware_missing(self, FALSE);
        if (old_state > NM_DEVICE_STATE_UNMANAGED) {
            if (priv->sys_iface_state != NM_DEVICE_SYS_IFACE_STATE_MANAGED) {
                nm_device_cleanup(self,
                                  reason,
                                  priv->sys_iface_state == NM_DEVICE_SYS_IFACE_STATE_REMOVED
                                      ? CLEANUP_TYPE_REMOVED
                                      : CLEANUP_TYPE_KEEP);
            } else {
                /* Clean up if the device is now unmanaged but was activated */
                if (nm_device_get_act_request(self))
                    nm_device_cleanup(self, reason, CLEANUP_TYPE_DECONFIGURE);
                nm_device_take_down(self, TRUE);
                nm_device_hw_addr_reset(self, "unmanage");
                _dev_addrgenmode6_set(self, NM_IN6_ADDR_GEN_MODE_EUI64);
                _dev_sysctl_restore_ip6_properties(self);
            }
        }
        nm_device_sys_iface_state_set(self, NM_DEVICE_SYS_IFACE_STATE_EXTERNAL);
        break;
    case NM_DEVICE_STATE_UNAVAILABLE:
        if (old_state == NM_DEVICE_STATE_UNMANAGED) {
            _dev_sysctl_save_ip6_properties(self);
            if (priv->sys_iface_state == NM_DEVICE_SYS_IFACE_STATE_MANAGED)
                ip6_managed_setup(self);
            device_init_static_sriov_num_vfs(self);

            /* We didn't bring the device up and we have little idea
             * when was it brought up. Play it safe and assume it could
             * have been brought up very recently and it might one of
             * those who take time to detect carrier.
             */
            carrier_detect_wait(self);
        }

        if (priv->sys_iface_state == NM_DEVICE_SYS_IFACE_STATE_MANAGED) {
            if (old_state == NM_DEVICE_STATE_UNMANAGED || priv->firmware_missing) {
                if (!nm_device_bring_up_full(self, TRUE, FALSE, &no_firmware) && no_firmware)
                    _LOGW(LOGD_PLATFORM, "firmware may be missing.");
                nm_device_set_firmware_missing(self, no_firmware ? TRUE : FALSE);
            }

            /* Ensure the device gets deactivated in response to stuff like
             * carrier changes or rfkill.  But don't deactivate devices that are
             * about to assume a connection since that defeats the purpose of
             * assuming the device's existing connection.
             *
             * Note that we "deactivate" the device even when coming from
             * UNMANAGED, to ensure that it's in a clean state.
             */
            nm_device_cleanup(self, reason, CLEANUP_TYPE_DECONFIGURE);
        }
        break;
    case NM_DEVICE_STATE_DISCONNECTED:
        if (old_state > NM_DEVICE_STATE_DISCONNECTED) {
            /* Ensure devices that previously assumed a connection now have
             * userspace IPv6LL enabled.
             */
            _dev_addrgenmode6_set(self, NM_IN6_ADDR_GEN_MODE_NONE);
            if (priv->sys_iface_state == NM_DEVICE_SYS_IFACE_STATE_REMOVED) {
                nm_device_cleanup(self, reason, CLEANUP_TYPE_REMOVED);
            } else
                nm_device_cleanup(self, reason, CLEANUP_TYPE_DECONFIGURE);

        } else if (old_state < NM_DEVICE_STATE_DISCONNECTED) {
            if (priv->sys_iface_state == NM_DEVICE_SYS_IFACE_STATE_MANAGED) {
                /* Ensure IPv6 is set up as it may not have been done when
                 * entering the UNAVAILABLE state depending on the reason.
                 */
                ip6_managed_setup(self);
            }
        }
        break;
    case NM_DEVICE_STATE_PREPARE:
        nm_device_update_initial_hw_address(self);
        break;
    case NM_DEVICE_STATE_NEED_AUTH:
        if (old_state > NM_DEVICE_STATE_NEED_AUTH) {
            /* Clean up any half-done IP operations if the device's layer2
             * finds out it needs authentication during IP config.
             */
            _cleanup_ip_pre(self, AF_INET, CLEANUP_TYPE_DECONFIGURE, FALSE);
            _cleanup_ip_pre(self, AF_INET6, CLEANUP_TYPE_DECONFIGURE, FALSE);
        }
        break;
    default:
        break;
    }

    /* Reset intern autoconnect flags when the device is activating or connected. */
    if (state >= NM_DEVICE_STATE_PREPARE && state <= NM_DEVICE_STATE_ACTIVATED)
        nm_device_autoconnect_blocked_unset(self, NM_DEVICE_AUTOCONNECT_BLOCKED_INTERNAL);

    _notify(self, PROP_STATE);
    _notify(self, PROP_STATE_REASON);
    nm_dbus_object_emit_signal(NM_DBUS_OBJECT(self),
                               &interface_info_device,
                               &signal_info_state_changed,
                               "(uuu)",
                               (guint32) state,
                               (guint32) old_state,
                               (guint32) reason);
    g_signal_emit(self,
                  signals[STATE_CHANGED],
                  0,
                  (guint) state,
                  (guint) old_state,
                  (guint) reason);

    /* Post-process the event after internal notification */

    switch (state) {
    case NM_DEVICE_STATE_UNAVAILABLE:
        /* If the device can activate now (ie, it's got a carrier, the supplicant
         * is active, or whatever) schedule a delayed transition to DISCONNECTED
         * to get things rolling.  The device can't transition immediately because
         * we can't change states again from the state handler for a variety of
         * reasons.
         */
        if (nm_device_is_available(self, NM_DEVICE_CHECK_DEV_AVAILABLE_NONE)) {
            nm_device_queue_recheck_available(self,
                                              NM_DEVICE_STATE_REASON_NONE,
                                              NM_DEVICE_STATE_REASON_NONE);
        } else {
            _LOGD(LOGD_DEVICE, "device not yet available for transition to DISCONNECTED");
        }
        break;
    case NM_DEVICE_STATE_DEACTIVATING:
        _cancel_activation(self);

        /* We cache the ignore_carrier state to not react on config-reloads while the connection
         * is active. But on deactivating, reset the ignore-carrier flag to the current state. */
        priv->ignore_carrier =
            nm_config_data_get_ignore_carrier_by_device(NM_CONFIG_GET_DATA, self);

        if (quitting) {
            nm_dispatcher_call_device_sync(NM_DISPATCHER_ACTION_PRE_DOWN, self, req);
        } else {
            priv->dispatcher.post_state        = NM_DEVICE_STATE_DISCONNECTED;
            priv->dispatcher.post_state_reason = reason;
            if (!nm_dispatcher_call_device(NM_DISPATCHER_ACTION_PRE_DOWN,
                                           self,
                                           req,
                                           deactivate_dispatcher_complete,
                                           self,
                                           &priv->dispatcher.call_id)) {
                /* Just proceed on errors */
                deactivate_dispatcher_complete(0, self);
            }

            if (priv->ifindex > 0
                && (s_sriov = nm_device_get_applied_setting(self, NM_TYPE_SETTING_SRIOV))) {
                priv->sriov_reset_pending++;
                sriov_op_queue(self,
                               0,
                               NM_OPTION_BOOL_TRUE,
                               sriov_reset_on_deactivate_cb,
                               nm_utils_user_data_pack(self, GINT_TO_POINTER(reason)));
            }
        }

        nm_pacrunner_manager_remove_clear(&priv->pacrunner_conf_id);
        break;
    case NM_DEVICE_STATE_DISCONNECTED:
        if (priv->queued_act_request && !priv->queued_act_request_is_waiting_for_carrier) {
            gs_unref_object NMActRequest *queued_req = NULL;

            queued_req = g_steal_pointer(&priv->queued_act_request);
            _device_activate(self, queued_req);
        }
        break;
    case NM_DEVICE_STATE_ACTIVATED:
        _LOGI(LOGD_DEVICE, "Activation: successful, device activated.");
        nm_device_update_metered(self);
        nm_dispatcher_call_device(NM_DISPATCHER_ACTION_UP, self, req, NULL, NULL, NULL);
        _pacrunner_manager_add(self);
        break;
    case NM_DEVICE_STATE_FAILED:
        /* Usually upon failure the activation chain is interrupted in
         * one of the stages; but in some cases the device fails for
         * external events (as a failure of master connection) while
         * the activation sequence is running and so we need to ensure
         * that the chain is terminated here.
         */
        _cancel_activation(self);

        sett_conn = nm_device_get_settings_connection(self);
        _LOGW(LOGD_DEVICE | LOGD_WIFI,
              "Activation: failed for connection '%s'",
              sett_conn ? nm_settings_connection_get_id(sett_conn) : "<unknown>");

        /* Notify any slaves of the unexpected failure */
        nm_device_master_release_slaves_all(self);

        /* If the connection doesn't yet have a timestamp, set it to zero so that
         * we can distinguish between connections we've tried to activate and have
         * failed (zero timestamp), connections that succeeded (non-zero timestamp),
         * and those we haven't tried yet (no timestamp).
         */
        if (sett_conn && !nm_settings_connection_get_timestamp(sett_conn, NULL))
            nm_settings_connection_update_timestamp(sett_conn, (guint64) 0);

        if (priv->ifindex > 0
            && (s_sriov = nm_device_get_applied_setting(self, NM_TYPE_SETTING_SRIOV))) {
            priv->sriov_reset_pending++;
            sriov_op_queue(self, 0, NM_OPTION_BOOL_TRUE, sriov_reset_on_failure_cb, self);
            break;
        }
        /* Schedule the transition to DISCONNECTED.  The device can't transition
         * immediately because we can't change states again from the state
         * handler for a variety of reasons.
         */
        nm_device_queue_state(self, NM_DEVICE_STATE_DISCONNECTED, NM_DEVICE_STATE_REASON_NONE);
        break;
    case NM_DEVICE_STATE_IP_CHECK:
    {
        gboolean change_zone = FALSE;

        if (!nm_device_sys_iface_state_is_external(self)) {
            if (priv->ip_iface) {
                /* The device now has a @ip_iface different from the
                 * @iface on which we previously set the zone. */
                change_zone = TRUE;
            } else if (priv->fw_state == FIREWALL_STATE_UNMANAGED && priv->ifindex > 0) {
                /* We didn't set the zone earlier because there was
                 * no ifindex. */
                change_zone = TRUE;
            }
        }

        if (change_zone) {
            priv->fw_state = FIREWALL_STATE_WAIT_IP_CONFIG;
            fw_change_zone(self);
        } else
            nm_device_start_ip_check(self);

        break;
    }
    case NM_DEVICE_STATE_SECONDARIES:
        ip_check_gw_ping_cleanup(self);
        _LOGD(LOGD_DEVICE, "device entered SECONDARIES state");
        break;
    default:
        break;
    }

    if (state > NM_DEVICE_STATE_DISCONNECTED)
        delete_on_deactivate_unschedule(self);

    if ((old_state == NM_DEVICE_STATE_ACTIVATED || old_state == NM_DEVICE_STATE_DEACTIVATING)
        && (state != NM_DEVICE_STATE_DEACTIVATING)) {
        if (quitting) {
            nm_dispatcher_call_device_sync(NM_DISPATCHER_ACTION_DOWN, self, req);
        } else {
            nm_dispatcher_call_device(NM_DISPATCHER_ACTION_DOWN, self, req, NULL, NULL, NULL);
        }
    }

    concheck_now = NM_IN_SET(state, NM_DEVICE_STATE_ACTIVATED, NM_DEVICE_STATE_DISCONNECTED)
                   || old_state >= NM_DEVICE_STATE_ACTIVATED;
    concheck_update_interval(self, AF_INET, concheck_now);
    concheck_update_interval(self, AF_INET6, concheck_now);

    update_prop_ip_iface(self);

    priv->in_state_changed--;

    nm_device_remove_pending_action(self, NM_PENDING_ACTION_IN_STATE_CHANGE, TRUE);

    if ((old_state > NM_DEVICE_STATE_UNMANAGED) != (state > NM_DEVICE_STATE_UNMANAGED))
        _notify(self, PROP_MANAGED);
}

void
nm_device_state_changed(NMDevice *self, NMDeviceState state, NMDeviceStateReason reason)
{
    _set_state_full(self, state, reason, FALSE);
}

static gboolean
queued_state_set(gpointer user_data)
{
    NMDevice           *self = NM_DEVICE(user_data);
    NMDevicePrivate    *priv = NM_DEVICE_GET_PRIVATE(self);
    NMDeviceState       new_state;
    NMDeviceStateReason new_reason;

    nm_assert(priv->queued_state.id);

    _LOGD(LOGD_DEVICE,
          "queue-state[%s, reason:%s, id:%u]: %s",
          nm_device_state_to_string(priv->queued_state.state),
          nm_device_state_reason_to_string_a(priv->queued_state.reason),
          priv->queued_state.id,
          "change state");

    /* Clear queued state struct before triggering state change, since
     * the state change may queue another state.
     */
    priv->queued_state.id = 0;
    new_state             = priv->queued_state.state;
    new_reason            = priv->queued_state.reason;

    nm_device_state_changed(self, new_state, new_reason);
    nm_device_remove_pending_action(self, nm_device_state_queued_state_to_string(new_state), TRUE);

    return G_SOURCE_REMOVE;
}

void
nm_device_queue_state(NMDevice *self, NMDeviceState state, NMDeviceStateReason reason)
{
    NMDevicePrivate *priv;

    g_return_if_fail(NM_IS_DEVICE(self));

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->queued_state.id && priv->queued_state.state == state) {
        _LOGD(LOGD_DEVICE,
              "queue-state[%s, reason:%s, id:%u]: %s%s%s%s",
              nm_device_state_to_string(priv->queued_state.state),
              nm_device_state_reason_to_string_a(priv->queued_state.reason),
              priv->queued_state.id,
              "ignore queuing same state change",
              NM_PRINT_FMT_QUOTED(priv->queued_state.reason != reason,
                                  " (reason differs: ",
                                  nm_device_state_reason_to_string_a(reason),
                                  ")",
                                  ""));
        return;
    }

    /* Add pending action for the new state before clearing the queued states, so
     * that we don't accidentally pop all pending states and reach 'startup complete'  */
    nm_device_add_pending_action(self, nm_device_state_queued_state_to_string(state), TRUE);

    /* We should only ever have one delayed state transition at a time */
    if (priv->queued_state.id) {
        _LOGD(LOGD_DEVICE,
              "queue-state[%s, reason:%s, id:%u]: %s",
              nm_device_state_to_string(priv->queued_state.state),
              nm_device_state_reason_to_string_a(priv->queued_state.reason),
              priv->queued_state.id,
              "replace previously queued state change");
        nm_clear_g_source(&priv->queued_state.id);
        nm_device_remove_pending_action(
            self,
            nm_device_state_queued_state_to_string(priv->queued_state.state),
            TRUE);
    }

    priv->queued_state.state  = state;
    priv->queued_state.reason = reason;
    priv->queued_state.id     = g_idle_add(queued_state_set, self);

    _LOGD(LOGD_DEVICE,
          "queue-state[%s, reason:%s, id:%u]: %s",
          nm_device_state_to_string(state),
          nm_device_state_reason_to_string_a(reason),
          priv->queued_state.id,
          "queue state change");
}

static void
queued_state_clear(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (!priv->queued_state.id)
        return;

    _LOGD(LOGD_DEVICE,
          "queue-state[%s, reason:%s, id:%u]: %s",
          nm_device_state_to_string(priv->queued_state.state),
          nm_device_state_reason_to_string_a(priv->queued_state.reason),
          priv->queued_state.id,
          "clear queued state change");
    nm_clear_g_source(&priv->queued_state.id);
    nm_device_remove_pending_action(
        self,
        nm_device_state_queued_state_to_string(priv->queued_state.state),
        TRUE);
}

NMDeviceState
nm_device_get_state(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), NM_DEVICE_STATE_UNKNOWN);

    return NM_DEVICE_GET_PRIVATE(self)->state;
}

/*****************************************************************************/

/**
 * nm_device_activation_state_set_preserve_external_ports:
 * @self: the NMDevice.
 * @flag: whether to set or clear the the flag.
 *
 * This sets an internal flag to true, which does something specific.
 * For non-master devices, it has no effect. For master devices, this
 * will prevent to detach all external ports, until the next activation
 * completes.
 *
 * This is used during checkpoint/rollback. We may want to preserve
 * externally attached ports during the restore. NMCheckpoint will
 * call this before doing a re-activation. By setting the flag,
 * we basically preserve such ports.
 *
 * Once we reach again ACTIVATED state, the flag gets cleared. This
 * only has effect for the next activation cycle. */
void
nm_device_activation_state_set_preserve_external_ports(NMDevice *self, gboolean flag)
{
    NMDevicePrivate *priv;

    g_return_if_fail(NM_IS_DEVICE(self));

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (!NM_IS_DEVICE_BRIDGE(self)) {
        /* This is actually only implemented for bridge devices. While it might
         * make sense for bond/team or OVS, it's not clear that it is actually
         * useful or desirable. */
        return;
    }

    if (priv->activation_state_preserve_external_ports == flag)
        return;

    priv->activation_state_preserve_external_ports = flag;
    _LOGD(LOGD_DEVICE,
          "activation-state: preserve-external-ports %s",
          flag ? "enabled" : "disabled");
}

/*****************************************************************************/
/* NMConfigDevice interface related stuff */

const char *
nm_device_get_hw_address(NMDevice *self)
{
    NMDevicePrivate *priv;
    char             buf[_NM_UTILS_HWADDR_LEN_MAX];
    gsize            l;

    g_return_val_if_fail(NM_IS_DEVICE(self), NULL);

    priv = NM_DEVICE_GET_PRIVATE(self);

    nm_assert((!priv->hw_addr && priv->hw_addr_len == 0)
              || (priv->hw_addr && _nm_utils_hwaddr_aton(priv->hw_addr, buf, sizeof(buf), &l)
                  && l == priv->hw_addr_len));

    return priv->hw_addr;
}

gboolean
nm_device_update_hw_address(NMDevice *self)
{
    NMDevicePrivate *priv;
    const guint8    *hwaddr;
    gsize            hwaddrlen = 0;

    priv = NM_DEVICE_GET_PRIVATE(self);
    if (priv->ifindex <= 0)
        return FALSE;

    hwaddr = nm_platform_link_get_address(nm_device_get_platform(self), priv->ifindex, &hwaddrlen);

    if (priv->type == NM_DEVICE_TYPE_ETHERNET && hwaddr
        && nm_utils_hwaddr_matches(hwaddr,
                                   hwaddrlen,
                                   &nm_ether_addr_zero,
                                   sizeof(nm_ether_addr_zero)))
        hwaddrlen = 0;

    if (!hwaddrlen)
        return FALSE;

    if (priv->hw_addr_len && priv->hw_addr_len != hwaddrlen) {
        char s_buf[NM_UTILS_HWADDR_LEN_MAX_STR];

        /* we cannot change the address length of a device once it is set (except
         * unrealizing the device).
         *
         * The reason is that the permanent and initial MAC addresses also must have the
         * same address length, so it's unclear what it would mean that the length changes. */
        _LOGD(LOGD_PLATFORM | LOGD_DEVICE,
              "hw-addr: read a MAC address with differing length (%s vs. %s)",
              priv->hw_addr,
              _nm_utils_hwaddr_ntoa(hwaddr, hwaddrlen, TRUE, s_buf, sizeof(s_buf)));
        return FALSE;
    }

    if (priv->hw_addr && nm_utils_hwaddr_matches(priv->hw_addr, -1, hwaddr, hwaddrlen))
        return FALSE;

    g_free(priv->hw_addr);
    priv->hw_addr_len_ = hwaddrlen;
    priv->hw_addr      = nm_utils_hwaddr_ntoa(hwaddr, hwaddrlen);

    _LOGD(LOGD_PLATFORM | LOGD_DEVICE, "hw-addr: hardware address now %s", priv->hw_addr);
    _notify(self, PROP_HW_ADDRESS);

    if (!priv->hw_addr_initial
        || (priv->hw_addr_type == HW_ADDR_TYPE_UNSET && priv->state < NM_DEVICE_STATE_PREPARE
            && !nm_device_is_activating(self))) {
        /* when we get a hw_addr the first time or while the device
         * is not activated (with no explicit hw address set), always
         * update our initial hw-address as well. */
        nm_device_update_initial_hw_address(self);
    }
    return TRUE;
}

void
nm_device_update_initial_hw_address(NMDevice *self)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->hw_addr && !nm_streq0(priv->hw_addr_initial, priv->hw_addr)) {
        if (priv->hw_addr_initial && priv->hw_addr_type != HW_ADDR_TYPE_UNSET) {
            /* once we have the initial hw address set, we only allow
             * update if the currently type is "unset". */
            return;
        }
        g_free(priv->hw_addr_initial);
        priv->hw_addr_initial = g_strdup(priv->hw_addr);
        _LOGD(LOGD_DEVICE, "hw-addr: update initial MAC address %s", priv->hw_addr_initial);
    }
}

void
nm_device_update_permanent_hw_address(NMDevice *self, gboolean force_freeze)
{
    NMDevicePrivate               *priv = NM_DEVICE_GET_PRIVATE(self);
    guint8                         buf[_NM_UTILS_HWADDR_LEN_MAX];
    gboolean                       success_read;
    int                            ifindex;
    const NMPlatformLink          *pllink;
    const NMConfigDeviceStateData *dev_state;
    NMPLinkAddress                 cached_hw_addr_perm;

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
    pllink = nm_platform_link_get(nm_device_get_platform(self), ifindex);
    if (!pllink || !pllink->initialized) {
        if (!force_freeze) {
            /* we can afford to wait. Back off and leave the permanent MAC address
             * undecided for now. */
            return;
        }
        /* try to refresh the link just to give UDEV a bit more time... */
        nm_platform_link_refresh(nm_device_get_platform(self), ifindex);
        /* maybe the MAC address changed... */
        nm_device_update_hw_address(self);
    } else if (!priv->hw_addr_len)
        nm_device_update_hw_address(self);

    if (!priv->hw_addr_len) {
        /* we need the current MAC address because we require the permanent MAC address
         * to have the same length as the current address.
         *
         * Abort if there is no current MAC address. */
        return;
    }

    success_read = nm_platform_link_get_permanent_address(nm_device_get_platform(self),
                                                          pllink,
                                                          &cached_hw_addr_perm);
    if (success_read && priv->hw_addr_len == cached_hw_addr_perm.len) {
        priv->hw_addr_perm_fake = FALSE;
        priv->hw_addr_perm =
            nm_utils_hwaddr_ntoa(cached_hw_addr_perm.data, cached_hw_addr_perm.len);
        _LOGD(LOGD_DEVICE, "hw-addr: read permanent MAC address '%s'", priv->hw_addr_perm);
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
    dev_state = nm_config_device_state_get(nm_config_get(), ifindex);
    if (dev_state && dev_state->perm_hw_addr_fake
        && nm_utils_hwaddr_aton(dev_state->perm_hw_addr_fake, buf, priv->hw_addr_len)
        && !nm_utils_hwaddr_matches(buf, priv->hw_addr_len, priv->hw_addr, -1)) {
        _LOGD(LOGD_PLATFORM | LOGD_ETHER,
              "hw-addr: %s (use from statefile: %s, current: %s)",
              success_read ? "read HW addr length of permanent MAC address differs"
                           : "unable to read permanent MAC address",
              dev_state->perm_hw_addr_fake,
              priv->hw_addr);
        priv->hw_addr_perm = nm_utils_hwaddr_ntoa(buf, priv->hw_addr_len);
        goto notify_and_out;
    }

    _LOGD(LOGD_PLATFORM | LOGD_ETHER,
          "hw-addr: %s (use current: %s)",
          success_read ? "read HW addr length of permanent MAC address differs"
                       : "unable to read permanent MAC address",
          priv->hw_addr);
    priv->hw_addr_perm = g_strdup(priv->hw_addr);

notify_and_out:
    _notify(self, PROP_PERM_HW_ADDRESS);
}

gboolean
nm_device_hw_addr_is_explict(NMDevice *self)
{
    NMDevicePrivate *priv;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    priv = NM_DEVICE_GET_PRIVATE(self);
    return !NM_IN_SET((HwAddrType) priv->hw_addr_type, HW_ADDR_TYPE_PERMANENT, HW_ADDR_TYPE_UNSET);
}

static gboolean
_hw_addr_matches(NMDevice *self, const guint8 *addr, gsize addr_len)
{
    const char *cur_addr;

    cur_addr = nm_device_get_hw_address(self);
    return cur_addr && nm_utils_hwaddr_matches(addr, addr_len, cur_addr, -1);
}

static gboolean
_hw_addr_set(NMDevice         *self,
             const char *const addr,
             const char *const operation,
             const char *const detail)
{
    NMDevicePrivate *priv;
    gboolean         success = FALSE;
    int              r;
    guint8           addr_bytes[_NM_UTILS_HWADDR_LEN_MAX];
    gsize            addr_len;
    gboolean         was_taken_down = FALSE;
    gboolean         retry_down;

    nm_assert(NM_IS_DEVICE(self));
    nm_assert(addr);
    nm_assert(operation);

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (!_nm_utils_hwaddr_aton(addr, addr_bytes, sizeof(addr_bytes), &addr_len))
        g_return_val_if_reached(FALSE);

    /* Do nothing if current MAC is same */
    if (_hw_addr_matches(self, addr_bytes, addr_len)) {
        _LOGT(LOGD_DEVICE, "set-hw-addr: no MAC address change needed (%s)", addr);
        return TRUE;
    }

    if (priv->hw_addr_len && priv->hw_addr_len != addr_len) {
        _LOGT(LOGD_DEVICE,
              "set-hw-addr: setting MAC address to '%s' (%s, %s) failed because of wrong address "
              "length (should be %u bytes)",
              addr,
              operation,
              detail,
              priv->hw_addr_len);
        return FALSE;
    }

    _LOGT(LOGD_DEVICE,
          "set-hw-addr: setting MAC address to '%s' (%s, %s)...",
          addr,
          operation,
          detail);

    if (nm_device_get_device_type(self) == NM_DEVICE_TYPE_WIFI) {
        /* Always take the device down for Wi-Fi because
         * wpa_supplicant needs it to properly detect the MAC
         * change. */
        retry_down     = FALSE;
        was_taken_down = TRUE;
        nm_device_take_down(self, FALSE);
    }

again:
    r       = nm_platform_link_set_address(nm_device_get_platform(self),
                                     nm_device_get_ip_ifindex(self),
                                     addr_bytes,
                                     addr_len);
    success = (r >= 0);
    if (!success) {
        retry_down =
            !was_taken_down && r != -NME_PL_NOT_FOUND
            && nm_platform_link_is_up(nm_device_get_platform(self), nm_device_get_ip_ifindex(self));
        _NMLOG((retry_down || r == -NME_PL_NOT_FOUND) ? LOGL_DEBUG : LOGL_WARN,
               LOGD_DEVICE,
               "set-hw-addr: failed to %s MAC address to %s (%s) (%s)%s",
               operation,
               addr,
               detail,
               nm_strerror(r),
               retry_down ? " (retry with taking down)" : "");
    } else {
        /* MAC address successfully changed; update the current MAC to match */
        nm_device_update_hw_address(self);

        if (!_hw_addr_matches(self, addr_bytes, addr_len)) {
            gint64 poll_end, now;

            _LOGD(LOGD_DEVICE,
                  "set-hw-addr: new MAC address %s not successfully %s (%s) (refresh link)",
                  addr,
                  operation,
                  detail);

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
             * taking down the device. Let's add another 100 msec to that.
             *
             * wait/poll up to 100 msec until it changes. */

            poll_end = nm_utils_get_monotonic_timestamp_usec() + (100 * 1000);
            for (;;) {
                if (!nm_platform_link_refresh(nm_device_get_platform(self),
                                              nm_device_get_ip_ifindex(self)))
                    goto handle_fail;
                if (!nm_device_update_hw_address(self))
                    goto handle_wait;
                if (!_hw_addr_matches(self, addr_bytes, addr_len))
                    goto handle_fail;

                break;
handle_wait:
                now = nm_utils_get_monotonic_timestamp_usec();
                if (now < poll_end) {
                    g_usleep(NM_MIN(poll_end - now, 500));
                    continue;
                }
handle_fail:
                success = FALSE;
                break;
            }
        }

        if (success) {
            retry_down = FALSE;
            _LOGI(LOGD_DEVICE, "set-hw-addr: %s MAC address to %s (%s)", operation, addr, detail);
        } else {
            retry_down = !was_taken_down
                         && nm_platform_link_is_up(nm_device_get_platform(self),
                                                   nm_device_get_ip_ifindex(self));

            _NMLOG(retry_down ? LOGL_DEBUG : LOGL_WARN,
                   LOGD_DEVICE,
                   "set-hw-addr: new MAC address %s not successfully %s (%s)%s",
                   addr,
                   operation,
                   detail,
                   retry_down ? " (retry with taking down)" : "");
        }
    }

    if (retry_down) {
        /* changing the MAC address failed, but also the device was up (and we did not yet try to take
         * it down). Optimally, we change the MAC address without taking the device down, but some
         * devices don't like that. So, retry with taking the device down. */
        retry_down     = FALSE;
        was_taken_down = TRUE;
        nm_device_take_down(self, FALSE);
        goto again;
    }

    if (was_taken_down) {
        if (!nm_device_bring_up(self))
            return FALSE;
    }

    return success;
}

gboolean
nm_device_hw_addr_set(NMDevice *self, const char *addr, const char *detail, gboolean set_permanent)
{
    NMDevicePrivate *priv;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (!addr)
        g_return_val_if_reached(FALSE);

    if (set_permanent) {
        /* The type is set to PERMANENT by NMDeviceVlan when taking the MAC
         * address from the parent and by NMDeviceWifi when setting a random MAC
         * address during scanning.
         */
        priv->hw_addr_type = HW_ADDR_TYPE_PERMANENT;
    }

    return _hw_addr_set(self, addr, "set", detail);
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
 * @error: on return, an error or %NULL
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
_hw_addr_get_cloned(NMDevice     *self,
                    NMConnection *connection,
                    gboolean      is_wifi,
                    gboolean     *preserve,
                    char        **hwaddr,
                    HwAddrType   *hwaddr_type,
                    const char  **hwaddr_detail,
                    GError      **error)
{
    NMDevicePrivate *priv;
    gs_free char    *hw_addr_generated = NULL;
    const char      *addr;
    const char      *addr_setting;
    char            *addr_out;
    HwAddrType       type_out;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);
    g_return_val_if_fail(NM_IS_CONNECTION(connection), FALSE);
    g_return_val_if_fail(!error || !*error, FALSE);

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (!connection)
        g_return_val_if_reached(FALSE);

    addr_setting = _prop_get_x_cloned_mac_address(self, connection, is_wifi);

    addr = addr_setting;

    if (nm_streq(addr, NM_CLONED_MAC_PRESERVE)) {
        /* "preserve" means to reset the initial MAC address. */
        NM_SET_OUT(preserve, TRUE);
        NM_SET_OUT(hwaddr, NULL);
        NM_SET_OUT(hwaddr_type, HW_ADDR_TYPE_UNSET);
        NM_SET_OUT(hwaddr_detail, addr_setting);
        return TRUE;
    }

    if (nm_streq(addr, NM_CLONED_MAC_PERMANENT)) {
        gboolean is_fake;

        addr = nm_device_get_permanent_hw_address_full(self, TRUE, &is_fake);
        if (is_fake) {
            /* Preserve the current address if the permanent address if fake */
            NM_SET_OUT(preserve, TRUE);
            NM_SET_OUT(hwaddr, NULL);
            NM_SET_OUT(hwaddr_type, HW_ADDR_TYPE_UNSET);
            NM_SET_OUT(hwaddr_detail, addr_setting);
            return TRUE;
        } else if (!addr) {
            g_set_error_literal(error,
                                NM_DEVICE_ERROR,
                                NM_DEVICE_ERROR_FAILED,
                                "failed to retrieve permanent address");
            return FALSE;
        }
        addr_out = g_strdup(addr);
        type_out = HW_ADDR_TYPE_PERMANENT;
    } else if (NM_IN_STRSET(addr, NM_CLONED_MAC_RANDOM)) {
        if (priv->hw_addr_type == HW_ADDR_TYPE_GENERATED) {
            /* hm, we already use a generate MAC address. Most certainly, that is from the same
             * activation request, so we should not create a new random address, instead keep
             * the current. */
            goto out_no_action;
        }
        hw_addr_generated = nm_utils_hw_addr_gen_random_eth(
            nm_device_get_initial_hw_address(self),
            _prop_get_x_generate_mac_address_mask(self, connection, is_wifi));
        if (!hw_addr_generated) {
            g_set_error(error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_FAILED,
                        "failed to generate %s MAC address",
                        "random");
            return FALSE;
        }

        addr_out = g_steal_pointer(&hw_addr_generated);
        type_out = HW_ADDR_TYPE_GENERATED;
    } else if (NM_IN_STRSET(addr, NM_CLONED_MAC_STABLE)) {
        NMUtilsStableType stable_type;
        const char       *stable_id;

        if (priv->hw_addr_type == HW_ADDR_TYPE_GENERATED) {
            /* hm, we already use a generate MAC address. Most certainly, that is from the same
             * activation request, so let's skip creating the stable address anew. */
            goto out_no_action;
        }

        stable_id         = _prop_get_connection_stable_id(self, connection, &stable_type);
        hw_addr_generated = nm_utils_hw_addr_gen_stable_eth(
            stable_type,
            stable_id,
            nm_device_get_ip_iface(self),
            nm_device_get_initial_hw_address(self),
            _prop_get_x_generate_mac_address_mask(self, connection, is_wifi));
        if (!hw_addr_generated) {
            g_set_error(error,
                        NM_DEVICE_ERROR,
                        NM_DEVICE_ERROR_FAILED,
                        "failed to generate %s MAC address",
                        "stable");
            return FALSE;
        }

        addr_out = g_steal_pointer(&hw_addr_generated);
        type_out = HW_ADDR_TYPE_GENERATED;
    } else {
        /* this must be a valid address. Otherwise, we shouldn't come here. */
        if (!nm_utils_hwaddr_valid(addr, -1))
            g_return_val_if_reached(FALSE);

        addr_out = g_strdup(addr);
        type_out = HW_ADDR_TYPE_EXPLICIT;
    }

    NM_SET_OUT(preserve, FALSE);
    NM_SET_OUT(hwaddr, addr_out);
    NM_SET_OUT(hwaddr_type, type_out);
    NM_SET_OUT(hwaddr_detail, addr_setting);
    return TRUE;
out_no_action:
    NM_SET_OUT(preserve, FALSE);
    NM_SET_OUT(hwaddr, NULL);
    NM_SET_OUT(hwaddr_type, HW_ADDR_TYPE_UNSET);
    NM_SET_OUT(hwaddr_detail, NULL);
    return TRUE;
}

gboolean
nm_device_hw_addr_get_cloned(NMDevice     *self,
                             NMConnection *connection,
                             gboolean      is_wifi,
                             char        **hwaddr,
                             gboolean     *preserve,
                             GError      **error)
{
    if (!_hw_addr_get_cloned(self, connection, is_wifi, preserve, hwaddr, NULL, NULL, error))
        return FALSE;

    return TRUE;
}

gboolean
nm_device_hw_addr_set_cloned(NMDevice *self, NMConnection *connection, gboolean is_wifi)
{
    NMDevicePrivate      *priv;
    gboolean              preserve = FALSE;
    gs_free char         *hwaddr   = NULL;
    const char           *detail   = NULL;
    HwAddrType            type     = HW_ADDR_TYPE_UNSET;
    gs_free_error GError *error    = NULL;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);
    priv = NM_DEVICE_GET_PRIVATE(self);

    if (!_hw_addr_get_cloned(self,
                             connection,
                             is_wifi,
                             &preserve,
                             &hwaddr,
                             &type,
                             &detail,
                             &error)) {
        _LOGW(LOGD_DEVICE, "set-hw-addr: %s", error->message);
        return FALSE;
    }

    if (preserve)
        return nm_device_hw_addr_reset(self, detail);

    if (hwaddr) {
        priv->hw_addr_type = type;
        return _hw_addr_set(self, hwaddr, "set-cloned", detail);
    }

    return TRUE;
}

gboolean
nm_device_hw_addr_reset(NMDevice *self, const char *detail)
{
    NMDevicePrivate *priv;
    const char      *addr;
    int              ifindex;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->hw_addr_type == HW_ADDR_TYPE_UNSET)
        return TRUE;

    priv->hw_addr_type = HW_ADDR_TYPE_UNSET;

    ifindex = nm_device_get_ip_ifindex(self);
    if (ifindex <= 0) {
        return TRUE;
    }

    addr = nm_device_get_initial_hw_address(self);
    if (!addr) {
        /* as hw_addr_type is not UNSET, we expect that we can get an
         * initial address to which to reset. */
        g_return_val_if_reached(FALSE);
    }

    return _hw_addr_set(self, addr, "reset", detail);
}

const char *
nm_device_get_permanent_hw_address_full(NMDevice *self,
                                        gboolean  force_freeze,
                                        gboolean *out_is_fake)
{
    NMDevicePrivate *priv;

    g_return_val_if_fail(NM_IS_DEVICE(self), ({
                             NM_SET_OUT(out_is_fake, FALSE);
                             NULL;
                         }));

    priv = NM_DEVICE_GET_PRIVATE(self);

    if (!priv->hw_addr_perm && force_freeze) {
        /* somebody requests a permanent MAC address, but we don't have it set
         * yet. We cannot delay it any longer and try to get it without waiting
         * for UDEV. */
        nm_device_update_permanent_hw_address(self, TRUE);
    }

    NM_SET_OUT(out_is_fake, priv->hw_addr_perm && priv->hw_addr_perm_fake);
    return priv->hw_addr_perm;
}

const char *
nm_device_get_permanent_hw_address(NMDevice *self)
{
    return nm_device_get_permanent_hw_address_full(self, TRUE, NULL);
}

const char *
nm_device_get_initial_hw_address(NMDevice *self)
{
    g_return_val_if_fail(NM_IS_DEVICE(self), NULL);

    return NM_DEVICE_GET_PRIVATE(self)->hw_addr_initial;
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
nm_device_spec_match_list(NMDevice *self, const GSList *specs)
{
    return nm_device_spec_match_list_full(self, specs, FALSE);
}

int
nm_device_spec_match_list_full(NMDevice *self, const GSList *specs, int no_match_value)
{
    NMMatchSpecDeviceData data;
    NMMatchSpecMatchType  m;

    m = nm_match_spec_device(specs, nm_match_spec_device_data_init_from_device(&data, self));
    return nm_match_spec_match_type_to_bool(m, no_match_value);
}

guint
nm_device_get_supplicant_timeout(NMDevice *self)
{
    NMConnection   *connection;
    NMSetting8021x *s_8021x;
    int             timeout;
#define SUPPLICANT_DEFAULT_TIMEOUT 25

    g_return_val_if_fail(NM_IS_DEVICE(self), SUPPLICANT_DEFAULT_TIMEOUT);

    connection = nm_device_get_applied_connection(self);

    g_return_val_if_fail(connection, SUPPLICANT_DEFAULT_TIMEOUT);

    s_8021x = nm_connection_get_setting_802_1x(connection);
    if (s_8021x) {
        timeout = nm_setting_802_1x_get_auth_timeout(s_8021x);
        if (timeout > 0)
            return timeout;
    }

    return nm_config_data_get_connection_default_int64(NM_CONFIG_GET_DATA,
                                                       NM_CON_DEFAULT("802-1x.auth-timeout"),
                                                       self,
                                                       1,
                                                       G_MAXINT32,
                                                       SUPPLICANT_DEFAULT_TIMEOUT);
}

gboolean
nm_device_auth_retries_try_next(NMDevice *self)
{
    NMDevicePrivate     *priv;
    NMSettingConnection *s_con;
    int                  auth_retries;

    g_return_val_if_fail(NM_IS_DEVICE(self), FALSE);

    priv         = NM_DEVICE_GET_PRIVATE(self);
    auth_retries = priv->auth_retries;

    if (G_UNLIKELY(auth_retries == NM_DEVICE_AUTH_RETRIES_UNSET)) {
        auth_retries = -1;

        s_con = nm_device_get_applied_setting(self, NM_TYPE_SETTING_CONNECTION);
        if (s_con)
            auth_retries = nm_setting_connection_get_auth_retries(s_con);

        if (auth_retries == -1) {
            auth_retries = nm_config_data_get_connection_default_int64(
                NM_CONFIG_GET_DATA,
                NM_CON_DEFAULT("connection.auth-retries"),
                self,
                -1,
                G_MAXINT32,
                -1);
        }

        if (auth_retries == 0)
            auth_retries = NM_DEVICE_AUTH_RETRIES_INFINITY;
        else if (auth_retries == -1)
            auth_retries = NM_DEVICE_AUTH_RETRIES_DEFAULT;
        else
            nm_assert(auth_retries > 0);

        priv->auth_retries = auth_retries;
    }

    if (auth_retries == NM_DEVICE_AUTH_RETRIES_INFINITY)
        return TRUE;
    if (auth_retries <= 0) {
        nm_assert(auth_retries == 0);
        return FALSE;
    }
    priv->auth_retries--;
    return TRUE;
}

static const char *
_resolver_state_to_string(ResolverState state)
{
    switch (state) {
    case RESOLVER_WAIT_ADDRESS:
        return "WAIT-ADDRESS";
    case RESOLVER_STARTED:
        return "STARTED";
    case RESOLVER_DONE:
        return "DONE";
    }
    nm_assert_not_reached();
    return "UNKNOWN";
}

static void
hostname_dns_lookup_callback(GObject *source, GAsyncResult *result, gpointer user_data)
{
    HostnameResolver     *resolver;
    NMDevice             *self;
    gs_free char         *addr_str = NULL;
    gs_free char         *output   = NULL;
    gs_free_error GError *error    = NULL;

    output = nm_device_resolve_address_finish(result, &error);
    if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        return;

    resolver        = user_data;
    self            = resolver->device;
    resolver->state = RESOLVER_DONE;

    if (error) {
        _LOGD(LOGD_DNS,
              "hostname-from-dns: ipv%c resolver %s: lookup error for %s: %s",
              nm_utils_addr_family_to_char(resolver->addr_family),
              _resolver_state_to_string(RESOLVER_DONE),
              (addr_str = g_inet_address_to_string(resolver->address)),
              error->message);
    } else {
        gboolean valid;

        resolver->hostname = g_steal_pointer(&output);
        valid              = nm_utils_validate_hostname(resolver->hostname);

        _LOGD(LOGD_DNS,
              "hostname-from-dns: ipv%c resolver %s: lookup successful for %s, result %s%s%s%s",
              nm_utils_addr_family_to_char(resolver->addr_family),
              _resolver_state_to_string(RESOLVER_DONE),
              (addr_str = g_inet_address_to_string(resolver->address)),
              NM_PRINT_FMT_QUOTE_STRING(resolver->hostname),
              valid ? "" : " (invalid)");

        if (!valid)
            nm_clear_g_free(&resolver->hostname);
    }

    nm_clear_g_cancellable(&resolver->cancellable);
    g_signal_emit(self, signals[DNS_LOOKUP_DONE], 0);
}

static gboolean
hostname_dns_address_timeout(gpointer user_data)
{
    HostnameResolver *resolver = user_data;
    NMDevice         *self     = resolver->device;

    g_return_val_if_fail(NM_IS_DEVICE(self), G_SOURCE_REMOVE);

    nm_assert(resolver->state == RESOLVER_WAIT_ADDRESS);
    nm_assert(!resolver->address);
    nm_assert(!resolver->cancellable);

    _LOGT(LOGD_DNS,
          "hostname-from-dns: ipv%c state %s: timed out while waiting for address",
          nm_utils_addr_family_to_char(resolver->addr_family),
          _resolver_state_to_string(RESOLVER_DONE));

    resolver->timeout_id = 0;
    resolver->state      = RESOLVER_DONE;
    g_signal_emit(self, signals[DNS_LOOKUP_DONE], 0);

    return G_SOURCE_REMOVE;
}

void
nm_device_clear_dns_lookup_data(NMDevice *self, const char *reason)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->hostname_resolver_4 || priv->hostname_resolver_6) {
        _LOGT(LOGD_DNS, "hostname-from-dns: resetting (%s)", reason);
        nm_clear_pointer(&priv->hostname_resolver_4, _hostname_resolver_free);
        nm_clear_pointer(&priv->hostname_resolver_6, _hostname_resolver_free);
    }
}

gboolean
nm_device_get_allow_autoconnect_on_external(NMDevice *self)
{
    return NM_DEVICE_GET_CLASS(self)->allow_autoconnect_on_external;
}

static GInetAddress *
get_address_for_hostname_dns_lookup(NMDevice *self, int addr_family)
{
    const int                    IS_IPv4 = NM_IS_IPv4(addr_family);
    NMPLookup                    lookup;
    const NMDedupMultiHeadEntry *head_entry;
    const NMDedupMultiEntry     *iter;
    const guint8                *addr6_ll    = NULL;
    const guint8                *addr6_nonll = NULL;
    int                          ifindex;

    ifindex = nm_device_get_ip_ifindex(self);
    if (ifindex <= 0)
        return NULL;

    /* FIXME(l3cfg): now we lookup the address from platform. Should we instead look
     *   it up from NML3Cfg? That is, take an address that we want to configure as
     *   opposed to an address that is configured? */
    head_entry = nm_platform_lookup(
        nm_device_get_platform(self),
        nmp_lookup_init_object_by_ifindex(&lookup, NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4), ifindex));

    if (head_entry) {
        c_list_for_each_entry (iter, &head_entry->lst_entries_head, lst_entries) {
            const NMPlatformIPXAddress *addr = NMP_OBJECT_CAST_IPX_ADDRESS(iter->obj);

            if (IS_IPv4) {
                if (nm_ip4_addr_is_loopback(addr->a4.address))
                    continue;
                return g_inet_address_new_from_bytes(addr->ax.address_ptr, G_SOCKET_FAMILY_IPV4);
            }

            if (addr->ax.n_ifa_flags & IFA_F_TENTATIVE)
                continue;

            /* For IPv6 prefer, in order:
             * - !link-local, !deprecated
             * - !link-local, deprecated
             * - link-local
             */

            if (IN6_ARE_ADDR_EQUAL(&addr->a6.address, &in6addr_loopback))
                continue;

            if (!IN6_IS_ADDR_LINKLOCAL(addr->ax.address_ptr)) {
                if (!(addr->ax.n_ifa_flags & IFA_F_DEPRECATED)) {
                    return g_inet_address_new_from_bytes(addr->ax.address_ptr,
                                                         G_SOCKET_FAMILY_IPV6);
                }
                addr6_nonll = addr->ax.address_ptr;
                continue;
            }

            addr6_ll = addr->ax.address_ptr;
        }

        if (addr6_nonll || addr6_ll)
            return g_inet_address_new_from_bytes(addr6_nonll ?: addr6_ll, G_SOCKET_FAMILY_IPV6);
    }

    return NULL;
}

/* return value is valid only immediately */
const char *
nm_device_get_hostname_from_dns_lookup(NMDevice *self, int addr_family, gboolean *out_wait)
{
    const int                     IS_IPv4 = NM_IS_IPv4(addr_family);
    NMDevicePrivate              *priv;
    HostnameResolver             *resolver;
    const char                   *method;
    gboolean                      address_changed = FALSE;
    gs_unref_object GInetAddress *new_address     = NULL;

    g_return_val_if_fail(NM_IS_DEVICE(self), NULL);
    priv = NM_DEVICE_GET_PRIVATE(self);

    /* If the device is not supposed to have addresses,
     * return an immediate empty result.*/
    if (!nm_device_get_applied_connection(self)) {
        nm_clear_pointer(&priv->hostname_resolver_x[IS_IPv4], _hostname_resolver_free);
        NM_SET_OUT(out_wait, FALSE);
        return NULL;
    }

    if (!priv->carrier) {
        nm_clear_pointer(&priv->hostname_resolver_x[IS_IPv4], _hostname_resolver_free);
        NM_SET_OUT(out_wait, FALSE);
        return NULL;
    }

    method = nm_device_get_effective_ip_config_method(self, addr_family);
    if (IS_IPv4) {
        if (NM_IN_STRSET(method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED)) {
            nm_clear_pointer(&priv->hostname_resolver_x[IS_IPv4], _hostname_resolver_free);
            NM_SET_OUT(out_wait, FALSE);
            return NULL;
        }
    } else {
        if (NM_IN_STRSET(method,
                         NM_SETTING_IP6_CONFIG_METHOD_DISABLED,
                         NM_SETTING_IP6_CONFIG_METHOD_IGNORE)) {
            nm_clear_pointer(&priv->hostname_resolver_x[IS_IPv4], _hostname_resolver_free);
            NM_SET_OUT(out_wait, FALSE);
            return NULL;
        }
    }

    resolver = priv->hostname_resolver_x[IS_IPv4];
    if (!resolver) {
        resolver  = g_slice_new(HostnameResolver);
        *resolver = (HostnameResolver){
            .device      = self,
            .addr_family = addr_family,
            .state       = RESOLVER_WAIT_ADDRESS,
        };
        priv->hostname_resolver_x[IS_IPv4] = resolver;
    }

    /* Determine the most suitable address of the interface
     * and whether it changed from the previous lookup */
    new_address = get_address_for_hostname_dns_lookup(self, addr_family);
    if (new_address && resolver->address) {
        if (!g_inet_address_equal(new_address, resolver->address))
            address_changed = TRUE;
    } else if (new_address != resolver->address)
        address_changed = TRUE;

    if (address_changed) {
        /* set new state before logging */
        if (new_address)
            resolver->state = RESOLVER_STARTED;
        else
            resolver->state = RESOLVER_WAIT_ADDRESS;
    }

    {
        gs_free char *old_str = NULL;
        gs_free char *new_str = NULL;

        if (address_changed) {
            _LOGT(LOGD_DNS,
                  "hostname-from-dns: ipv%c resolver %s, address changed from %s to %s",
                  nm_utils_addr_family_to_char(resolver->addr_family),
                  _resolver_state_to_string(resolver->state),
                  resolver->address ? (old_str = g_inet_address_to_string(resolver->address))
                                    : "(null)",
                  new_address ? (new_str = g_inet_address_to_string(new_address)) : "(null)");
        }
    }

    if (address_changed) {
        nm_clear_g_cancellable(&resolver->cancellable);
        g_clear_object(&resolver->address);
    }

    if (address_changed && new_address) {
        resolver->cancellable = g_cancellable_new();
        resolver->address     = g_steal_pointer(&new_address);

        nm_device_resolve_address(addr_family,
                                  g_inet_address_to_bytes(resolver->address),
                                  resolver->cancellable,
                                  hostname_dns_lookup_callback,
                                  resolver);
        nm_clear_g_source(&resolver->timeout_id);
    }

    switch (resolver->state) {
    case RESOLVER_WAIT_ADDRESS:
        if (!resolver->timeout_id)
            resolver->timeout_id = g_timeout_add(30000, hostname_dns_address_timeout, resolver);
        NM_SET_OUT(out_wait, TRUE);
        return NULL;
    case RESOLVER_STARTED:
        NM_SET_OUT(out_wait, TRUE);
        return NULL;
    case RESOLVER_DONE:
        NM_SET_OUT(out_wait, FALSE);
        return resolver->hostname;
    }

    return nm_assert_unreachable_val(NULL);
}

/*****************************************************************************/

static const char *
_activation_func_to_string(ActivationHandleFunc func)
{
#define FUNC_TO_STRING_CHECK_AND_RETURN(func, f) \
    G_STMT_START                                 \
    {                                            \
        if ((func) == (f))                       \
            return #f;                           \
    }                                            \
    G_STMT_END
    FUNC_TO_STRING_CHECK_AND_RETURN(func, activate_stage1_device_prepare);
    FUNC_TO_STRING_CHECK_AND_RETURN(func, activate_stage2_device_config);
    FUNC_TO_STRING_CHECK_AND_RETURN(func, activate_stage3_ip_config);
    g_return_val_if_reached("unknown");
}

static GVariant *
_device_get_ports_variant(NMDevice *device)
{
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(device);
    SlaveInfo       *info;
    GVariantBuilder  builder;
    gboolean         any = FALSE;

    if (priv->ports_variant)
        return priv->ports_variant;

    c_list_for_each_entry (info, &priv->slaves, lst_slave) {
        const char *path;

        if (!NM_DEVICE_GET_PRIVATE(info->slave)->is_enslaved)
            continue;
        path = nm_dbus_object_get_path(NM_DBUS_OBJECT(info->slave));
        if (!path)
            continue;
        if (!any) {
            any = TRUE;
            g_variant_builder_init(&builder, G_VARIANT_TYPE("ao"));
        }
        g_variant_builder_add(&builder, "o", path);
    }
    priv->ports_variant = any ? g_variant_ref_sink(g_variant_builder_end(&builder))
                              : g_variant_ref(nm_g_variant_singleton_ao());

    return priv->ports_variant;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDevice        *self = NM_DEVICE(object);
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_UDI:
        /* UDI is (depending on the device type) a path to sysfs and can contain
         * non-UTF-8.
         *   ip link add name $'d\xccf\\c' type dummy  */
        g_value_take_string(
            value,
            nm_utils_str_utf8safe_escape_cp(priv->udi, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE));
        break;
    case PROP_PATH:
        g_value_take_string(
            value,
            nm_utils_str_utf8safe_escape_cp(priv->path, NM_UTILS_STR_UTF8_SAFE_FLAG_NONE));
        break;
    case PROP_IFACE:
        g_value_take_string(
            value,
            nm_utils_str_utf8safe_escape_cp(priv->iface, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL));
        break;
    case PROP_IP_IFACE:
        g_value_set_string(value, priv->prop_ip_iface);
        break;
    case PROP_IFINDEX:
        g_value_set_int(value, priv->ifindex);
        break;
    case PROP_DRIVER:
        g_value_take_string(
            value,
            nm_utils_str_utf8safe_escape_cp(priv->driver, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL));
        break;
    case PROP_DRIVER_VERSION:
        g_value_take_string(
            value,
            nm_utils_str_utf8safe_escape_cp(priv->driver_version,
                                            NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL));
        break;
    case PROP_FIRMWARE_VERSION:
        g_value_take_string(
            value,
            nm_utils_str_utf8safe_escape_cp(priv->firmware_version,
                                            NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL));
        break;
    case PROP_CAPABILITIES:
        g_value_set_uint(value, (priv->capabilities & ~NM_DEVICE_CAP_INTERNAL_MASK));
        break;
    case PROP_IP4_ADDRESS:
        g_value_set_variant(value, nm_g_variant_singleton_u_0());
        break;
    case PROP_CARRIER:
        g_value_set_boolean(value, priv->carrier);
        break;
    case PROP_MTU:
        g_value_set_uint(value, priv->mtu);
        break;
    case PROP_IP4_CONFIG:
        nm_dbus_utils_g_value_set_object_path(value, priv->l3ipdata_4.ip_config);
        break;
    case PROP_DHCP4_CONFIG:
        nm_dbus_utils_g_value_set_object_path(value, priv->ipdhcp_data_4.config);
        break;
    case PROP_IP6_CONFIG:
        nm_dbus_utils_g_value_set_object_path(value, priv->l3ipdata_6.ip_config);
        break;
    case PROP_DHCP6_CONFIG:
        nm_dbus_utils_g_value_set_object_path(value, priv->ipdhcp_data_6.config);
        break;
    case PROP_STATE:
        g_value_set_uint(value, priv->state);
        break;
    case PROP_STATE_REASON:
        g_value_take_variant(value, g_variant_new("(uu)", priv->state, priv->state_reason));
        break;
    case PROP_ACTIVE_CONNECTION:
        g_value_set_string(value, nm_dbus_track_obj_path_get(&priv->act_request));
        break;
    case PROP_DEVICE_TYPE:
        g_value_set_uint(value, priv->type);
        break;
    case PROP_LINK_TYPE:
        g_value_set_uint(value, priv->link_type);
        break;
    case PROP_MANAGED:
        /* The managed state exposed on D-Bus only depends on the current device state alone. */
        g_value_set_boolean(value, nm_device_get_state(self) > NM_DEVICE_STATE_UNMANAGED);
        break;
    case PROP_AUTOCONNECT:
        g_value_set_boolean(
            value,
            nm_device_autoconnect_blocked_get(self, NM_DEVICE_AUTOCONNECT_BLOCKED_ALL) ? FALSE
                                                                                       : TRUE);
        break;
    case PROP_FIRMWARE_MISSING:
        g_value_set_boolean(value, priv->firmware_missing);
        break;
    case PROP_NM_PLUGIN_MISSING:
        g_value_set_boolean(value, priv->nm_plugin_missing);
        break;
    case PROP_TYPE_DESC:
        g_value_set_string(value, priv->type_desc);
        break;
    case PROP_AVAILABLE_CONNECTIONS:
        nm_dbus_utils_g_value_set_object_path_from_hash(value, priv->available_connections, TRUE);
        break;
    case PROP_PHYSICAL_PORT_ID:
        g_value_set_string(value, priv->physical_port_id);
        break;
    case PROP_MASTER:
        g_value_set_object(value, nm_device_get_master(self));
        break;
    case PROP_PARENT:
        g_value_set_string(value, nm_dbus_track_obj_path_get(&priv->parent_device));
        break;
    case PROP_HW_ADDRESS:
        g_value_set_string(value, priv->hw_addr);
        break;
    case PROP_PERM_HW_ADDRESS:
    {
        const char *perm_hw_addr;
        gboolean    perm_hw_addr_is_fake;

        perm_hw_addr = nm_device_get_permanent_hw_address_full(self, FALSE, &perm_hw_addr_is_fake);
        /* this property is exposed on D-Bus for NMDeviceEthernet and NMDeviceWifi. */
        g_value_set_string(value, perm_hw_addr && !perm_hw_addr_is_fake ? perm_hw_addr : NULL);
        break;
    }
    case PROP_HAS_PENDING_ACTION:
        g_value_set_boolean(value, nm_device_has_pending_action(self));
        break;
    case PROP_METERED:
        g_value_set_uint(value, priv->metered);
        break;
    case PROP_LLDP_NEIGHBORS:
        g_value_set_variant(value,
                            priv->lldp_listener
                                ? nm_lldp_listener_get_neighbors(priv->lldp_listener)
                                : nm_g_variant_singleton_aaLsvI());
        break;
    case PROP_REAL:
        g_value_set_boolean(value, nm_device_is_real(self));
        break;
    case PROP_SLAVES:
    case PROP_PORTS:
        g_value_set_variant(value, _device_get_ports_variant(self));
        break;
    case PROP_STATISTICS_REFRESH_RATE_MS:
        g_value_set_uint(value, priv->stats.refresh_rate_ms);
        break;
    case PROP_STATISTICS_TX_BYTES:
        g_value_set_uint64(value, priv->stats.tx_bytes);
        break;
    case PROP_STATISTICS_RX_BYTES:
        g_value_set_uint64(value, priv->stats.rx_bytes);
        break;
    case PROP_IP4_CONNECTIVITY:
        g_value_set_uint(value, priv->concheck_x[1].state);
        break;
    case PROP_IP6_CONNECTIVITY:
        g_value_set_uint(value, priv->concheck_x[0].state);
        break;
    case PROP_INTERFACE_FLAGS:
        g_value_set_uint(value, priv->interface_flags);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMDevice        *self = (NMDevice *) object;
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_UDI:
        /* construct-only */
        priv->udi = g_value_dup_string(value);
        break;
    case PROP_IFACE:
        /* construct-only */
        priv->iface_ = g_value_dup_string(value);
        break;
    case PROP_DRIVER:
        /* construct-only */
        priv->driver = g_value_dup_string(value);
        break;
    case PROP_MANAGED:
        /* via D-Bus */
        if (nm_device_is_real(self)) {
            gboolean            managed;
            NMDeviceStateReason reason;

            managed = g_value_get_boolean(value);
            if (managed) {
                reason = NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED;
                if (NM_IN_SET_TYPED(NMDeviceSysIfaceState,
                                    priv->sys_iface_state,
                                    NM_DEVICE_SYS_IFACE_STATE_EXTERNAL,
                                    NM_DEVICE_SYS_IFACE_STATE_REMOVED))
                    nm_device_sys_iface_state_set(self, NM_DEVICE_SYS_IFACE_STATE_ASSUME);
            } else {
                reason = NM_DEVICE_STATE_REASON_REMOVED;
                nm_device_sys_iface_state_set(self, NM_DEVICE_SYS_IFACE_STATE_REMOVED);
            }
            nm_device_set_unmanaged_by_flags(self, NM_UNMANAGED_USER_EXPLICIT, !managed, reason);
        }
        break;
    case PROP_AUTOCONNECT:
        /* via D-Bus */
        if (g_value_get_boolean(value))
            nm_device_autoconnect_blocked_unset(self, NM_DEVICE_AUTOCONNECT_BLOCKED_ALL);
        else
            nm_device_autoconnect_blocked_set(self, NM_DEVICE_AUTOCONNECT_BLOCKED_USER);
        break;
    case PROP_NM_PLUGIN_MISSING:
        /* construct-only */
        priv->nm_plugin_missing = g_value_get_boolean(value);
        break;
    case PROP_DEVICE_TYPE:
        /* construct-only */
        nm_assert(priv->type == NM_DEVICE_TYPE_UNKNOWN);
        priv->type = g_value_get_uint(value);
        nm_assert(priv->type > NM_DEVICE_TYPE_UNKNOWN);
        nm_assert(priv->type <= NM_DEVICE_TYPE_LOOPBACK);
        break;
    case PROP_LINK_TYPE:
        /* construct-only */
        nm_assert(priv->link_type == NM_LINK_TYPE_NONE);
        priv->link_type = g_value_get_uint(value);
        break;
    case PROP_TYPE_DESC:
        /* construct-only */
        priv->type_desc = g_value_dup_string(value);
        break;
    case PROP_PERM_HW_ADDRESS:
        /* construct-only */
        priv->hw_addr_perm = g_value_dup_string(value);
        break;
    case PROP_STATISTICS_REFRESH_RATE_MS:
        /* via D-Bus */
        _stats_set_refresh_rate(self, g_value_get_uint(value));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_device_init(NMDevice *self)
{
    NMDevicePrivate *priv;

    priv = G_TYPE_INSTANCE_GET_PRIVATE(self, NM_TYPE_DEVICE, NMDevicePrivate);

    self->_priv = priv;

    c_list_init(&priv->concheck_lst_head);
    c_list_init(&self->devices_lst);
    c_list_init(&self->devcon_dev_lst_head);
    c_list_init(&self->policy_auto_activate_lst);
    c_list_init(&priv->slaves);

    priv->ipdhcp_data_6.v6.mode = NM_NDISC_DHCP_LEVEL_NONE;

    priv->concheck_x[0].state = NM_CONNECTIVITY_UNKNOWN;
    priv->concheck_x[1].state = NM_CONNECTIVITY_UNKNOWN;

    nm_dbus_track_obj_path_init(&priv->parent_device, G_OBJECT(self), obj_properties[PROP_PARENT]);
    nm_dbus_track_obj_path_init(&priv->act_request,
                                G_OBJECT(self),
                                obj_properties[PROP_ACTIVE_CONNECTION]);

    priv->netns = g_object_ref(NM_NETNS_GET);

    priv->autoconnect_blocked_flags = DEFAULT_AUTOCONNECT ? NM_DEVICE_AUTOCONNECT_BLOCKED_NONE
                                                          : NM_DEVICE_AUTOCONNECT_BLOCKED_USER;

    priv->auth_retries          = NM_DEVICE_AUTH_RETRIES_UNSET;
    priv->type                  = NM_DEVICE_TYPE_UNKNOWN;
    priv->capabilities          = NM_DEVICE_CAP_NM_SUPPORTED;
    priv->state                 = NM_DEVICE_STATE_UNMANAGED;
    priv->state_reason          = NM_DEVICE_STATE_REASON_NONE;
    priv->unmanaged_flags       = NM_UNMANAGED_PLATFORM_INIT;
    priv->unmanaged_mask        = priv->unmanaged_flags;
    priv->available_connections = g_hash_table_new_full(nm_direct_hash, NULL, g_object_unref, NULL);
    priv->ip6_saved_properties  = g_hash_table_new_full(nm_str_hash, g_str_equal, NULL, g_free);

    priv->sys_iface_state_ = NM_DEVICE_SYS_IFACE_STATE_EXTERNAL;
    /* If networking is already disabled at boot, we want to manage all devices
     * after re-enabling networking; hence, the initial state is MANAGED. */
    priv->sys_iface_state_before_sleep = NM_DEVICE_SYS_IFACE_STATE_MANAGED;

    priv->promisc_reset = NM_OPTION_BOOL_DEFAULT;
}

static GObject *
constructor(GType type, guint n_construct_params, GObjectConstructParam *construct_params)
{
    GObject              *object;
    GObjectClass         *klass;
    NMDevice             *self;
    NMDevicePrivate      *priv;
    const NMPlatformLink *pllink;

    klass  = G_OBJECT_CLASS(nm_device_parent_class);
    object = klass->constructor(type, n_construct_params, construct_params);
    if (!object)
        return NULL;

    self = NM_DEVICE(object);
    priv = NM_DEVICE_GET_PRIVATE(self);

    if (priv->iface && G_LIKELY(!nm_utils_get_testing())) {
        pllink = nm_platform_link_get_by_ifname(nm_device_get_platform(self), priv->iface);

        if (pllink && link_type_compatible(self, pllink->type, NULL, NULL)) {
            _set_ifindex(self, pllink->ifindex, FALSE);
            priv->up = NM_FLAGS_HAS(pllink->n_ifi_flags, IFF_UP);
        }
    }

    if (priv->hw_addr_perm) {
        guint8 buf[_NM_UTILS_HWADDR_LEN_MAX];
        gsize  l;

        if (!_nm_utils_hwaddr_aton(priv->hw_addr_perm, buf, sizeof(buf), &l)) {
            nm_clear_g_free(&priv->hw_addr_perm);
            g_return_val_if_reached(object);
        }

        priv->hw_addr_len_ = l;
        priv->hw_addr      = nm_utils_hwaddr_ntoa(buf, l);
        _LOGT(LOGD_DEVICE, "hw-addr: has permanent hw-address '%s'", priv->hw_addr_perm);
    }

    return object;
}

static void
constructed(GObject *object)
{
    NMDevice        *self = NM_DEVICE(object);
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);
    NMPlatform      *platform;

    if (NM_DEVICE_GET_CLASS(self)->get_generic_capabilities)
        priv->capabilities |= NM_DEVICE_GET_CLASS(self)->get_generic_capabilities(self);

    platform = nm_device_get_platform(self);
    g_signal_connect(platform, NM_PLATFORM_SIGNAL_LINK_CHANGED, G_CALLBACK(link_changed_cb), self);

    priv->manager  = g_object_ref(NM_MANAGER_GET);
    priv->settings = g_object_ref(NM_SETTINGS_GET);

    g_signal_connect(priv->settings,
                     NM_SETTINGS_SIGNAL_CONNECTION_ADDED,
                     G_CALLBACK(cp_connection_added),
                     self);
    g_signal_connect(priv->settings,
                     NM_SETTINGS_SIGNAL_CONNECTION_UPDATED,
                     G_CALLBACK(cp_connection_updated),
                     self);
    g_signal_connect(priv->settings,
                     NM_SETTINGS_SIGNAL_CONNECTION_REMOVED,
                     G_CALLBACK(cp_connection_removed),
                     self);

    G_OBJECT_CLASS(nm_device_parent_class)->constructed(object);

    _LOGD(LOGD_DEVICE, "constructed (%s)", G_OBJECT_TYPE_NAME(self));
}

static void
dispose(GObject *object)
{
    NMDevice                   *self = NM_DEVICE(object);
    NMDevicePrivate            *priv = NM_DEVICE_GET_PRIVATE(self);
    NMPlatform                 *platform;
    NMDeviceConnectivityHandle *con_handle;
    gs_free_error GError       *cancelled_error = NULL;

    _LOGD(LOGD_DEVICE, "disposing");

    nm_assert(c_list_is_empty(&self->devices_lst));
    nm_assert(c_list_is_empty(&self->devcon_dev_lst_head));
    nm_assert(c_list_is_empty(&self->policy_auto_activate_lst));
    nm_assert(!self->policy_auto_activate_idle_source);

    while ((con_handle = c_list_first_entry(&priv->concheck_lst_head,
                                            NMDeviceConnectivityHandle,
                                            concheck_lst))) {
        if (!cancelled_error)
            nm_utils_error_set_cancelled(&cancelled_error, FALSE, "NMDevice");
        concheck_handle_complete(con_handle, cancelled_error);
    }

    nm_clear_g_cancellable(&priv->deactivating_cancellable);

    nm_device_assume_state_reset(self);

    _parent_set_ifindex(self, 0, FALSE);

    platform = nm_device_get_platform(self);
    g_signal_handlers_disconnect_by_func(platform, G_CALLBACK(link_changed_cb), self);

    nm_clear_g_signal_handler(nm_config_get(), &priv->config_changed_id);
    nm_clear_g_signal_handler(priv->manager, &priv->ifindex_changed_id);

    _dispatcher_cleanup(self);

    nm_pacrunner_manager_remove_clear(&priv->pacrunner_conf_id);

    _cleanup_generic_pre(self, CLEANUP_TYPE_KEEP);

    nm_assert(c_list_is_empty(&priv->slaves));

    /* Let the kernel manage IPv6LL again */
    _dev_addrgenmode6_set(self, NM_IN6_ADDR_GEN_MODE_EUI64);

    _cleanup_generic_post(self, NM_DEVICE_STATE_REASON_NONE, CLEANUP_TYPE_KEEP);

    nm_assert(priv->master_ready_id == 0);

    g_hash_table_remove_all(priv->ip6_saved_properties);

    nm_clear_g_source(&priv->recheck_assume_id);
    nm_clear_g_source(&priv->recheck_available.call_id);

    nm_clear_g_source(&priv->check_delete_unrealized_id);

    nm_clear_g_source_inst(&priv->stats.timeout_source);

    carrier_disconnected_action_cancel(self);

    _set_ifindex(self, 0, FALSE);
    _set_ifindex(self, 0, TRUE);

    if (priv->settings) {
        g_signal_handlers_disconnect_by_func(priv->settings, cp_connection_added, self);
        g_signal_handlers_disconnect_by_func(priv->settings, cp_connection_updated, self);
        g_signal_handlers_disconnect_by_func(priv->settings, cp_connection_removed, self);
    }

    available_connections_del_all(self);

    if (nm_clear_g_source_inst(&priv->carrier_wait_source))
        nm_device_remove_pending_action(self, NM_PENDING_ACTION_CARRIER_WAIT, FALSE);

    _clear_queued_act_request(priv, NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED);

    nm_clear_g_source(&priv->device_link_changed_id);
    nm_clear_g_source(&priv->device_ip_link_changed_id);

    lldp_setup(self, FALSE);

    nm_clear_g_source(&priv->concheck_x[0].p_cur_id);
    nm_clear_g_source(&priv->concheck_x[1].p_cur_id);

    nm_assert(!priv->sriov.pending);
    if (priv->sriov.next) {
        nm_g_slice_free(priv->sriov.next);
        priv->sriov.next = NULL;
    }

    g_clear_object(&priv->l3cfg_);
    g_clear_object(&priv->l3ipdata_4.ip_config);
    g_clear_object(&priv->l3ipdata_6.ip_config);

    G_OBJECT_CLASS(nm_device_parent_class)->dispose(object);

    if (nm_clear_g_source(&priv->queued_state.id)) {
        /* FIXME: we'd expect the queud_state to be already cleared and this statement
         * not being necessary. Add this check here to hopefully investigate crash
         * rh#1270247. */
        g_return_if_reached();
    }
}

static void
finalize(GObject *object)
{
    NMDevice        *self = NM_DEVICE(object);
    NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE(self);

    _LOGD(LOGD_DEVICE, "finalize(): %s", G_OBJECT_TYPE_NAME(self));

    g_free(priv->hw_addr);
    g_free(priv->hw_addr_perm);
    g_free(priv->hw_addr_initial);
    g_free(priv->pending_actions.arr);
    nm_clear_g_free(&priv->physical_port_id);
    g_free(priv->udi);
    g_free(priv->path);
    g_free(priv->iface_);
    g_free(priv->ip_iface_);
    g_free(priv->driver);
    g_free(priv->driver_version);
    g_free(priv->firmware_version);
    g_free(priv->type_desc);
    g_free(priv->current_stable_id);

    g_hash_table_unref(priv->ip6_saved_properties);
    g_hash_table_unref(priv->available_connections);

    nm_dbus_track_obj_path_deinit(&priv->parent_device);
    nm_dbus_track_obj_path_deinit(&priv->act_request);

    nm_g_variant_unref(priv->ports_variant);

    G_OBJECT_CLASS(nm_device_parent_class)->finalize(object);

    /* for testing, NMDeviceTest does not invoke NMDevice::constructed,
     * and thus @settings might be unset. */
    nm_g_object_unref(priv->settings);
    nm_g_object_unref(priv->manager);

    nm_g_object_unref(priv->concheck_mgr);

    g_object_unref(priv->netns);
}

/*****************************************************************************/

static const GDBusSignalInfo signal_info_state_changed = NM_DEFINE_GDBUS_SIGNAL_INFO_INIT(
    "StateChanged",
    .args = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("new_state", "u"),
                                      NM_DEFINE_GDBUS_ARG_INFO("old_state", "u"),
                                      NM_DEFINE_GDBUS_ARG_INFO("reason", "u"), ), );

static const NMDBusInterfaceInfoExtended interface_info_device = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE,
        .methods = NM_DEFINE_GDBUS_METHOD_INFOS(
            NM_DEFINE_DBUS_METHOD_INFO_EXTENDED(
                NM_DEFINE_GDBUS_METHOD_INFO_INIT(
                    "Reapply",
                    .in_args = NM_DEFINE_GDBUS_ARG_INFOS(
                        NM_DEFINE_GDBUS_ARG_INFO("connection", "a{sa{sv}}"),
                        NM_DEFINE_GDBUS_ARG_INFO("version_id", "t"),
                        NM_DEFINE_GDBUS_ARG_INFO("flags", "u"), ), ),
                .handle = impl_device_reapply, ),
            NM_DEFINE_DBUS_METHOD_INFO_EXTENDED(
                NM_DEFINE_GDBUS_METHOD_INFO_INIT(
                    "GetAppliedConnection",
                    .in_args  = NM_DEFINE_GDBUS_ARG_INFOS(NM_DEFINE_GDBUS_ARG_INFO("flags", "u"), ),
                    .out_args = NM_DEFINE_GDBUS_ARG_INFOS(
                        NM_DEFINE_GDBUS_ARG_INFO("connection", "a{sa{sv}}"),
                        NM_DEFINE_GDBUS_ARG_INFO("version_id", "t"), ), ),
                .handle = impl_device_get_applied_connection, ),
            NM_DEFINE_DBUS_METHOD_INFO_EXTENDED(NM_DEFINE_GDBUS_METHOD_INFO_INIT("Disconnect", ),
                                                .handle = impl_device_disconnect, ),
            NM_DEFINE_DBUS_METHOD_INFO_EXTENDED(NM_DEFINE_GDBUS_METHOD_INFO_INIT("Delete", ),
                                                .handle = impl_device_delete, ), ),
        .signals    = NM_DEFINE_GDBUS_SIGNAL_INFOS(&signal_info_state_changed, ),
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Udi", "s", NM_DEVICE_UDI),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Path", "s", NM_DEVICE_PATH),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Interface", "s", NM_DEVICE_IFACE),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("IpInterface", "s", NM_DEVICE_IP_IFACE),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Driver", "s", NM_DEVICE_DRIVER),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("DriverVersion",
                                                           "s",
                                                           NM_DEVICE_DRIVER_VERSION),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("FirmwareVersion",
                                                           "s",
                                                           NM_DEVICE_FIRMWARE_VERSION),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Capabilities",
                                                           "u",
                                                           NM_DEVICE_CAPABILITIES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Ip4Address",
                                                           "u",
                                                           NM_DEVICE_IP4_ADDRESS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("State", "u", NM_DEVICE_STATE),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("StateReason",
                                                           "(uu)",
                                                           NM_DEVICE_STATE_REASON),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("ActiveConnection",
                                                           "o",
                                                           NM_DEVICE_ACTIVE_CONNECTION),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Ip4Config", "o", NM_DEVICE_IP4_CONFIG),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Dhcp4Config",
                                                           "o",
                                                           NM_DEVICE_DHCP4_CONFIG),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Ip6Config", "o", NM_DEVICE_IP6_CONFIG),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Dhcp6Config",
                                                           "o",
                                                           NM_DEVICE_DHCP6_CONFIG),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READWRITABLE("Managed",
                                                               "b",
                                                               NM_DEVICE_MANAGED,
                                                               NM_AUTH_PERMISSION_NETWORK_CONTROL,
                                                               NM_AUDIT_OP_DEVICE_MANAGED),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READWRITABLE("Autoconnect",
                                                               "b",
                                                               NM_DEVICE_AUTOCONNECT,
                                                               NM_AUTH_PERMISSION_NETWORK_CONTROL,
                                                               NM_AUDIT_OP_DEVICE_AUTOCONNECT),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("FirmwareMissing",
                                                           "b",
                                                           NM_DEVICE_FIRMWARE_MISSING),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("NmPluginMissing",
                                                           "b",
                                                           NM_DEVICE_NM_PLUGIN_MISSING),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("DeviceType",
                                                           "u",
                                                           NM_DEVICE_DEVICE_TYPE),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("AvailableConnections",
                                                           "ao",
                                                           NM_DEVICE_AVAILABLE_CONNECTIONS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("PhysicalPortId",
                                                           "s",
                                                           NM_DEVICE_PHYSICAL_PORT_ID),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Mtu", "u", NM_DEVICE_MTU),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Metered", "u", NM_DEVICE_METERED),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("LldpNeighbors",
                                                           "aa{sv}",
                                                           NM_DEVICE_LLDP_NEIGHBORS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Real", "b", NM_DEVICE_REAL),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Ip4Connectivity",
                                                           "u",
                                                           NM_DEVICE_IP4_CONNECTIVITY),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Ip6Connectivity",
                                                           "u",
                                                           NM_DEVICE_IP6_CONNECTIVITY),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("InterfaceFlags",
                                                           "u",
                                                           NM_DEVICE_INTERFACE_FLAGS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("HwAddress", "s", NM_DEVICE_HW_ADDRESS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Ports", "ao", NM_DEVICE_PORTS), ), ),
};

static const NMDBusInterfaceInfoExtended interface_info_device_statistics = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_STATISTICS,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READWRITABLE(
                "RefreshRateMs",
                "u",
                NM_DEVICE_STATISTICS_REFRESH_RATE_MS,
                NM_AUTH_PERMISSION_ENABLE_DISABLE_STATISTICS,
                NM_AUDIT_OP_STATISTICS),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("TxBytes",
                                                           "t",
                                                           NM_DEVICE_STATISTICS_TX_BYTES),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("RxBytes",
                                                           "t",
                                                           NM_DEVICE_STATISTICS_RX_BYTES), ), ),
};

static void
nm_device_class_init(NMDeviceClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);

    g_type_class_add_private(object_class, sizeof(NMDevicePrivate));

    dbus_object_class->export_path = NM_DBUS_EXPORT_PATH_NUMBERED(NM_DBUS_PATH "/Devices");
    dbus_object_class->interface_infos =
        NM_DBUS_INTERFACE_INFOS(&interface_info_device, &interface_info_device_statistics);

    object_class->dispose      = dispose;
    object_class->finalize     = finalize;
    object_class->set_property = set_property;
    object_class->get_property = get_property;
    object_class->constructor  = constructor;
    object_class->constructed  = constructed;

    klass->link_changed = link_changed;

    klass->is_available       = is_available;
    klass->act_stage2_config  = act_stage2_config;
    klass->get_ip_method_auto = get_ip_method_auto;

    klass->get_type_description          = get_type_description;
    klass->can_auto_connect              = can_auto_connect;
    klass->can_update_from_platform_link = can_update_from_platform_link;
    klass->check_connection_compatible   = check_connection_compatible;
    klass->check_connection_available    = check_connection_available;
    klass->can_unmanaged_external_down   = can_unmanaged_external_down;
    klass->realize_start_notify          = realize_start_notify;
    klass->unrealize_notify              = unrealize_notify;
    klass->carrier_changed_notify        = carrier_changed_notify;
    klass->get_ip_iface_identifier       = get_ip_iface_identifier;
    klass->unmanaged_on_quit             = unmanaged_on_quit;
    klass->deactivate_reset_hw_addr      = deactivate_reset_hw_addr;
    klass->parent_changed_notify         = parent_changed_notify;
    klass->can_reapply_change            = can_reapply_change;
    klass->reapply_connection            = reapply_connection;
    klass->set_platform_mtu              = set_platform_mtu;

    klass->rfkill_type = NM_RFKILL_TYPE_UNKNOWN;

    obj_properties[PROP_UDI] =
        g_param_spec_string(NM_DEVICE_UDI,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_PATH] = g_param_spec_string(NM_DEVICE_PATH,
                                                    "",
                                                    "",
                                                    NULL,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_IFACE] =
        g_param_spec_string(NM_DEVICE_IFACE,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_IP_IFACE] = g_param_spec_string(NM_DEVICE_IP_IFACE,
                                                        "",
                                                        "",
                                                        NULL,
                                                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_DRIVER] =
        g_param_spec_string(NM_DEVICE_DRIVER,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_DRIVER_VERSION] =
        g_param_spec_string(NM_DEVICE_DRIVER_VERSION,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_FIRMWARE_VERSION] =
        g_param_spec_string(NM_DEVICE_FIRMWARE_VERSION,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_CAPABILITIES] =
        g_param_spec_uint(NM_DEVICE_CAPABILITIES,
                          "",
                          "",
                          0,
                          G_MAXUINT32,
                          NM_DEVICE_CAP_NONE,
                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_CARRIER] = g_param_spec_boolean(NM_DEVICE_CARRIER,
                                                        "",
                                                        "",
                                                        FALSE,
                                                        G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_MTU]     = g_param_spec_uint(NM_DEVICE_MTU,
                                                 "",
                                                 "",
                                                 0,
                                                 G_MAXUINT32,
                                                 1500,
                                                 G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_IP4_ADDRESS] =
        g_param_spec_variant(NM_DEVICE_IP4_ADDRESS,
                             "",
                             "",
                             G_VARIANT_TYPE_UINT32,
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_IP4_CONFIG] =
        g_param_spec_string(NM_DEVICE_IP4_CONFIG,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_DHCP4_CONFIG] =
        g_param_spec_string(NM_DEVICE_DHCP4_CONFIG,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_IP6_CONFIG] =
        g_param_spec_string(NM_DEVICE_IP6_CONFIG,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_DHCP6_CONFIG] =
        g_param_spec_string(NM_DEVICE_DHCP6_CONFIG,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_STATE] = g_param_spec_uint(NM_DEVICE_STATE,
                                                   "",
                                                   "",
                                                   0,
                                                   G_MAXUINT32,
                                                   NM_DEVICE_STATE_UNKNOWN,
                                                   G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_STATE_REASON] =
        g_param_spec_variant(NM_DEVICE_STATE_REASON,
                             "",
                             "",
                             G_VARIANT_TYPE("(uu)"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_ACTIVE_CONNECTION] =
        g_param_spec_string(NM_DEVICE_ACTIVE_CONNECTION,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_DEVICE_TYPE] =
        g_param_spec_uint(NM_DEVICE_DEVICE_TYPE,
                          "",
                          "",
                          0,
                          G_MAXUINT32,
                          NM_DEVICE_TYPE_UNKNOWN,
                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_LINK_TYPE] =
        g_param_spec_uint(NM_DEVICE_LINK_TYPE,
                          "",
                          "",
                          0,
                          G_MAXUINT32,
                          NM_LINK_TYPE_NONE,
                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_MANAGED]     = g_param_spec_boolean(NM_DEVICE_MANAGED,
                                                        "",
                                                        "",
                                                        FALSE,
                                                        G_PARAM_READWRITE | /* via D-Bus */
                                                            G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_AUTOCONNECT] = g_param_spec_boolean(NM_DEVICE_AUTOCONNECT,
                                                            "",
                                                            "",
                                                            DEFAULT_AUTOCONNECT,
                                                            G_PARAM_READWRITE | /* via D-Bus */
                                                                G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_FIRMWARE_MISSING] =
        g_param_spec_boolean(NM_DEVICE_FIRMWARE_MISSING,
                             "",
                             "",
                             FALSE,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_NM_PLUGIN_MISSING] =
        g_param_spec_boolean(NM_DEVICE_NM_PLUGIN_MISSING,
                             "",
                             "",
                             FALSE,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_TYPE_DESC] =
        g_param_spec_string(NM_DEVICE_TYPE_DESC,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_IFINDEX] = g_param_spec_int(NM_DEVICE_IFINDEX,
                                                    "",
                                                    "",
                                                    0,
                                                    G_MAXINT,
                                                    0,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_AVAILABLE_CONNECTIONS] =
        g_param_spec_boxed(NM_DEVICE_AVAILABLE_CONNECTIONS,
                           "",
                           "",
                           G_TYPE_STRV,
                           G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_PHYSICAL_PORT_ID] =
        g_param_spec_string(NM_DEVICE_PHYSICAL_PORT_ID,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_MASTER] = g_param_spec_object(NM_DEVICE_MASTER,
                                                      "",
                                                      "",
                                                      NM_TYPE_DEVICE,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_PARENT] = g_param_spec_string(NM_DEVICE_PARENT,
                                                      "",
                                                      "",
                                                      NULL,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_HW_ADDRESS] =
        g_param_spec_string(NM_DEVICE_HW_ADDRESS,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_PERM_HW_ADDRESS] =
        g_param_spec_string(NM_DEVICE_PERM_HW_ADDRESS,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_HAS_PENDING_ACTION] =
        g_param_spec_boolean(NM_DEVICE_HAS_PENDING_ACTION,
                             "",
                             "",
                             FALSE,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_METERED] = g_param_spec_uint(NM_DEVICE_METERED,
                                                     "",
                                                     "",
                                                     0,
                                                     G_MAXUINT32,
                                                     NM_METERED_UNKNOWN,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_LLDP_NEIGHBORS] =
        g_param_spec_variant(NM_DEVICE_LLDP_NEIGHBORS,
                             "",
                             "",
                             G_VARIANT_TYPE("aa{sv}"),
                             NULL,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_REAL]   = g_param_spec_boolean(NM_DEVICE_REAL,
                                                     "",
                                                     "",
                                                     FALSE,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_SLAVES] = g_param_spec_variant(NM_DEVICE_SLAVES,
                                                       "",
                                                       "",
                                                       G_VARIANT_TYPE("ao"),
                                                       NULL,
                                                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_PORTS]  = g_param_spec_variant(NM_DEVICE_PORTS,
                                                      "",
                                                      "",
                                                      G_VARIANT_TYPE("ao"),
                                                      NULL,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_STATISTICS_REFRESH_RATE_MS] =
        g_param_spec_uint(NM_DEVICE_STATISTICS_REFRESH_RATE_MS,
                          "",
                          "",
                          0,
                          UINT32_MAX,
                          0,
                          G_PARAM_READWRITE | /* via D-Bus */
                              G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_STATISTICS_TX_BYTES] =
        g_param_spec_uint64(NM_DEVICE_STATISTICS_TX_BYTES,
                            "",
                            "",
                            0,
                            UINT64_MAX,
                            0,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_STATISTICS_RX_BYTES] =
        g_param_spec_uint64(NM_DEVICE_STATISTICS_RX_BYTES,
                            "",
                            "",
                            0,
                            UINT64_MAX,
                            0,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_IP4_CONNECTIVITY] =
        g_param_spec_uint(NM_DEVICE_IP4_CONNECTIVITY,
                          "",
                          "",
                          NM_CONNECTIVITY_UNKNOWN,
                          NM_CONNECTIVITY_FULL,
                          NM_CONNECTIVITY_UNKNOWN,
                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_IP6_CONNECTIVITY] =
        g_param_spec_uint(NM_DEVICE_IP6_CONNECTIVITY,
                          "",
                          "",
                          NM_CONNECTIVITY_UNKNOWN,
                          NM_CONNECTIVITY_FULL,
                          NM_CONNECTIVITY_UNKNOWN,
                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    obj_properties[PROP_INTERFACE_FLAGS] =
        g_param_spec_uint(NM_DEVICE_INTERFACE_FLAGS,
                          "",
                          "",
                          0,
                          G_MAXUINT32,
                          0,
                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    signals[STATE_CHANGED] = g_signal_new(NM_DEVICE_STATE_CHANGED,
                                          G_OBJECT_CLASS_TYPE(object_class),
                                          G_SIGNAL_RUN_LAST,
                                          G_STRUCT_OFFSET(NMDeviceClass, state_changed),
                                          NULL,
                                          NULL,
                                          NULL,
                                          G_TYPE_NONE,
                                          3,
                                          G_TYPE_UINT,
                                          G_TYPE_UINT,
                                          G_TYPE_UINT);

    signals[AUTOCONNECT_ALLOWED] = g_signal_new(NM_DEVICE_AUTOCONNECT_ALLOWED,
                                                G_OBJECT_CLASS_TYPE(object_class),
                                                G_SIGNAL_RUN_LAST,
                                                0,
                                                autoconnect_allowed_accumulator,
                                                NULL,
                                                NULL,
                                                G_TYPE_BOOLEAN,
                                                0);

    signals[L3CD_CHANGED] = g_signal_new(NM_DEVICE_L3CD_CHANGED,
                                         G_OBJECT_CLASS_TYPE(object_class),
                                         G_SIGNAL_RUN_FIRST,
                                         0,
                                         NULL,
                                         NULL,
                                         NULL,
                                         G_TYPE_NONE,
                                         2,
                                         G_TYPE_POINTER, /* (const NML3ConfigData *l3cd_old) */
                                         G_TYPE_POINTER /* (const NML3ConfigData *l3cd_new) */);

    signals[IP6_PREFIX_DELEGATED] =
        g_signal_new(NM_DEVICE_IP6_PREFIX_DELEGATED,
                     G_OBJECT_CLASS_TYPE(object_class),
                     G_SIGNAL_RUN_FIRST,
                     0,
                     NULL,
                     NULL,
                     NULL,
                     G_TYPE_NONE,
                     1,
                     G_TYPE_POINTER /* const NMPlatformIP6Address *prefix */);

    signals[IP6_SUBNET_NEEDED] = g_signal_new(NM_DEVICE_IP6_SUBNET_NEEDED,
                                              G_OBJECT_CLASS_TYPE(object_class),
                                              G_SIGNAL_RUN_FIRST,
                                              0,
                                              NULL,
                                              NULL,
                                              NULL,
                                              G_TYPE_NONE,
                                              0);

    signals[REMOVED] = g_signal_new(NM_DEVICE_REMOVED,
                                    G_OBJECT_CLASS_TYPE(object_class),
                                    G_SIGNAL_RUN_FIRST,
                                    0,
                                    NULL,
                                    NULL,
                                    NULL,
                                    G_TYPE_NONE,
                                    0);

    signals[RECHECK_ASSUME] = g_signal_new(NM_DEVICE_RECHECK_ASSUME,
                                           G_OBJECT_CLASS_TYPE(object_class),
                                           G_SIGNAL_RUN_FIRST,
                                           0,
                                           NULL,
                                           NULL,
                                           NULL,
                                           G_TYPE_NONE,
                                           0);

    signals[DNS_LOOKUP_DONE] = g_signal_new(NM_DEVICE_DNS_LOOKUP_DONE,
                                            G_OBJECT_CLASS_TYPE(object_class),
                                            G_SIGNAL_RUN_FIRST,
                                            0,
                                            NULL,
                                            NULL,
                                            NULL,
                                            G_TYPE_NONE,
                                            0);

    signals[PLATFORM_ADDRESS_CHANGED] = g_signal_new(NM_DEVICE_PLATFORM_ADDRESS_CHANGED,
                                                     G_OBJECT_CLASS_TYPE(object_class),
                                                     G_SIGNAL_RUN_FIRST,
                                                     0,
                                                     NULL,
                                                     NULL,
                                                     NULL,
                                                     G_TYPE_NONE,
                                                     0);
}

/* Connection defaults from plugins */
NM_CON_DEFAULT_NOP("cdma.mtu");
NM_CON_DEFAULT_NOP("gsm.mtu");
NM_CON_DEFAULT_NOP("wifi.ap-isolation");
NM_CON_DEFAULT_NOP("wifi.powersave");
NM_CON_DEFAULT_NOP("wifi.wake-on-wlan");
NM_CON_DEFAULT_NOP("wifi-sec.pmf");
NM_CON_DEFAULT_NOP("wifi-sec.fils");
