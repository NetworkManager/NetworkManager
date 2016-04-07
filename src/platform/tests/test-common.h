#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <arpa/inet.h>

#include "nm-platform.h"
#include "nm-fake-platform.h"
#include "nm-linux-platform.h"

#include "nm-test-utils.h"

#define DEVICE_NAME "nm-test-device"

/*********************************************************************************************/

#define _NMLOG_PREFIX_NAME                "platform-test"
#define _NMLOG_DOMAIN                     LOGD_PLATFORM
#define _NMLOG(level, ...)                _LOG(level, _NMLOG_DOMAIN, __VA_ARGS__)

#define _LOG(level, domain, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        const NMLogDomain __domain = (domain); \
        \
        if (nm_logging_enabled (__level, __domain)) { \
            gint64 _ts = nm_utils_get_monotonic_timestamp_ns (); \
            \
            _nm_log (__level, __domain, 0, \
                     "%s[%ld.%09ld]: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     _NMLOG_PREFIX_NAME, \
                     (long) (_ts / NM_UTILS_NS_PER_SECOND), \
                     (long) (_ts % NM_UTILS_NS_PER_SECOND) \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*********************************************************************************************/

gboolean nmtstp_is_root_test (void);
gboolean nmtstp_is_sysfs_writable (void);

/******************************************************************************/

typedef struct _NMTstpNamespaceHandle NMTstpNamespaceHandle;

NMTstpNamespaceHandle *nmtstp_namespace_create (int flags, GError **error);

void nmtstp_namespace_handle_release (NMTstpNamespaceHandle *handle);
pid_t nmtstp_namespace_handle_get_pid (NMTstpNamespaceHandle *handle);

int nmtstp_namespace_get_fd_for_process (pid_t pid, const char *ns_name);

/******************************************************************************/

typedef struct {
	gulong handler_id;
	const char *name;
	NMPlatformSignalChangeType change_type;
	gint received_count;
	GMainLoop *loop;
	int ifindex;
	const char *ifname;
} SignalData;

SignalData *add_signal_full (const char *name, NMPlatformSignalChangeType change_type, GCallback callback, int ifindex, const char *ifname);
#define add_signal(name, change_type, callback) add_signal_full (name, change_type, (GCallback) callback, 0, NULL)
#define add_signal_ifindex(name, change_type, callback, ifindex) add_signal_full (name, change_type, (GCallback) callback, ifindex, NULL)
#define add_signal_ifname(name, change_type, callback, ifname) add_signal_full (name, change_type, (GCallback) callback, 0, ifname)
void _accept_signal (const char *file, int line, const char *func, SignalData *data);
void _accept_signals (const char *file, int line, const char *func, SignalData *data, int min, int max);
void _wait_signal (const char *file, int line, const char *func, SignalData *data);
void _accept_or_wait_signal (const char *file, int line, const char *func, SignalData *data);
void _ensure_no_signal (const char *file, int line, const char *func, SignalData *data);
void _free_signal (const char *file, int line, const char *func, SignalData *data);
#define accept_signal(data) _accept_signal(__FILE__, __LINE__, G_STRFUNC, data)
#define accept_signals(data, min, max) _accept_signals(__FILE__, __LINE__, G_STRFUNC, data, min, max)
#define wait_signal(data) _wait_signal(__FILE__, __LINE__, G_STRFUNC, data)
#define accept_or_wait_signal(data) _accept_or_wait_signal(__FILE__, __LINE__, G_STRFUNC, data)
#define ensure_no_signal(data) _ensure_no_signal(__FILE__, __LINE__, G_STRFUNC, data)
#define free_signal(data) _free_signal(__FILE__, __LINE__, G_STRFUNC, data)

void link_callback (NMPlatform *platform, NMPObjectType obj_type, int ifindex, NMPlatformLink *received, NMPlatformSignalChangeType change_type, SignalData *data);

/*****************************************************************************/

int nmtstp_run_command (const char *format, ...) __attribute__((__format__ (__printf__, 1, 2)));
#define nmtstp_run_command_check(...) do { g_assert_cmpint (nmtstp_run_command (__VA_ARGS__), ==, 0); } while (0)

/*****************************************************************************/

guint nmtstp_wait_for_signal (NMPlatform *platform, guint timeout_ms);
guint nmtstp_wait_for_signal_until (NMPlatform *platform, gint64 until_ms);
const NMPlatformLink *nmtstp_wait_for_link (NMPlatform *platform, const char *ifname, NMLinkType expected_link_type, guint timeout_ms);
const NMPlatformLink *nmtstp_wait_for_link_until (NMPlatform *platform, const char *ifname, NMLinkType expected_link_type, gint64 until_ms);

#define nmtstp_assert_wait_for_signal(platform, timeout_ms) \
	G_STMT_START { \
		if (nmtstp_wait_for_signal (platform, timeout_ms) == 0) \
			g_assert_not_reached (); \
	} G_STMT_END

#define nmtstp_assert_wait_for_signal_until(platform, until_ms) \
	G_STMT_START { \
		if (nmtstp_wait_for_signal_until (platform, until_ms) == 0) \
			g_assert_not_reached (); \
	} G_STMT_END

const NMPlatformLink *nmtstp_assert_wait_for_link (NMPlatform *platform, const char *ifname, NMLinkType expected_link_type, guint timeout_ms);
const NMPlatformLink *nmtstp_assert_wait_for_link_until (NMPlatform *platform, const char *ifname, NMLinkType expected_link_type, gint64 until_ms);

/*****************************************************************************/

int nmtstp_run_command_check_external_global (void);
gboolean nmtstp_run_command_check_external (int external_command);

/*****************************************************************************/

gboolean nmtstp_ip4_route_exists (const char *ifname, guint32 network, int plen, guint32 metric);

void _nmtstp_assert_ip4_route_exists (const char *file, guint line, const char *func, NMPlatform *platform, gboolean exists, const char *ifname, guint32 network, int plen, guint32 metric);
#define nmtstp_assert_ip4_route_exists(platform, exists, ifname, network, plen, metric) _nmtstp_assert_ip4_route_exists (__FILE__, __LINE__, G_STRFUNC, platform, exists, ifname, network, plen, metric)

/*****************************************************************************/

gboolean nmtstp_ip_address_check_lifetime (const NMPlatformIPAddress *addr,
                                           gint64 now,
                                           guint32 expected_lifetime,
                                           guint32 expected_preferred);
void nmtstp_ip_address_assert_lifetime (const NMPlatformIPAddress *addr,
                                        gint64 now,
                                        guint32 expected_lifetime,
                                        guint32 expected_preferred);

void nmtstp_ip4_address_add (NMPlatform *platform,
                             gboolean external_command,
                             int ifindex,
                             in_addr_t address,
                             int plen,
                             in_addr_t peer_address,
                             guint32 lifetime,
                             guint32 preferred,
                             guint32 flags,
                             const char *label);
void nmtstp_ip6_address_add (NMPlatform *platform,
                             gboolean external_command,
                             int ifindex,
                             struct in6_addr address,
                             int plen,
                             struct in6_addr peer_address,
                             guint32 lifetime,
                             guint32 preferred,
                             guint32 flags);
void nmtstp_ip4_address_del (NMPlatform *platform,
                             gboolean external_command,
                             int ifindex,
                             in_addr_t address,
                             int plen,
                             in_addr_t peer_address);
void nmtstp_ip6_address_del (NMPlatform *platform,
                             gboolean external_command,
                             int ifindex,
                             struct in6_addr address,
                             int plen);

/*****************************************************************************/

const NMPlatformLink *nmtstp_link_get_typed (NMPlatform *platform, int ifindex, const char *name, NMLinkType link_type);
const NMPlatformLink *nmtstp_link_get (NMPlatform *platform, int ifindex, const char *name);

void nmtstp_link_set_updown (NMPlatform *platform,
                             gboolean external_command,
                             int ifindex,
                             gboolean up);

const NMPlatformLink *nmtstp_link_dummy_add (NMPlatform *platform,
                                             gboolean external_command,
                                             const char *name);
const NMPlatformLink *nmtstp_link_gre_add (NMPlatform *platform,
                                           gboolean external_command,
                                           const char *name,
                                           const NMPlatformLnkGre *lnk);
const NMPlatformLink *nmtstp_link_ip6tnl_add (NMPlatform *platform,
                                              gboolean external_command,
                                              const char *name,
                                              const NMPlatformLnkIp6Tnl *lnk);
const NMPlatformLink *nmtstp_link_ipip_add (NMPlatform *platform,
                                            gboolean external_command,
                                            const char *name,
                                            const NMPlatformLnkIpIp *lnk);
const NMPlatformLink *nmtstp_link_macvlan_add (NMPlatform *platform,
                                               gboolean external_command,
                                               const char *name,
                                               int parent,
                                               const NMPlatformLnkMacvlan *lnk);
const NMPlatformLink *nmtstp_link_sit_add (NMPlatform *platform,
                                           gboolean external_command,
                                           const char *name,
                                           const NMPlatformLnkSit *lnk);
const NMPlatformLink *nmtstp_link_vxlan_add (NMPlatform *platform,
                                             gboolean external_command,
                                             const char *name,
                                             const NMPlatformLnkVxlan *lnk);

void nmtstp_link_del (NMPlatform *platform,
                      gboolean external_command,
                      int ifindex,
                      const char *name);

/*****************************************************************************/

void _nmtstp_init_tests (int *argc, char ***argv);
void _nmtstp_setup_tests (void);

