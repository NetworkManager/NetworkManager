#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <arpa/inet.h>

#include "nm-default.h"
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
            _nm_log (__level, __domain, 0, \
                     "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     _NMLOG_PREFIX_NAME _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*********************************************************************************************/

typedef struct {
	int handler_id;
	const char *name;
	NMPlatformSignalChangeType change_type;
	gint received_count;
	GMainLoop *loop;
	int ifindex;
	const char *ifname;
} SignalData;

gboolean nmtstp_is_root_test (void);
gboolean nmtstp_is_sysfs_writable (void);

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

gboolean ip4_route_exists (const char *ifname, guint32 network, int plen, guint32 metric);

void _assert_ip4_route_exists (const char *file, guint line, const char *func, gboolean exists, const char *ifname, guint32 network, int plen, guint32 metric);
#define assert_ip4_route_exists(exists, ifname, network, plen, metric) _assert_ip4_route_exists (__FILE__, __LINE__, G_STRFUNC, exists, ifname, network, plen, metric)

void link_callback (NMPlatform *platform, NMPObjectType obj_type, int ifindex, NMPlatformLink *received, NMPlatformSignalChangeType change_type, NMPlatformReason reason, SignalData *data);

int nmtstp_run_command (const char *format, ...) __attribute__((__format__ (__printf__, 1, 2)));
#define nmtstp_run_command_check(format, ...) do { g_assert_cmpint (nmtstp_run_command (format, __VA_ARGS__), ==, 0); } while (0)

gboolean nmtstp_wait_for_signal (guint timeout_ms);
gboolean nmtstp_wait_for_signal_until (gint64 until_ms);

int nmtstp_run_command_check_external_global (void);
gboolean nmtstp_run_command_check_external (int external_command);

gboolean nmtstp_ip_address_check_lifetime (const NMPlatformIPAddress *addr,
                                           gint64 now,
                                           guint32 expected_lifetime,
                                           guint32 expected_preferred);
void nmtstp_ip_address_assert_lifetime (const NMPlatformIPAddress *addr,
                                        gint64 now,
                                        guint32 expected_lifetime,
                                        guint32 expected_preferred);
void nmtstp_ip4_address_add (gboolean external_command,
                             int ifindex,
                             in_addr_t address,
                             int plen,
                             in_addr_t peer_address,
                             guint32 lifetime,
                             guint32 preferred,
                             const char *label);
void nmtstp_ip6_address_add (gboolean external_command,
                             int ifindex,
                             struct in6_addr address,
                             int plen,
                             struct in6_addr peer_address,
                             guint32 lifetime,
                             guint32 preferred,
                             guint flags);
void nmtstp_ip4_address_del (gboolean external_command,
                             int ifindex,
                             in_addr_t address,
                             int plen,
                             in_addr_t peer_address);
void nmtstp_ip6_address_del (gboolean external_command,
                             int ifindex,
                             struct in6_addr address,
                             int plen);


void init_tests (int *argc, char ***argv);
void setup_tests (void);

