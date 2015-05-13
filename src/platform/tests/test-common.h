#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <arpa/inet.h>

#include "nm-logging.h"
#include "nm-platform.h"
#include "nm-fake-platform.h"
#include "nm-linux-platform.h"

#include "nm-test-utils.h"

#define DEVICE_NAME "nm-test-device"

#define debug(...) nm_log_dbg (LOGD_PLATFORM, __VA_ARGS__)

#define error(err) g_assert (nm_platform_get_error (NM_PLATFORM_GET) == err)
#define no_error() error (NM_PLATFORM_ERROR_NONE)

typedef struct {
	int handler_id;
	const char *name;
	NMPlatformSignalChangeType change_type;
	gint received_count;
	GMainLoop *loop;
	int ifindex;
	const char *ifname;
} SignalData;

gboolean nmtst_platform_is_root_test (void);

SignalData *add_signal_full (const char *name, NMPlatformSignalChangeType change_type, GCallback callback, int ifindex, const char *ifname);
#define add_signal(name, change_type, callback) add_signal_full (name, change_type, (GCallback) callback, 0, NULL)
#define add_signal_ifindex(name, change_type, callback, ifindex) add_signal_full (name, change_type, (GCallback) callback, ifindex, NULL)
#define add_signal_ifname(name, change_type, callback, ifname) add_signal_full (name, change_type, (GCallback) callback, 0, ifname)
void _accept_signal (const char *file, int line, const char *func, SignalData *data);
void _accept_signals (const char *file, int line, const char *func, SignalData *data, int min, int max);
void _wait_signal (const char *file, int line, const char *func, SignalData *data);
void _ensure_no_signal (const char *file, int line, const char *func, SignalData *data);
void _free_signal (const char *file, int line, const char *func, SignalData *data);
#define accept_signal(data) _accept_signal(__FILE__, __LINE__, G_STRFUNC, data)
#define accept_signals(data, min, max) _accept_signals(__FILE__, __LINE__, G_STRFUNC, data, min, max)
#define wait_signal(data) _wait_signal(__FILE__, __LINE__, G_STRFUNC, data)
#define ensure_no_signal(data) _ensure_no_signal(__FILE__, __LINE__, G_STRFUNC, data)
#define free_signal(data) _free_signal(__FILE__, __LINE__, G_STRFUNC, data)

gboolean ip4_route_exists (const char *ifname, guint32 network, int plen, guint32 metric);

void _assert_ip4_route_exists (const char *file, guint line, const char *func, gboolean exists, const char *ifname, guint32 network, int plen, guint32 metric);
#define assert_ip4_route_exists(exists, ifname, network, plen, metric) _assert_ip4_route_exists (__FILE__, __LINE__, G_STRFUNC, exists, ifname, network, plen, metric)

void link_callback (NMPlatform *platform, int ifindex, NMPlatformLink *received, NMPlatformSignalChangeType change_type, NMPlatformReason reason, SignalData *data);

void run_command (const char *format, ...);

void init_tests (int *argc, char ***argv);
void setup_tests (void);

