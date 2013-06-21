#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <arpa/inet.h>

#include "nm-logging.h"
#include "nm-platform.h"
#include "nm-fake-platform.h"
#include "nm-linux-platform.h"

#define error(err) g_assert (nm_platform_get_error () == err)
#define no_error() error (NM_PLATFORM_ERROR_NONE)

typedef struct {
	int handler_id;
	const char *name;
	gboolean received;
	GMainLoop *loop;
	int ifindex;
	const char *ifname;
} SignalData;

SignalData *add_signal_full (const char *name, GCallback callback, int ifindex, const char *ifname);
#define add_signal(name, callback) add_signal_full (name, (GCallback) callback, 0, NULL)
#define add_signal_ifname(name, callback, ifname) add_signal_full (name, (GCallback) callback, 0, ifname)
void accept_signal (SignalData *data);
void wait_signal (SignalData *data);
void free_signal (SignalData *data);

void run_command (const char *format, ...);

void setup_tests (void);

