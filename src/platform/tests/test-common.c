#include "config.h"

#include <sys/mount.h>
#include <sched.h>

#include "test-common.h"

#include "nm-test-utils.h"

#define SIGNAL_DATA_FMT "'%s-%s' ifindex %d%s%s%s (%d times received)"
#define SIGNAL_DATA_ARG(data) (data)->name, nm_platform_signal_change_type_to_string ((data)->change_type), (data)->ifindex, (data)->ifname ? " ifname '" : "", (data)->ifname ? (data)->ifname : "", (data)->ifname ? "'" : "", (data)->received_count

gboolean
nmtstp_is_root_test (void)
{
	NM_PRAGMA_WARNING_DISABLE("-Wtautological-compare")
	return (SETUP == nm_linux_platform_setup);
	NM_PRAGMA_WARNING_REENABLE
}

gboolean
nmtstp_is_sysfs_writable (void)
{
	return    !nmtstp_is_root_test ()
	       || (access ("/sys/devices", W_OK) == 0);
}

SignalData *
add_signal_full (const char *name, NMPlatformSignalChangeType change_type, GCallback callback, int ifindex, const char *ifname)
{
	SignalData *data = g_new0 (SignalData, 1);

	data->name = name;
	data->change_type = change_type;
	data->received_count = 0;
	data->handler_id = g_signal_connect (nm_platform_get (), name, callback, data);
	data->ifindex = ifindex;
	data->ifname = ifname;

	g_assert (data->handler_id >= 0);

	return data;
}

void
_accept_signal (const char *file, int line, const char *func, SignalData *data)
{
	_LOGD ("NMPlatformSignalAssert: %s:%d, %s(): Accepting signal one time: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));
	if (data->received_count != 1)
		g_error ("NMPlatformSignalAssert: %s:%d, %s(): failure to accept signal one time: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));
	data->received_count = 0;
}

void
_accept_signals (const char *file, int line, const char *func, SignalData *data, int min, int max)
{
	_LOGD ("NMPlatformSignalAssert: %s:%d, %s(): Accepting signal [%d,%d] times: "SIGNAL_DATA_FMT, file, line, func, min, max, SIGNAL_DATA_ARG (data));
	if (data->received_count < min || data->received_count > max)
		g_error ("NMPlatformSignalAssert: %s:%d, %s(): failure to accept signal [%d,%d] times: "SIGNAL_DATA_FMT, file, line, func, min, max, SIGNAL_DATA_ARG (data));
	data->received_count = 0;
}

void
_ensure_no_signal (const char *file, int line, const char *func, SignalData *data)
{
	_LOGD ("NMPlatformSignalAssert: %s:%d, %s(): Accepting signal 0 times: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));
	if (data->received_count > 0)
		g_error ("NMPlatformSignalAssert: %s:%d, %s(): failure to accept signal 0 times: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));
}

void
_accept_or_wait_signal (const char *file, int line, const char *func, SignalData *data)
{
	_LOGD ("NMPlatformSignalAssert: %s:%d, %s(): accept-or-wait signal: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));
	if (data->received_count == 0) {
		data->loop = g_main_loop_new (NULL, FALSE);
		g_main_loop_run (data->loop);
		g_clear_pointer (&data->loop, g_main_loop_unref);
	}

	_accept_signal (file, line, func, data);
}

void
_wait_signal (const char *file, int line, const char *func, SignalData *data)
{
	_LOGD ("NMPlatformSignalAssert: %s:%d, %s(): wait signal: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));
	if (data->received_count)
		g_error ("NMPlatformSignalAssert: %s:%d, %s(): failure to wait for signal: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));

	data->loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (data->loop);
	g_clear_pointer (&data->loop, g_main_loop_unref);

	_accept_signal (file, line, func, data);
}

void
_free_signal (const char *file, int line, const char *func, SignalData *data)
{
	_LOGD ("NMPlatformSignalAssert: %s:%d, %s(): free signal: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));
	if (data->received_count != 0)
		g_error ("NMPlatformSignalAssert: %s:%d, %s(): failure to free non-accepted signal: "SIGNAL_DATA_FMT, file, line, func, SIGNAL_DATA_ARG (data));

	g_signal_handler_disconnect (nm_platform_get (), data->handler_id);
	g_free (data);
}

void
link_callback (NMPlatform *platform, NMPObjectType obj_type, int ifindex, NMPlatformLink *received, NMPlatformSignalChangeType change_type, NMPlatformReason reason, SignalData *data)
{
	GArray *links;
	NMPlatformLink *cached;
	int i;

	g_assert (received);
	g_assert_cmpint (received->ifindex, ==, ifindex);
	g_assert (data && data->name);
	g_assert_cmpstr (data->name, ==, NM_PLATFORM_SIGNAL_LINK_CHANGED);

	if (data->ifindex && data->ifindex != received->ifindex)
		return;
	if (data->ifname && g_strcmp0 (data->ifname, nm_platform_link_get_name (NM_PLATFORM_GET, ifindex)) != 0)
		return;
	if (change_type != data->change_type)
		return;

	if (data->loop) {
		_LOGD ("Quitting main loop.");
		g_main_loop_quit (data->loop);
	}

	data->received_count++;
	_LOGD ("Received signal '%s-%s' ifindex %d ifname '%s' %dth time.", data->name, nm_platform_signal_change_type_to_string (data->change_type), ifindex, received->name, data->received_count);

	if (change_type == NM_PLATFORM_SIGNAL_REMOVED)
		g_assert (!nm_platform_link_get_name (NM_PLATFORM_GET, ifindex));
	else
		g_assert (nm_platform_link_get_name (NM_PLATFORM_GET, ifindex));

	/* Check the data */
	g_assert (received->ifindex > 0);
	links = nm_platform_link_get_all (NM_PLATFORM_GET);
	for (i = 0; i < links->len; i++) {
		cached = &g_array_index (links, NMPlatformLink, i);
		if (cached->ifindex == received->ifindex) {
			g_assert_cmpint (nm_platform_link_cmp (cached, received), ==, 0);
			g_assert (!memcmp (cached, received, sizeof (*cached)));
			if (data->change_type == NM_PLATFORM_SIGNAL_REMOVED)
				g_error ("Deleted link still found in the local cache.");
			g_array_unref (links);
			return;
		}
	}
	g_array_unref (links);

	if (data->change_type != NM_PLATFORM_SIGNAL_REMOVED)
		g_error ("Added/changed link not found in the local cache.");
}

gboolean
ip4_route_exists (const char *ifname, guint32 network, int plen, guint32 metric)
{
	gs_free char *arg_network = NULL;
	const char *argv[] = {
		NULL,
		"route",
		"list",
		"dev",
		ifname,
		"exact",
		NULL,
		NULL,
	};
	int exit_status;
	gs_free char *std_out = NULL, *std_err = NULL;
	char *out;
	gboolean success;
	gs_free_error GError *error = NULL;
	gs_free char *metric_pattern = NULL;

	g_assert (ifname && nm_utils_iface_valid_name (ifname));
	g_assert (!strstr (ifname, " metric "));
	g_assert (plen >= 0 && plen <= 32);

	if (!NM_IS_LINUX_PLATFORM (nm_platform_get ())) {
		/* If we don't test against linux-platform, we don't actually configure any
		 * routes in the system. */
		return -1;
	}

	argv[0] = nm_utils_file_search_in_paths ("ip", NULL,
	                                         (const char *[]) { "/sbin", "/usr/sbin", NULL },
	                                         G_FILE_TEST_IS_EXECUTABLE, NULL, NULL, NULL);
	argv[6] = arg_network = g_strdup_printf ("%s/%d", nm_utils_inet4_ntop (network, NULL), plen);

	if (!argv[0]) {
		/* Hm. There is no 'ip' binary. Return *unknown* */
		return -1;
	}

	success = g_spawn_sync (NULL,
	                        (char **) argv,
	                        (char *[]) { NULL },
	                        0,
	                        NULL,
	                        NULL,
	                        &std_out,
	                        &std_err,
	                        &exit_status,
	                        &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert_cmpstr (std_err, ==, "");
	g_assert (std_out);

	metric_pattern = g_strdup_printf (" metric %u", metric);
	out = std_out;
	while (out) {
		char *eol = strchr (out, '\n');
		gs_free char *line = eol ? g_strndup (out, eol - out) : g_strdup (out);
		const char *p;

		out = eol ? &eol[1] : NULL;
		if (!line[0])
			continue;

		if (metric == 0) {
			if (!strstr (line, " metric "))
				return TRUE;
		}
		p = strstr (line, metric_pattern);
		if (p && NM_IN_SET (p[strlen (metric_pattern)], ' ', '\0'))
			return TRUE;
	}
	return FALSE;
}

void
_assert_ip4_route_exists (const char *file, guint line, const char *func, gboolean exists, const char *ifname, guint32 network, int plen, guint32 metric)
{
	int ifindex;
	gboolean exists_checked;

	/* Check for existance of the route by spawning iproute2. Do this because platform
	 * code might be entirely borked, but we expect ip-route to give a correct result.
	 * If the ip command cannot be found, we accept this as success. */
	exists_checked = ip4_route_exists (ifname, network, plen, metric);
	if (exists_checked != -1 && !exists_checked != !exists) {
		g_error ("[%s:%u] %s(): We expect the ip4 route %s/%d metric %u %s, but it %s",
		         file, line, func,
		         nm_utils_inet4_ntop (network, NULL), plen, metric,
		         exists ? "to exist" : "not to exist",
		         exists ? "doesn't" : "does");
	}

	ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, ifname);
	g_assert (ifindex > 0);
	if (!nm_platform_ip4_route_get (NM_PLATFORM_GET, ifindex, network, plen, metric) != !exists) {
		g_error ("[%s:%u] %s(): The ip4 route %s/%d metric %u %s, but platform thinks %s",
		         file, line, func,
		         nm_utils_inet4_ntop (network, NULL), plen, metric,
		         exists ? "exists" : "does not exist",
		         exists ? "it doesn't" : "it does");
	}
}

int
nmtstp_run_command (const char *format, ...)
{
	int result;
	gs_free char *command = NULL;
	va_list ap;

	va_start (ap, format);
	command = g_strdup_vprintf (format, ap);
	va_end (ap);

	_LOGD ("Running command: %s", command);
	result = system (command);
	_LOGD ("Command finished: result=%d", result);

	return result;
}

/*****************************************************************************/

typedef struct {
	GMainLoop *loop;
	gboolean timeout;
	guint id;
} WaitForSignalData;

static void
_wait_for_signal_cb (NMPlatform *platform,
                     NMPObjectType obj_type,
                     int ifindex,
                     NMPlatformLink *plink,
                     NMPlatformSignalChangeType change_type,
                     NMPlatformReason reason,
                     gpointer user_data)
{
	WaitForSignalData *data = user_data;

	g_main_loop_quit (data->loop);
}

static gboolean
_wait_for_signal_timeout (gpointer user_data)
{
	WaitForSignalData *data = user_data;

	data->timeout = TRUE;
	data->id = 0;
	g_main_loop_quit (data->loop);
	return G_SOURCE_REMOVE;
}

gboolean
nmtstp_wait_for_signal (guint timeout_ms)
{
	WaitForSignalData data = { 0 };

	guint id_link, id_ip4_address, id_ip6_address, id_ip4_route, id_ip6_route;

	data.loop = g_main_loop_new (NULL, FALSE);

	id_link        = g_signal_connect (NM_PLATFORM_GET, NM_PLATFORM_SIGNAL_LINK_CHANGED, G_CALLBACK (_wait_for_signal_cb), &data);
	id_ip4_address = g_signal_connect (NM_PLATFORM_GET, NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED, G_CALLBACK (_wait_for_signal_cb), &data);
	id_ip6_address = g_signal_connect (NM_PLATFORM_GET, NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED, G_CALLBACK (_wait_for_signal_cb), &data);
	id_ip4_route   = g_signal_connect (NM_PLATFORM_GET, NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED, G_CALLBACK (_wait_for_signal_cb), &data);
	id_ip6_route   = g_signal_connect (NM_PLATFORM_GET, NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED, G_CALLBACK (_wait_for_signal_cb), &data);

	if (timeout_ms != 0)
		data.id = g_timeout_add (timeout_ms, _wait_for_signal_timeout, &data);

	g_main_loop_run (data.loop);

	g_assert (nm_clear_g_signal_handler (NM_PLATFORM_GET, &id_link));
	g_assert (nm_clear_g_signal_handler (NM_PLATFORM_GET, &id_ip4_address));
	g_assert (nm_clear_g_signal_handler (NM_PLATFORM_GET, &id_ip6_address));
	g_assert (nm_clear_g_signal_handler (NM_PLATFORM_GET, &id_ip4_route));
	g_assert (nm_clear_g_signal_handler (NM_PLATFORM_GET, &id_ip6_route));

	if (nm_clear_g_source (&data.id))
		g_assert (timeout_ms != 0 && !data.timeout);

	g_clear_pointer (&data.loop, g_main_loop_unref);

	return !data.timeout;
}

gboolean
nmtstp_wait_for_signal_until (gint64 until_ms)
{
	gint64 now;

	while (TRUE) {
		now = nm_utils_get_monotonic_timestamp_ms ();

		if (until_ms < now)
			return FALSE;

		if (nmtstp_wait_for_signal (MAX (1, until_ms - now)))
			return TRUE;
	}
}

int
nmtstp_run_command_check_external_global (void)
{
	if (!nmtstp_is_root_test ())
		return FALSE;
	switch (nmtst_get_rand_int () % 3) {
	case 0:
		return -1;
	case 1:
		return FALSE;
	default:
		return TRUE;
	}
}

gboolean
nmtstp_run_command_check_external (int external_command)
{
	if (external_command != -1) {
		g_assert (NM_IN_SET (external_command, FALSE, TRUE));
		g_assert (!external_command || nmtstp_is_root_test ());
		return !!external_command;
	}
	if (!nmtstp_is_root_test ())
		return FALSE;
	return (nmtst_get_rand_int () % 2) == 0;
}

#define CHECK_LIFETIME_MAX_DIFF    2

gboolean
nmtstp_ip_address_check_lifetime (const NMPlatformIPAddress *addr,
                                  gint64 now,
                                  guint32 expected_lifetime,
                                  guint32 expected_preferred)
{
	gint64 offset;
	int i;

	g_assert (addr);

	if (now == -1)
		now = nm_utils_get_monotonic_timestamp_s ();
	g_assert (now > 0);

	g_assert (expected_preferred <= expected_lifetime);

	if (   expected_lifetime == NM_PLATFORM_LIFETIME_PERMANENT
	    && expected_lifetime == NM_PLATFORM_LIFETIME_PERMANENT) {
		return    addr->timestamp == 0
		       && addr->lifetime == NM_PLATFORM_LIFETIME_PERMANENT
		       && addr->preferred == NM_PLATFORM_LIFETIME_PERMANENT;
	}

	if (addr->timestamp == 0)
		return FALSE;

	offset = (gint64) now - addr->timestamp;

	for (i = 0; i < 2; i++) {
		guint32 lft = i ? expected_lifetime : expected_preferred;
		guint32 adr = i ? addr->lifetime : addr->preferred;

		if (lft == NM_PLATFORM_LIFETIME_PERMANENT) {
			if (adr != NM_PLATFORM_LIFETIME_PERMANENT)
				return FALSE;
		} else {
			if (   adr - offset <= lft - CHECK_LIFETIME_MAX_DIFF
			    || adr - offset >= lft + CHECK_LIFETIME_MAX_DIFF)
				return FALSE;
		}
	}
	return TRUE;
}

void
nmtstp_ip_address_assert_lifetime (const NMPlatformIPAddress *addr,
                                   gint64 now,
                                   guint32 expected_lifetime,
                                   guint32 expected_preferred)
{
	gint64 n = now;
	gint64 offset;
	int i;

	g_assert (addr);

	if (now == -1)
		now = nm_utils_get_monotonic_timestamp_s ();
	g_assert (now > 0);

	g_assert (expected_preferred <= expected_lifetime);

	if (   expected_lifetime == NM_PLATFORM_LIFETIME_PERMANENT
	    && expected_lifetime == NM_PLATFORM_LIFETIME_PERMANENT) {
		g_assert_cmpint (addr->timestamp, ==, 0);
		g_assert_cmpint (addr->lifetime, ==, NM_PLATFORM_LIFETIME_PERMANENT);
		g_assert_cmpint (addr->preferred, ==, NM_PLATFORM_LIFETIME_PERMANENT);
		return;
	}

	g_assert_cmpint (addr->timestamp, >, 0);
	g_assert_cmpint (addr->timestamp, <=, now);

	offset = (gint64) now - addr->timestamp;
	g_assert_cmpint (offset, >=, 0);

	for (i = 0; i < 2; i++) {
		guint32 lft = i ? expected_lifetime : expected_preferred;
		guint32 adr = i ? addr->lifetime : addr->preferred;

		if (lft == NM_PLATFORM_LIFETIME_PERMANENT)
			g_assert_cmpint (adr, ==, NM_PLATFORM_LIFETIME_PERMANENT);
		else {
			g_assert_cmpint (adr, <=, lft);
			g_assert_cmpint (offset, <=, adr);
			g_assert_cmpint (adr - offset, <=, lft + CHECK_LIFETIME_MAX_DIFF);
			g_assert_cmpint (adr - offset, >=, lft - CHECK_LIFETIME_MAX_DIFF);
		}
	}

	g_assert (nmtstp_ip_address_check_lifetime (addr, n, expected_lifetime, expected_preferred));
}

static void
_ip_address_add (gboolean external_command,
                 gboolean is_v4,
                 int ifindex,
                 const NMIPAddr *address,
                 int plen,
                 const NMIPAddr *peer_address,
                 guint32 lifetime,
                 guint32 preferred,
                 const char *label,
                 guint flags)
{
	gint64 end_time;

	external_command = nmtstp_run_command_check_external (external_command);

	if (external_command) {
		const char *ifname;
		gs_free char *s_valid = NULL;
		gs_free char *s_preferred = NULL;
		gs_free char *s_label = NULL;
		char b1[NM_UTILS_INET_ADDRSTRLEN], b2[NM_UTILS_INET_ADDRSTRLEN];

		ifname = nm_platform_link_get_name (NM_PLATFORM_GET, ifindex);
		g_assert (ifname);

		if (peer_address == address)
			peer_address = 0;

		if (lifetime != NM_PLATFORM_LIFETIME_PERMANENT)
			s_valid = g_strdup_printf (" valid_lft %d", lifetime);
		if (preferred != NM_PLATFORM_LIFETIME_PERMANENT)
			s_preferred = g_strdup_printf (" preferred_lft %d", preferred);
		if (label)
			s_label = g_strdup_printf ("%s:%s", ifname, label);

		if (is_v4) {
			g_assert (flags == 0);
			nmtstp_run_command_check ("ip address change %s%s%s/%d dev %s%s%s%s",
			                          nm_utils_inet4_ntop (address->addr4, b1),
			                          peer_address->addr4 ? " peer " : "",
			                          peer_address->addr4 ? nm_utils_inet4_ntop (peer_address->addr4, b2) : "",
			                          plen,
			                          ifname,
			                          s_valid ?: "",
			                          s_preferred ?: "",
			                          s_label ?: "");
		} else {
			g_assert (label == NULL);

			/* flags not implemented (yet) */
			g_assert (flags == 0);
			nmtstp_run_command_check ("ip address change %s%s%s/%d dev %s%s%s%s",
			                          nm_utils_inet6_ntop (&address->addr6, b1),
			                          !IN6_IS_ADDR_UNSPECIFIED (&peer_address->addr6) ? " peer " : "",
			                          !IN6_IS_ADDR_UNSPECIFIED (&peer_address->addr6) ? nm_utils_inet6_ntop (&peer_address->addr6, b2) : "",
			                          plen,
			                          ifname,
			                          s_valid ?: "",
			                          s_preferred ?: "",
			                          s_label ?: "");
		}
	} else {
		gboolean success;

		if (is_v4) {
			g_assert (flags == 0);
			success = nm_platform_ip4_address_add (NM_PLATFORM_GET,
			                                       ifindex,
			                                       address->addr4,
			                                       plen,
			                                       peer_address->addr4,
			                                       lifetime,
			                                       preferred,
			                                       label);
		} else {
			g_assert (label == NULL);
			success = nm_platform_ip6_address_add (NM_PLATFORM_GET,
			                                       ifindex,
			                                       address->addr6,
			                                       plen,
			                                       peer_address->addr6,
			                                       lifetime,
			                                       preferred,
			                                       flags);
		}
		g_assert (success);
	}

	/* Let's wait until we see the address. */
	end_time = nm_utils_get_monotonic_timestamp_ms () + 250;
	do {

		if (external_command)
			nm_platform_process_events (NM_PLATFORM_GET);

		/* let's wait until we see the address as we added it. */
		if (is_v4) {
			const NMPlatformIP4Address *a;

			g_assert (flags == 0);
			a = nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, address->addr4, plen, peer_address->addr4);
			if (   a
			    && nm_platform_ip4_address_get_peer (a) == (peer_address->addr4 ? peer_address->addr4 : address->addr4)
			    && nmtstp_ip_address_check_lifetime ((NMPlatformIPAddress*) a, -1, lifetime, preferred)
			    && strcmp (a->label, label ?: "") == 0)
				break;
		} else {
			const NMPlatformIP6Address *a;

			g_assert (label == NULL);
			g_assert (flags == 0);

			a = nm_platform_ip6_address_get (NM_PLATFORM_GET, ifindex, address->addr6, plen);
			if (   a
			    && !memcmp (nm_platform_ip6_address_get_peer (a),
			                (IN6_IS_ADDR_UNSPECIFIED (&peer_address->addr6) || IN6_ARE_ADDR_EQUAL (&address->addr6, &peer_address->addr6))
			                    ? &address->addr6 : &peer_address->addr6,
			                sizeof (struct in6_addr))
			    && nmtstp_ip_address_check_lifetime ((NMPlatformIPAddress*) a, -1, lifetime, preferred))
				break;
		}

		/* for internal command, we expect not to reach this line.*/
		g_assert (external_command);

		/* timeout? */
		g_assert (nm_utils_get_monotonic_timestamp_ms () < end_time);

		g_assert (nmtstp_wait_for_signal_until (end_time));
	} while (TRUE);
}

void
nmtstp_ip4_address_add (gboolean external_command,
                        int ifindex,
                        in_addr_t address,
                        int plen,
                        in_addr_t peer_address,
                        guint32 lifetime,
                        guint32 preferred,
                        const char *label)
{
	_ip_address_add (external_command,
	                 TRUE,
	                 ifindex,
	                 (NMIPAddr *) &address,
	                 plen,
	                 (NMIPAddr *) &peer_address,
	                 lifetime,
	                 preferred,
	                 label,
	                 0);
}

void
nmtstp_ip6_address_add (gboolean external_command,
                        int ifindex,
                        struct in6_addr address,
                        int plen,
                        struct in6_addr peer_address,
                        guint32 lifetime,
                        guint32 preferred,
                        guint flags)
{
	_ip_address_add (external_command,
	                 FALSE,
	                 ifindex,
	                 (NMIPAddr *) &address,
	                 plen,
	                 (NMIPAddr *) &peer_address,
	                 lifetime,
	                 preferred,
	                 NULL,
	                 flags);
}

static void
_ip_address_del (gboolean external_command,
                 gboolean is_v4,
                 int ifindex,
                 const NMIPAddr *address,
                 int plen,
                 const NMIPAddr *peer_address)
{
	gint64 end_time;

	external_command = nmtstp_run_command_check_external (external_command);

	if (external_command) {
		const char *ifname;
		char b1[NM_UTILS_INET_ADDRSTRLEN], b2[NM_UTILS_INET_ADDRSTRLEN];
		int success;
		gboolean had_address;

		ifname = nm_platform_link_get_name (NM_PLATFORM_GET, ifindex);
		g_assert (ifname);

		if (peer_address == address)
			peer_address = 0;

		/* let's wait until we see the address as we added it. */
		if (is_v4)
			had_address = !!nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, address->addr4, plen, peer_address->addr4);
		else
			had_address = !!nm_platform_ip6_address_get (NM_PLATFORM_GET, ifindex, address->addr6, plen);

		if (is_v4) {
			success = nmtstp_run_command ("ip address delete %s%s%s/%d dev %s",
			                              nm_utils_inet4_ntop (address->addr4, b1),
			                              peer_address->addr4 ? " peer " : "",
			                              peer_address->addr4 ? nm_utils_inet4_ntop (peer_address->addr4, b2) : "",
			                              plen,
			                              ifname);
		} else {
			g_assert (!peer_address);
			success = nmtstp_run_command ("ip address delete %s/%d dev %s",
			                              nm_utils_inet6_ntop (&address->addr6, b1),
			                              plen,
			                              ifname);
		}
		g_assert (success == 0 || !had_address);
	} else {
		gboolean success;

		if (is_v4) {
			success = nm_platform_ip4_address_delete (NM_PLATFORM_GET,
			                                          ifindex,
			                                          address->addr4,
			                                          plen,
			                                          peer_address->addr4);
		} else {
			g_assert (!peer_address);
			success = nm_platform_ip6_address_delete (NM_PLATFORM_GET,
			                                          ifindex,
			                                          address->addr6,
			                                          plen);
		}
		g_assert (success);
	}

	/* Let's wait until we get the result */
	end_time = nm_utils_get_monotonic_timestamp_ms () + 250;
	do {
		if (external_command)
			nm_platform_process_events (NM_PLATFORM_GET);

		/* let's wait until we see the address as we added it. */
		if (is_v4) {
			const NMPlatformIP4Address *a;

			a = nm_platform_ip4_address_get (NM_PLATFORM_GET, ifindex, address->addr4, plen, peer_address->addr4);
			if (!a)
				break;
		} else {
			const NMPlatformIP6Address *a;

			a = nm_platform_ip6_address_get (NM_PLATFORM_GET, ifindex, address->addr6, plen);
			if (!a)
				break;
		}

		/* for internal command, we expect not to reach this line.*/
		g_assert (external_command);

		/* timeout? */
		g_assert (nm_utils_get_monotonic_timestamp_ms () < end_time);

		g_assert (nmtstp_wait_for_signal_until (end_time));
	} while (TRUE);
}

void
nmtstp_ip4_address_del (gboolean external_command,
                        int ifindex,
                        in_addr_t address,
                        int plen,
                        in_addr_t peer_address)
{
	_ip_address_del (external_command,
	                 TRUE,
	                 ifindex,
	                 (NMIPAddr *) &address,
	                 plen,
	                 (NMIPAddr *) &peer_address);
}

void
nmtstp_ip6_address_del (gboolean external_command,
                        int ifindex,
                        struct in6_addr address,
                        int plen)
{
	_ip_address_del (external_command,
	                 FALSE,
	                 ifindex,
	                 (NMIPAddr *) &address,
	                 plen,
	                 NULL);
}

/*****************************************************************************/

NMTST_DEFINE();

static gboolean
unshare_user (void)
{
	FILE *f;
	uid_t uid = geteuid ();
	gid_t gid = getegid ();

	/* Already a root? */
	if (gid == 0 && uid == 0)
		return TRUE;

	/* Become a root in new user NS. */
	if (unshare (CLONE_NEWUSER) != 0)
		return FALSE;

	/* Since Linux 3.19 we have to disable setgroups() in order to map users.
	 * Just proceed if the file is not there. */
	f = fopen ("/proc/self/setgroups", "w");
	if (f) {
		fprintf (f, "deny");
		fclose (f);
	}

	/* Map current UID to root in NS to be created. */
	f = fopen ("/proc/self/uid_map", "w");
	if (!f)
		return FALSE;
	fprintf (f, "0 %d 1", uid);
	fclose (f);

	/* Map current GID to root in NS to be created. */
	f = fopen ("/proc/self/gid_map", "w");
	if (!f)
		return FALSE;
	fprintf (f, "0 %d 1", gid);
	fclose (f);

	return TRUE;
}

int
main (int argc, char **argv)
{
	int result;
	const char *program = *argv;

	init_tests (&argc, &argv);

	if (   nmtstp_is_root_test ()
	    && (geteuid () != 0 || getegid () != 0)) {
		if (   g_getenv ("NMTST_FORCE_REAL_ROOT")
		    || !unshare_user ()) {
			/* Try to exec as sudo, this function does not return, if a sudo-cmd is set. */
			nmtst_reexec_sudo ();

#ifdef REQUIRE_ROOT_TESTS
			g_print ("Fail test: requires root privileges (%s)\n", program);
			return EXIT_FAILURE;
#else
			g_print ("Skipping test: requires root privileges (%s)\n", program);
			return g_test_run ();
#endif
		}
	}

	if (nmtstp_is_root_test () && !g_getenv ("NMTST_NO_UNSHARE")) {
		int errsv;

		if (unshare (CLONE_NEWNET | CLONE_NEWNS) != 0) {
			errsv = errno;
			g_error ("unshare(CLONE_NEWNET|CLONE_NEWNS) failed with %s (%d)", strerror (errsv), errsv);
		}

		/* Mount our /sys instance, so that gudev sees only our devices.
		 * Needs to be read-only, because we don't run udev. */
		mount (NULL, "/sys", "sysfs", MS_SLAVE, NULL);
		if (mount ("sys", "/sys", "sysfs", MS_RDONLY, NULL) != 0) {
			errsv = errno;
			g_error ("mount(\"/sys\") failed with %s (%d)", strerror (errsv), errsv);
		}

		/* Create a writable /sys/devices tree. This makes it possible to run tests
		 * that modify values via sysfs (such as bridge forward delay). */
		if (mount ("sys", "/sys/devices", "sysfs", 0, NULL) != 0) {
			errsv = errno;
			g_error ("mount(\"/sys/devices\") failed with %s (%d)", strerror (errsv), errsv);
		}
		if (mount (NULL, "/sys/devices", "sysfs", MS_REMOUNT, NULL) != 0) {
			/* Read-write remount failed. Never mind, we're probably just a root in
			 * our user NS. */
			if (umount ("/sys/devices") != 0) {
				errsv = errno;
				g_error ("umount(\"/sys/devices\") failed with  %s (%d)", strerror (errsv), errsv);
			}
		} else {
			if (mount ("/sys/devices/devices", "/sys/devices", "sysfs", MS_BIND, NULL) != 0) {
				errsv = errno;
				g_error ("mount(\"/sys\") failed with %s (%d)", strerror (errsv), errsv);
			}
		}
	}

	SETUP ();

	setup_tests ();

	result = g_test_run ();

	nm_platform_link_delete (NM_PLATFORM_GET, nm_platform_link_get_ifindex (NM_PLATFORM_GET, DEVICE_NAME));

	g_object_unref (nm_platform_get ());
	return result;
}
