#include "test-common.h"

#include "nm-test-utils.h"

SignalData *
add_signal_full (const char *name, NMPlatformSignalChangeType change_type, GCallback callback, int ifindex, const char *ifname)
{
	SignalData *data = g_new0 (SignalData, 1);

	data->name = name;
	data->change_type = change_type;
	data->received = FALSE;
	data->handler_id = g_signal_connect (nm_platform_get (), name, callback, data);
	data->ifindex = ifindex;
	data->ifname = ifname;

	g_assert (data->handler_id >= 0);

	return data;
}

static const char *
_change_type_to_string (NMPlatformSignalChangeType change_type)
{
    switch (change_type) {
    case NM_PLATFORM_SIGNAL_ADDED:
        return "added";
    case NM_PLATFORM_SIGNAL_CHANGED:
        return "changed";
    case NM_PLATFORM_SIGNAL_REMOVED:
        return "removed";
    default:
        g_return_val_if_reached ("UNKNOWN");
    }
}

void
accept_signal (SignalData *data)
{
	debug ("Accepting signal '%s-%s' ifindex %d ifname %s.", data->name, _change_type_to_string (data->change_type), data->ifindex, data->ifname);
	if (!data->received)
		g_error ("Attemted to accept a non-received signal '%s-%s'.", data->name, _change_type_to_string (data->change_type));

	data->received = FALSE;
}

void
wait_signal (SignalData *data)
{
	if (data->received)
		g_error ("Signal '%s' received before waiting for it.", data->name);

	data->loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (data->loop);
	g_clear_pointer (&data->loop, g_main_loop_unref);

	accept_signal (data);
}

void
free_signal (SignalData *data)
{
	if (data->received)
		g_error ("Attempted to free received but not accepted signal '%s-%s'.", data->name, _change_type_to_string (data->change_type));

	g_signal_handler_disconnect (nm_platform_get (), data->handler_id);
	g_free (data);
}

void
link_callback (NMPlatform *platform, int ifindex, NMPlatformLink *received, NMPlatformSignalChangeType change_type, NMPlatformReason reason, SignalData *data)
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
	if (data->ifname && g_strcmp0 (data->ifname, nm_platform_link_get_name (ifindex)) != 0)
		return;
	if (change_type != data->change_type)
		return;

	if (data->loop) {
		debug ("Quitting main loop.");
		g_main_loop_quit (data->loop);
	}

	if (data->received)
		g_error ("Received signal '%s-%s' a second time.", data->name, _change_type_to_string (data->change_type));

	debug ("Received signal '%s-%s' ifindex %d ifname '%s'.", data->name, _change_type_to_string (data->change_type), ifindex, received->name);
	data->received = TRUE;

	if (change_type == NM_PLATFORM_SIGNAL_REMOVED)
		g_assert (!nm_platform_link_get_name (ifindex));
	else
		g_assert (nm_platform_link_get_name (ifindex));

	/* Check the data */
	g_assert (received->ifindex > 0);
	links = nm_platform_link_get_all ();
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

void
run_command (const char *format, ...)
{
	char *command;
	va_list ap;

	va_start (ap, format);
	command = g_strdup_vprintf (format, ap);
	va_end (ap);
	debug ("Running command: %s", command);
	g_assert (!system (command));
	debug ("Command finished.");
	g_free (command);
}

NMTST_DEFINE();

int
main (int argc, char **argv)
{
	int result;
	const char *program = *argv;

	nmtst_init_with_logging (&argc, &argv, NULL, "ALL");

	if (SETUP == nm_linux_platform_setup && getuid() != 0) {
		/* Try to exec as sudo, this function does not return, if a sudo-cmd is set. */
		nmtst_reexec_sudo ();

#ifdef REQUIRE_ROOT_TESTS
		g_message ("Fail test: requires root privileges (%s)", program);
		return EXIT_FAILURE;
#else
		g_message ("Skipping test: requires root privileges (%s)", program);
		return 77;
#endif
	}

	SETUP ();

	setup_tests ();

	result = g_test_run ();

	nm_platform_link_delete (nm_platform_link_get_ifindex (DEVICE_NAME));

	nm_platform_free ();
	return result;
}
