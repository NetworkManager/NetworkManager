/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2014 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/ether.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "NetworkManagerUtils.h"

#include "nm-test-utils-core.h"

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif

/*****************************************************************************/

static void
test_nm_utils_monotonic_timestamp_as_boottime (void)
{
	gint64 timestamp_ns_per_tick, now, now_boottime, now_boottime_2, now_boottime_3;
	struct timespec tp;
	clockid_t clockid;
	guint i;

	if (clock_gettime (CLOCK_BOOTTIME, &tp) != 0 && errno == EINVAL)
		clockid = CLOCK_MONOTONIC;
	else
		clockid = CLOCK_BOOTTIME;

	for (i = 0; i < 10; i++) {

		if (clock_gettime (clockid, &tp) != 0)
			g_assert_not_reached ();
		now_boottime = ( ((gint64) tp.tv_sec) * NM_UTILS_NS_PER_SECOND ) + ((gint64) tp.tv_nsec);

		now = nm_utils_get_monotonic_timestamp_ns ();

		now_boottime_2 = nm_utils_monotonic_timestamp_as_boottime (now, 1);
		g_assert_cmpint (now_boottime_2, >=, 0);
		g_assert_cmpint (now_boottime_2, >=, now_boottime);
		g_assert_cmpint (now_boottime_2 - now_boottime, <=, NM_UTILS_NS_PER_SECOND / 10);

		for (timestamp_ns_per_tick = 1; timestamp_ns_per_tick <= NM_UTILS_NS_PER_SECOND; timestamp_ns_per_tick *= 10) {
			now_boottime_3 = nm_utils_monotonic_timestamp_as_boottime (now / timestamp_ns_per_tick, timestamp_ns_per_tick);

			g_assert_cmpint (now_boottime_2 / timestamp_ns_per_tick, ==, now_boottime_3);
		}
	}
}

/*****************************************************************************/

struct test_nm_utils_kill_child_async_data
{
	GMainLoop *loop;
	pid_t pid;
	gboolean called;
	gboolean expected_success;
	const int *expected_child_status;
};

static void
test_nm_utils_kill_child_async_cb (pid_t pid, gboolean success, int child_status, void *user_data)
{
	struct test_nm_utils_kill_child_async_data *data = user_data;

	g_assert (success == !!data->expected_success);
	g_assert (pid == data->pid);
	if (data->expected_child_status)
		g_assert_cmpint (*data->expected_child_status, ==, child_status);
	if (!success)
		g_assert_cmpint (child_status, ==, -1);

	data->called = TRUE;

	g_assert (data->loop);
	g_main_loop_quit (data->loop);
}

static gboolean
test_nm_utils_kill_child_async_fail_cb (void *user_data)
{
	g_assert_not_reached ();
}

static void
test_nm_utils_kill_child_async_do (const char *name, pid_t pid, int sig, guint32 wait_before_kill_msec, gboolean expected_success, const int *expected_child_status)
{
	gboolean success;
	struct test_nm_utils_kill_child_async_data data = { };
	int timeout_id;

	data.pid = pid;
	data.expected_success = expected_success;
	data.expected_child_status = expected_child_status;

	nm_utils_kill_child_async (pid, sig, LOGD_CORE, name, wait_before_kill_msec, test_nm_utils_kill_child_async_cb, &data);
	g_assert (!data.called);

	timeout_id = g_timeout_add_seconds (5, test_nm_utils_kill_child_async_fail_cb, &data);

	data.loop = g_main_loop_new (NULL, FALSE);
	g_main_run (data.loop);

	g_assert (data.called);
	success = g_source_remove (timeout_id);
	g_assert (success);

	g_main_destroy (data.loop);
}

static void
test_nm_utils_kill_child_sync_do (const char *name, pid_t pid, int sig, guint32 wait_before_kill_msec, gboolean expected_success, const int *expected_child_status)
{
	gboolean success;
	int child_status = -1;

	success = nm_utils_kill_child_sync (pid, sig, LOGD_CORE, name, &child_status, wait_before_kill_msec, 0);
	g_assert (success == !!expected_success);
	if (expected_child_status)
		g_assert_cmpint (*expected_child_status, ==, child_status);

	g_test_assert_expected_messages ();
}

static pid_t
test_nm_utils_kill_child_spawn (char **argv, gboolean do_not_reap_child)
{
	GError *error = NULL;
	int success;
	GPid child_pid;

	success = g_spawn_async (NULL,
	                         argv,
	                         NULL,
	                         G_SPAWN_SEARCH_PATH | (do_not_reap_child ? G_SPAWN_DO_NOT_REAP_CHILD : 0),
	                         NULL,
	                         NULL,
	                         &child_pid,
	                         &error);
	g_assert (success && !error);
	return child_pid;
}

static pid_t
do_test_nm_utils_kill_child_create_and_join_pgroup (void)
{
	int err, tmp = 0;
	int pipefd[2];
	pid_t pgid;

	err = pipe2 (pipefd, O_CLOEXEC);
	g_assert (err == 0);

	pgid = fork();
	g_assert (pgid >= 0);

	if (pgid == 0) {
		/* child process... */
		nm_close (pipefd[0]);

		err = setpgid (0, 0);
		g_assert (err == 0);

		err = write (pipefd[1], &tmp, sizeof (tmp));
		g_assert (err == sizeof (tmp));

		nm_close (pipefd[1]);
		exit (0);
	}

	nm_close (pipefd[1]);

	err = read (pipefd[0], &tmp, sizeof (tmp));
	g_assert (err == sizeof (tmp));

	nm_close (pipefd[0]);

	err = setpgid (0, pgid);
	g_assert (err == 0);

	do {
		err = waitpid (pgid, &tmp, 0);
	} while (err == -1 && errno == EINTR);
	g_assert (err == pgid);
	g_assert (WIFEXITED (tmp) && WEXITSTATUS(tmp) == 0);

	return pgid;
}

#define TEST_TOKEN  "nm_test_kill_child_process"

static void
do_test_nm_utils_kill_child (void)
{
	GLogLevelFlags fatal_mask;
	char *argv_watchdog[] = {
			"bash",
			"-c",
			"sleep 4; "
			"kill -KILL 0; #watchdog for #" TEST_TOKEN,
			NULL,
		};
	char *argv1[] = {
			"bash",
			"-c",
			"trap \"sleep 0.3; exit 10\" EXIT; "
			"sleep 100000; exit $? #" TEST_TOKEN,
			NULL,
		};
	char *argv2[] = {
			"bash",
			"-c",
			"exit 47; #" TEST_TOKEN,
			NULL,
		};
	char *argv3[] = {
			"bash",
			"-c",
			"trap \"exit 47\" TERM; while true; do :; done; #" TEST_TOKEN,
			NULL,
		};
	char *argv4[] = {
			"bash",
			"-c",
			"trap \"while true; do :; done\" TERM; while true; do :; done; #" TEST_TOKEN,
			NULL,
		};
	pid_t pid1a_1, pid1a_2, pid1a_3, pid2a, pid3a, pid4a;
	pid_t pid1s_1, pid1s_2, pid1s_3, pid2s, pid3s, pid4s;

	const int expected_exit_47 = 12032; /* exit with status 47 */
	const int expected_signal_TERM = SIGTERM;
	const int expected_signal_KILL = SIGKILL;

	test_nm_utils_kill_child_spawn (argv_watchdog, FALSE);

	pid1s_1 = test_nm_utils_kill_child_spawn (argv1, TRUE);
	pid1s_2 = test_nm_utils_kill_child_spawn (argv1, TRUE);
	pid1s_3 = test_nm_utils_kill_child_spawn (argv1, TRUE);
	pid2s = test_nm_utils_kill_child_spawn (argv2, TRUE);
	pid3s = test_nm_utils_kill_child_spawn (argv3, TRUE);
	pid4s = test_nm_utils_kill_child_spawn (argv4, TRUE);

	pid1a_1 = test_nm_utils_kill_child_spawn (argv1, TRUE);
	pid1a_2 = test_nm_utils_kill_child_spawn (argv1, TRUE);
	pid1a_3 = test_nm_utils_kill_child_spawn (argv1, TRUE);
	pid2a = test_nm_utils_kill_child_spawn (argv2, TRUE);
	pid3a = test_nm_utils_kill_child_spawn (argv3, TRUE);
	pid4a = test_nm_utils_kill_child_spawn (argv4, TRUE);

	/* give processes time to start (and potentially block signals) ... */
	g_usleep (G_USEC_PER_SEC / 10);

	fatal_mask = g_log_set_always_fatal (G_LOG_FATAL_MASK);

	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-s-1-1' (*): waiting up to 3000 milliseconds for process to terminate normally after sending SIGTERM (15)...");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-s-1-1' (*): after sending SIGTERM (15), process * exited by signal 15 (* usec elapsed)");
	test_nm_utils_kill_child_sync_do ("test-s-1-1", pid1s_1, SIGTERM, 3000, TRUE,  &expected_signal_TERM);

	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-s-1-2' (*): waiting for process to terminate after sending SIGKILL (9)...");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-s-1-2' (*): after sending SIGKILL (9), process * exited by signal 9 (* usec elapsed)");
	test_nm_utils_kill_child_sync_do ("test-s-1-2", pid1s_2, SIGKILL, 1000 / 2, TRUE,  &expected_signal_KILL);

	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-s-1-3' (*): waiting up to 1 milliseconds for process to terminate normally after sending no signal (0)...");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-s-1-3' (*): sending SIGKILL...");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-s-1-3' (*): after sending no signal (0) and SIGKILL, process * exited by signal 9 (* usec elapsed)");
	test_nm_utils_kill_child_sync_do ("test-s-1-3", pid1s_3, 0, 1, TRUE,  &expected_signal_KILL);

	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-s-2' (*): process * already terminated normally with status 47");
	test_nm_utils_kill_child_sync_do ("test-s-2", pid2s, SIGTERM, 3000, TRUE,  &expected_exit_47);

	/* send invalid signal. */
	NMTST_EXPECT_NM_ERROR ("kill child process 'test-s-3-0' (*): failed to send Unexpected signal: Invalid argument (22)");
	test_nm_utils_kill_child_sync_do ("test-s-3-0", pid3s, -1, 0, FALSE, NULL);

	/* really kill pid3s */
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-s-3-1' (*): waiting up to 3000 milliseconds for process to terminate normally after sending SIGTERM (15)...");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-s-3-1' (*): after sending SIGTERM (15), process * exited normally with status 47 (* usec elapsed)");
	test_nm_utils_kill_child_sync_do ("test-s-3-1", pid3s, SIGTERM, 3000, TRUE,  &expected_exit_47);

	/* pid3s should not be a valid process, hence the call should fail. Note, that there
	 * is a race here. */
	NMTST_EXPECT_NM_ERROR ("kill child process 'test-s-3-2' (*): failed due to unexpected return value -1 by waitpid (No child processes, 10) after sending no signal (0)");
	test_nm_utils_kill_child_sync_do ("test-s-3-2", pid3s, 0, 0, FALSE, NULL);

	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-s-4' (*): waiting up to 1 milliseconds for process to terminate normally after sending SIGTERM (15)...");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-s-4' (*): sending SIGKILL...");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-s-4' (*): after sending SIGTERM (15) and SIGKILL, process * exited by signal 9 (* usec elapsed)");
	test_nm_utils_kill_child_sync_do ("test-s-4", pid4s, SIGTERM, 1, TRUE, &expected_signal_KILL);

	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-1-1' (*): wait for process to terminate after sending SIGTERM (15) (send SIGKILL in 3000 milliseconds)...");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-1-1' (*): terminated by signal 15 (* usec elapsed)");
	test_nm_utils_kill_child_async_do ("test-a-1-1", pid1a_1, SIGTERM, 3000, TRUE, &expected_signal_TERM);

	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-1-2' (*): wait for process to terminate after sending SIGKILL (9)...");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-1-2' (*): terminated by signal 9 (* usec elapsed)");
	test_nm_utils_kill_child_async_do ("test-a-1-2", pid1a_2, SIGKILL, 1000 / 2, TRUE, &expected_signal_KILL);

	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-1-3' (*): wait for process to terminate after sending no signal (0) (send SIGKILL in 1 milliseconds)...");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-1-3' (*): process not terminated after * usec. Sending SIGKILL signal");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-1-3' (*): terminated by signal 9 (* usec elapsed)");
	test_nm_utils_kill_child_async_do ("test-a-1-3", pid1a_3, 0, 1, TRUE, &expected_signal_KILL);

	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-2' (*): process * already terminated normally with status 47");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-2' (*): invoke callback: terminated normally with status 47");
	test_nm_utils_kill_child_async_do ("test-a-2", pid2a, SIGTERM, 3000, TRUE, &expected_exit_47);

	NMTST_EXPECT_NM_ERROR ("kill child process 'test-a-3-0' (*): unexpected error sending Unexpected signal: Invalid argument (22)");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-3-0' (*): invoke callback: killing child failed");
	/* coverity[negative_returns] */
	test_nm_utils_kill_child_async_do ("test-a-3-0", pid3a, -1, 1000 / 2, FALSE, NULL);

	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-3-1' (*): wait for process to terminate after sending SIGTERM (15) (send SIGKILL in 3000 milliseconds)...");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-3-1' (*): terminated normally with status 47 (* usec elapsed)");
	test_nm_utils_kill_child_async_do ("test-a-3-1", pid3a, SIGTERM, 3000, TRUE, &expected_exit_47);

	/* pid3a should not be a valid process, hence the call should fail. Note, that there
	 * is a race here. */
	NMTST_EXPECT_NM_ERROR ("kill child process 'test-a-3-2' (*): failed due to unexpected return value -1 by waitpid (No child processes, 10) after sending no signal (0)");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-3-2' (*): invoke callback: killing child failed");
	test_nm_utils_kill_child_async_do ("test-a-3-2", pid3a, 0, 0, FALSE, NULL);

	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-4' (*): wait for process to terminate after sending SIGTERM (15) (send SIGKILL in 1 milliseconds)...");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-4' (*): process not terminated after * usec. Sending SIGKILL signal");
	NMTST_EXPECT_NM_DEBUG ("kill child process 'test-a-4' (*): terminated by signal 9 (* usec elapsed)");
	test_nm_utils_kill_child_async_do ("test-a-4", pid4a, SIGTERM, 1, TRUE, &expected_signal_KILL);

	g_log_set_always_fatal (fatal_mask);

	g_test_assert_expected_messages ();
}

static void
test_nm_utils_kill_child (void)
{
	int err;
	int exit_status;
	pid_t gpid;
	pid_t child_pid;

	/* the tests spawns several processes, we want to clean them up
	 * by sending a SIGKILL to the process group.
	 *
	 * The current process might be a session leader, which prevents it from
	 * creating a new process group. Hence, first fork and let the child
	 * create a new process group, run the tests, and kill all pending
	 * processes. */
	child_pid = fork ();
	g_assert (child_pid >= 0);

	if (child_pid == 0) {
		gpid = do_test_nm_utils_kill_child_create_and_join_pgroup ();

		do_test_nm_utils_kill_child ();

		err = setpgid (0, 0);
		g_assert (err == 0);

		kill (-gpid, SIGKILL);

		exit (0);
	};

	do {
		err = waitpid (child_pid, &exit_status, 0);
	} while (err == -1 && errno == EINTR);
	g_assert (err == child_pid);
	g_assert (WIFEXITED (exit_status) && WEXITSTATUS(exit_status) == 0);
}

/*****************************************************************************/

static void
_remove_at_indexes_init_random_idx (GArray *idx, guint array_len, guint idx_len)
{
	GRand *rand = nmtst_get_rand ();
	gs_free char *mask = NULL;
	guint i, max_test_idx;

	g_assert (idx);
	g_assert (array_len > 0);
	g_assert (idx_len >= 1 && idx_len <= array_len);

	mask = g_new0 (char, array_len);

	max_test_idx = array_len - 1;
	for (i = 0; i < idx_len; i++) {
		guint itest;

		/* find a index itest that is not yet taken */
		if (max_test_idx == 0)
			itest = 0;
		else
			itest = g_rand_int_range (rand, 0, max_test_idx);
		while (itest < array_len && mask[itest])
			itest++;
		g_assert (itest <= max_test_idx);
		g_assert (!mask[itest]);

		mask[itest] = TRUE;
		if (itest == max_test_idx) {
			g_assert (max_test_idx > 0 || i == idx_len - 1);

			if (max_test_idx == 0)
				g_assert_cmpint (i, ==, idx_len - 1);
			else {
				max_test_idx--;
				while (max_test_idx > 0 && mask[max_test_idx])
					max_test_idx--;
				if (mask[max_test_idx])
					g_assert_cmpint (i, ==, idx_len - 1);
			}
		}
	}

	g_array_set_size (idx, 0);
	for (i = 0; i < array_len; i++) {
		if (mask[i])
			g_array_append_val (idx, i);
	}
	g_assert_cmpint (idx->len, ==, idx_len);
}

static void
test_nm_utils_array_remove_at_indexes (void)
{
	gs_unref_array GArray *idx = NULL, *array = NULL;
	gs_unref_hashtable GHashTable *unique = NULL;
	guint i_len, i_idx_len, i_rnd, i;

	idx = g_array_new (FALSE, FALSE, sizeof (guint));
	array = g_array_new (FALSE, FALSE, sizeof (gssize));
	unique = g_hash_table_new (nm_direct_hash, NULL);
	for (i_len = 1; i_len < 20; i_len++) {
		for (i_idx_len = 1; i_idx_len <= i_len; i_idx_len++) {
			for (i_rnd = 0; i_rnd < 20; i_rnd++) {

				_remove_at_indexes_init_random_idx (idx, i_len, i_idx_len);
				g_array_set_size (array, i_len);
				for (i = 0; i < i_len; i++)
					g_array_index (array, gssize, i) = i;

				nm_utils_array_remove_at_indexes (array, &g_array_index (idx, guint, 0), i_idx_len);

				g_hash_table_remove_all (unique);
				/* ensure that all the indexes are still unique */
				for (i = 0; i < array->len; i++)
					g_hash_table_add (unique, GUINT_TO_POINTER (g_array_index (array, gssize, i)));
				g_assert_cmpint (g_hash_table_size (unique), ==, array->len);

				for (i = 0; i < idx->len; i++)
					g_hash_table_add (unique, GUINT_TO_POINTER (g_array_index (idx, guint, i)));
				g_assert_cmpint (g_hash_table_size (unique), ==, i_len);

				/* ensure proper sort order in array */
				for (i = 0; i < array->len; i++) {
					gssize i1 = g_array_index (array, gssize, i);

					g_assert (i1 >= 0 && i1 < i_len);
					if (i > 0) {
						gsize i0 = g_array_index (array, gssize, i - 1);
						g_assert_cmpint (i0, <, i1);
					}
				}
			}
		}
	}
}

/*****************************************************************************/

static void
test_nm_ethernet_address_is_valid (void)
{
	g_assert (!nm_ethernet_address_is_valid (NULL, -1));
	g_assert (!nm_ethernet_address_is_valid (NULL, ETH_ALEN));

	g_assert (!nm_ethernet_address_is_valid ("FF:FF:FF:FF:FF:FF", -1));
	g_assert (!nm_ethernet_address_is_valid ("00:00:00:00:00:00", -1));
	g_assert (!nm_ethernet_address_is_valid ("44:44:44:44:44:44", -1));
	g_assert (!nm_ethernet_address_is_valid ("00:30:b4:00:00:00", -1));

	g_assert (!nm_ethernet_address_is_valid ("", -1));
	g_assert (!nm_ethernet_address_is_valid ("1", -1));
	g_assert (!nm_ethernet_address_is_valid ("2", -1));

	g_assert (!nm_ethernet_address_is_valid (((guint8[8]) { 0x00,0x30,0xb4,0x00,0x00,0x00 }), ETH_ALEN));
	g_assert ( nm_ethernet_address_is_valid (((guint8[8]) { 0x00,0x30,0xb4,0x00,0x00,0x01 }), ETH_ALEN));

	/* some Broad cast addresses (with MSB of first octet set). */
	g_assert (!nm_ethernet_address_is_valid ("57:44:44:44:44:44", -1));
	g_assert ( nm_ethernet_address_is_valid ("56:44:44:44:44:44", -1));
	g_assert (!nm_ethernet_address_is_valid (((guint8[8]) { 0x03,0x30,0xb4,0x00,0x00,0x00 }), ETH_ALEN));
	g_assert ( nm_ethernet_address_is_valid (((guint8[8]) { 0x02,0x30,0xb4,0x00,0x00,0x01 }), ETH_ALEN));
}

/*****************************************************************************/

static void
test_nm_utils_new_vlan_name (void)
{
	guint i, j;
	const char *parent_names[] = {
		"a",
		"a2",
		"a23",
		"a23456789",
		"a2345678901",
		"a23456789012",
		"a234567890123",
		"a2345678901234",
		"a23456789012345",
		"a234567890123456",
		"a2345678901234567",
	};

	for (i = 0; i < G_N_ELEMENTS (parent_names); i++) {
		for (j = 0; j < 10; j++) {
			gs_free char *ifname = NULL;
			gs_free char *vlan_id_s = NULL;
			guint vlan_id;

			/* Create a random VLAN id between 0 and 4094 */
			vlan_id = nmtst_get_rand_int () % 4095;

			vlan_id_s = g_strdup_printf (".%d", vlan_id);

			ifname = nm_utils_new_vlan_name (parent_names[i], vlan_id);
			g_assert (ifname && ifname[0]);
			g_assert_cmpint (strlen (ifname), ==, MIN (15, strlen (parent_names[i]) + strlen (vlan_id_s)));
			g_assert (g_str_has_suffix (ifname, vlan_id_s));
			g_assert (ifname[strlen (ifname) - strlen (vlan_id_s)] == '.');
			g_assert (strncmp (ifname, parent_names[i], strlen (ifname) - strlen (vlan_id_s)) == 0);
			if (!g_str_has_prefix (ifname, parent_names[i]))
				g_assert_cmpint (strlen (ifname), ==, 15);
		}
	}
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "DEBUG", "DEFAULT");

	g_test_add_func ("/general/nm_utils_monotonic_timestamp_as_boottime", test_nm_utils_monotonic_timestamp_as_boottime);
	g_test_add_func ("/general/nm_utils_kill_child", test_nm_utils_kill_child);
	g_test_add_func ("/general/nm_utils_array_remove_at_indexes", test_nm_utils_array_remove_at_indexes);
	g_test_add_func ("/general/nm_ethernet_address_is_valid", test_nm_ethernet_address_is_valid);
	g_test_add_func ("/general/nm_utils_new_vlan_name", test_nm_utils_new_vlan_name);

	return g_test_run ();
}

