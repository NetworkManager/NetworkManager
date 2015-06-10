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

#include "config.h"

#include <glib.h>
#include <string.h>
#include <errno.h>
#include <netinet/ether.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "NetworkManagerUtils.h"
#include "nm-logging.h"

#include "nm-test-utils.h"

/*******************************************/

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
test_nm_utils_kill_child_create_and_join_pgroup (void)
{
	int err, tmp = 0;
	int pipefd[2];
	pid_t pgid;

	err = pipe (pipefd);
	g_assert (err == 0);

	pgid = fork();
	if (pgid < 0) {
		g_assert_not_reached ();
		return pgid;
	}

	if (pgid == 0) {
		/* child process... */
		close (pipefd[0]);

		err = setpgid (0, 0);
		g_assert (err == 0);

		err = write (pipefd[1], &tmp, sizeof (tmp));
		g_assert (err == sizeof (tmp));

		close (pipefd[1]);
		exit (0);
	}

	close (pipefd[1]);

	err = read (pipefd[0], &tmp, sizeof (tmp));
	g_assert (err == sizeof (tmp));

	close (pipefd[0]);

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
test_nm_utils_kill_child (void)
{
	int err;
	GLogLevelFlags fatal_mask;
	char *argv_watchdog[] = {
			"sh",
			"-c",
			"sleep 4; "
			"kill -KILL 0; #watchdog for #" TEST_TOKEN,
			NULL,
		};
	char *argv1[] = {
			"sh",
			"-c",
			"trap \"sleep 0.3; exit 10\" EXIT; "
			"sleep 100000; exit $? #" TEST_TOKEN,
			NULL,
		};
	char *argv2[] = {
			"sh",
			"-c",
			"exit 47; #" TEST_TOKEN,
			NULL,
		};
	char *argv3[] = {
			"sh",
			"-c",
			"trap \"exit 47\" TERM; while true; do :; done; #" TEST_TOKEN,
			NULL,
		};
	char *argv4[] = {
			"sh",
			"-c",
			"trap \"while true; do :; done\" TERM; while true; do :; done; #" TEST_TOKEN,
			NULL,
		};
	pid_t gpid;
	pid_t pid1a_1, pid1a_2, pid1a_3, pid2a, pid3a, pid4a;
	pid_t pid1s_1, pid1s_2, pid1s_3, pid2s, pid3s, pid4s;

	const int expected_exit_47 = 12032; /* exit with status 47 */
	const int expected_signal_TERM = SIGTERM;
	const int expected_signal_KILL = SIGKILL;

	gpid = test_nm_utils_kill_child_create_and_join_pgroup ();

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

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-s-1-1' (*): waiting up to 500 milliseconds for process to terminate normally after sending SIGTERM (15)...");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-s-1-1' (*): after sending SIGTERM (15), process * exited by signal 15 (* usec elapsed)");
	test_nm_utils_kill_child_sync_do ("test-s-1-1", pid1s_1, SIGTERM, 1000 / 2, TRUE,  &expected_signal_TERM);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-s-1-2' (*): waiting for process to terminate after sending SIGKILL (9)...");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-s-1-2' (*): after sending SIGKILL (9), process * exited by signal 9 (* usec elapsed)");
	test_nm_utils_kill_child_sync_do ("test-s-1-2", pid1s_2, SIGKILL, 1000 / 2, TRUE,  &expected_signal_KILL);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-s-1-3' (*): waiting up to 1 milliseconds for process to terminate normally after sending no signal (0)...");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-s-1-3' (*): sending SIGKILL...");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-s-1-3' (*): after sending no signal (0) and SIGKILL, process * exited by signal 9 (* usec elapsed)");
	test_nm_utils_kill_child_sync_do ("test-s-1-3", pid1s_3, 0, 1, TRUE,  &expected_signal_KILL);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-s-2' (*): process * already terminated normally with status 47");
	test_nm_utils_kill_child_sync_do ("test-s-2", pid2s, SIGTERM, 1000 / 2, TRUE,  &expected_exit_47);

	/* send invalid signal. */
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING, "*kill child process 'test-s-3-0' (*): failed to send Unexpected signal: Invalid argument (22)");
	test_nm_utils_kill_child_sync_do ("test-s-3-0", pid3s, -1, 0, FALSE, NULL);

	/* really kill pid3s */
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-s-3-1' (*): waiting up to 500 milliseconds for process to terminate normally after sending SIGTERM (15)...");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-s-3-1' (*): after sending SIGTERM (15), process * exited normally with status 47 (* usec elapsed)");
	test_nm_utils_kill_child_sync_do ("test-s-3-1", pid3s, SIGTERM, 1000 / 2, TRUE,  &expected_exit_47);

	/* pid3s should not be a valid process, hence the call should fail. Note, that there
	 * is a race here. */
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING, "*kill child process 'test-s-3-2' (*): failed due to unexpected return value -1 by waitpid (No child processes, 10) after sending no signal (0)");
	test_nm_utils_kill_child_sync_do ("test-s-3-2", pid3s, 0, 0, FALSE, NULL);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-s-4' (*): waiting up to 1 milliseconds for process to terminate normally after sending SIGTERM (15)...");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-s-4' (*): sending SIGKILL...");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-s-4' (*): after sending SIGTERM (15) and SIGKILL, process * exited by signal 9 (* usec elapsed)");
	test_nm_utils_kill_child_sync_do ("test-s-4", pid4s, SIGTERM, 1, TRUE, &expected_signal_KILL);


	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-1-1' (*): wait for process to terminate after sending SIGTERM (15) (send SIGKILL in 500 milliseconds)...");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-1-1' (*): terminated by signal 15 (* usec elapsed)");
	test_nm_utils_kill_child_async_do ("test-a-1-1", pid1a_1, SIGTERM, 1000 / 2, TRUE, &expected_signal_TERM);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-1-2' (*): wait for process to terminate after sending SIGKILL (9)...");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-1-2' (*): terminated by signal 9 (* usec elapsed)");
	test_nm_utils_kill_child_async_do ("test-a-1-2", pid1a_2, SIGKILL, 1000 / 2, TRUE, &expected_signal_KILL);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-1-3' (*): wait for process to terminate after sending no signal (0) (send SIGKILL in 1 milliseconds)...");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-1-3' (*): process not terminated after * usec. Sending SIGKILL signal");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-1-3' (*): terminated by signal 9 (* usec elapsed)");
	test_nm_utils_kill_child_async_do ("test-a-1-3", pid1a_3, 0, 1, TRUE, &expected_signal_KILL);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-2' (*): process * already terminated normally with status 47");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-2' (*): invoke callback: terminated normally with status 47");
	test_nm_utils_kill_child_async_do ("test-a-2", pid2a, SIGTERM, 1000 / 2, TRUE, &expected_exit_47);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING, "*kill child process 'test-a-3-0' (*): unexpected error sending Unexpected signal: Invalid argument (22)");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-3-0' (*): invoke callback: killing child failed");
	/* coverity[negative_returns] */
	test_nm_utils_kill_child_async_do ("test-a-3-0", pid3a, -1, 1000 / 2, FALSE, NULL);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-3-1' (*): wait for process to terminate after sending SIGTERM (15) (send SIGKILL in 500 milliseconds)...");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-3-1' (*): terminated normally with status 47 (* usec elapsed)");
	test_nm_utils_kill_child_async_do ("test-a-3-1", pid3a, SIGTERM, 1000 / 2, TRUE, &expected_exit_47);

	/* pid3a should not be a valid process, hence the call should fail. Note, that there
	 * is a race here. */
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_WARNING, "*kill child process 'test-a-3-2' (*): failed due to unexpected return value -1 by waitpid (No child processes, 10) after sending no signal (0)");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-3-2' (*): invoke callback: killing child failed");
	test_nm_utils_kill_child_async_do ("test-a-3-2", pid3a, 0, 0, FALSE, NULL);

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-4' (*): wait for process to terminate after sending SIGTERM (15) (send SIGKILL in 1 milliseconds)...");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-4' (*): process not terminated after * usec. Sending SIGKILL signal");
	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_DEBUG, "*kill child process 'test-a-4' (*): terminated by signal 9 (* usec elapsed)");
	test_nm_utils_kill_child_async_do ("test-a-4", pid4a, SIGTERM, 1, TRUE, &expected_signal_KILL);

	err = setpgid (0, 0);
	g_assert (err == 0);

	kill (-gpid, SIGKILL);

	g_log_set_always_fatal (fatal_mask);

	g_test_assert_expected_messages ();
}


/*******************************************/

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

/*******************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "DEBUG", "DEFAULT");

	g_test_add_func ("/general/nm_utils_kill_child", test_nm_utils_kill_child);
	g_test_add_func ("/general/nm_ethernet_address_is_valid", test_nm_ethernet_address_is_valid);

	return g_test_run ();
}

