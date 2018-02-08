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
 * Copyright (C) 2004 - 2005 Colin Walters <walters@redhat.com>
 * Copyright (C) 2004 - 2017 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 *   and others
 */

#include "nm-default.h"

#include <errno.h>
#include <fcntl.h>
#include <resolv.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/fs.h>

#if WITH_LIBPSL
#include <libpsl.h>
#endif

#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nm-dns-manager.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "NetworkManagerUtils.h"
#include "nm-config.h"
#include "devices/nm-device.h"
#include "nm-manager.h"

#include "nm-dns-plugin.h"
#include "nm-dns-dnsmasq.h"
#include "nm-dns-systemd-resolved.h"
#include "nm-dns-unbound.h"

#include "introspection/org.freedesktop.NetworkManager.DnsManager.h"

#define HASH_LEN 20

#ifndef RESOLVCONF_PATH
#define RESOLVCONF_PATH "/sbin/resolvconf"
#endif

#ifndef NETCONFIG_PATH
#define NETCONFIG_PATH "/sbin/netconfig"
#endif

#define PLUGIN_RATELIMIT_INTERVAL    30
#define PLUGIN_RATELIMIT_BURST       5
#define PLUGIN_RATELIMIT_DELAY       300

enum {
	CONFIG_CHANGED,

	LAST_SIGNAL
};

NM_GOBJECT_PROPERTIES_DEFINE (NMDnsManager,
	PROP_MODE,
	PROP_RC_MANAGER,
	PROP_CONFIGURATION,
);

static guint signals[LAST_SIGNAL] = { 0 };

typedef enum {
	SR_SUCCESS,
	SR_NOTFOUND,
	SR_ERROR
} SpawnResult;

NM_DEFINE_SINGLETON_GETTER (NMDnsManager, nm_dns_manager_get, NM_TYPE_DNS_MANAGER);

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME                "dns-mgr"
#define _NMLOG_DOMAIN                     LOGD_DNS
#define _NMLOG(level, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        \
        if (nm_logging_enabled (__level, _NMLOG_DOMAIN)) { \
            char __prefix[20]; \
            const NMDnsManager *const __self = (self); \
            \
            _nm_log (__level, _NMLOG_DOMAIN, 0, NULL, NULL, \
                     "%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     _NMLOG_PREFIX_NAME, \
                     ((!__self || __self == singleton_instance) \
                        ? "" \
                        : nm_sprintf_buf (__prefix, "[%p]", __self)) \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

typedef struct {
	GPtrArray *configs;
	GVariant *config_variant;
	NMDnsIPConfigData *best_conf4, *best_conf6;

	bool need_sort:1;
	bool dns_touched:1;
	bool is_stopped:1;

	char *hostname;
	guint updates_queue;

	guint8 hash[HASH_LEN];  /* SHA1 hash of current DNS config */
	guint8 prev_hash[HASH_LEN];  /* Hash when begin_updates() was called */

	NMDnsManagerResolvConfManager rc_manager;
	char *mode;
	NMDnsPlugin *plugin;

	NMConfig *config;

	struct {
		guint64 ts;
		guint num_restarts;
		guint timer;
	} plugin_ratelimit;
} NMDnsManagerPrivate;

struct _NMDnsManager {
	NMExportedObject parent;
	NMDnsManagerPrivate _priv;
};

struct _NMDnsManagerClass {
	NMExportedObjectClass parent;
};

G_DEFINE_TYPE (NMDnsManager, nm_dns_manager, NM_TYPE_EXPORTED_OBJECT)

#define NM_DNS_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDnsManager, NM_IS_DNS_MANAGER)

static gboolean
domain_is_valid (const gchar *domain, gboolean check_public_suffix)
{
	if (*domain == '\0')
		return FALSE;
#if WITH_LIBPSL
	if (check_public_suffix && psl_is_public_suffix (psl_builtin (), domain))
		return FALSE;
#endif
	return TRUE;
}

/*****************************************************************************/

typedef struct {
	GPtrArray *nameservers;
	GPtrArray *searches;
	GPtrArray *options;
	const char *nis_domain;
	GPtrArray *nis_servers;
} NMResolvConfData;

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_rc_manager_to_string, NMDnsManagerResolvConfManager,
	NM_UTILS_LOOKUP_DEFAULT_WARN (NULL),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DNS_MANAGER_RESOLV_CONF_MAN_UNKNOWN,        "unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED,      "unmanaged"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE,      "immutable"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK,        "symlink"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE,           "file"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF,     "resolvconf"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG,      "netconfig"),
);

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_config_type_to_string, NMDnsIPConfigType,
	NM_UTILS_LOOKUP_DEFAULT_WARN ("<unknown>"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DNS_IP_CONFIG_TYPE_DEFAULT, "default"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE, "best"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_DNS_IP_CONFIG_TYPE_VPN, "vpn"),
);

static NMDnsIPConfigData *
ip_config_data_new (gpointer config, NMDnsIPConfigType type, const char *iface)
{
	NMDnsIPConfigData *data;

	data = g_slice_new0 (NMDnsIPConfigData);
	data->config = g_object_ref (config);
	data->iface = g_strdup (iface);
	data->type = type;

	return data;
}

static void
ip_config_data_destroy (gpointer ptr)
{
	NMDnsIPConfigData *data = ptr;

	if (!data)
		return;

	g_object_unref (data->config);
	g_free (data->iface);
	g_slice_free (NMDnsIPConfigData, data);
}

static gint
ip_config_data_compare (const NMDnsIPConfigData *a, const NMDnsIPConfigData *b)
{
	int a_prio, b_prio;

	a_prio = nm_ip_config_get_dns_priority (a->config);
	b_prio = nm_ip_config_get_dns_priority (b->config);

	/* Configurations with lower priority value first */
	if (a_prio < b_prio)
		return -1;
	else if (a_prio > b_prio)
		return 1;

	/* Sort also according to type */
	if (a->type > b->type)
		return -1;
	else if (a->type < b->type)
		return 1;

	return 0;
}

static gint
ip_config_data_ptr_compare (gconstpointer a, gconstpointer b)
{
	const NMDnsIPConfigData *const *ptr_a = a, *const *ptr_b = b;

	return ip_config_data_compare (*ptr_a, *ptr_b);
}

static void
add_string_item (GPtrArray *array, const char *str)
{
	int i;

	g_return_if_fail (array != NULL);
	g_return_if_fail (str != NULL);

	/* Check for dupes before adding */
	for (i = 0; i < array->len; i++) {
		const char *candidate = g_ptr_array_index (array, i);

		if (candidate && !strcmp (candidate, str))
			return;
	}

	/* No dupes, add the new item */
	g_ptr_array_add (array, g_strdup (str));
}

static void
add_dns_option_item (GPtrArray *array, const char *str)
{
	if (_nm_utils_dns_option_find_idx (array, str) < 0)
		g_ptr_array_add (array, g_strdup (str));
}

static void
merge_one_ip_config (NMResolvConfData *rc,
                     const NMIPConfig *config,
                     const char *iface)
{
	int addr_family;
	guint num, num_domains, num_searches, i;
	char buf[NM_UTILS_INET_ADDRSTRLEN + 50];
	const char *str;

	addr_family = nm_ip_config_get_addr_family (config);

	nm_assert_addr_family (addr_family);

	num = nm_ip_config_get_num_nameservers (config);
	for (i = 0; i < num; i++) {
		const NMIPAddr *addr;

		addr = nm_ip_config_get_nameserver (config, i);
		if (addr_family == AF_INET)
			nm_utils_inet_ntop (addr_family, addr, buf);
		else if (IN6_IS_ADDR_V4MAPPED (addr))
			nm_utils_inet4_ntop (addr->addr6.s6_addr32[3], buf);
		else {
			nm_utils_inet6_ntop (&addr->addr6, buf);
			if (IN6_IS_ADDR_LINKLOCAL (addr)) {
				g_strlcat (buf, "%", sizeof (buf));
				g_strlcat (buf, iface, sizeof (buf));
			}
		}

		add_string_item (rc->nameservers, buf);
	}

	num_domains = nm_ip_config_get_num_domains (config);
	num_searches = nm_ip_config_get_num_searches (config);
	for (i = 0; i < num_searches; i++) {
		str = nm_ip_config_get_search (config, i);
		if (domain_is_valid (str, FALSE))
			add_string_item (rc->searches, str);
	}
	if (num_domains > 1 || !num_searches) {
		for (i = 0; i < num_domains; i++) {
			str = nm_ip_config_get_domain (config, i);
			if (domain_is_valid (str, FALSE))
				add_string_item (rc->searches, str);
		}
	}

	num = nm_ip_config_get_num_dns_options (config);
	for (i = 0; i < num; i++) {
		add_dns_option_item (rc->options,
		                     nm_ip_config_get_dns_option (config, i));
	}

	if (addr_family == AF_INET) {
		const NMIP4Config *config4 = (const NMIP4Config *) config;

		/* NIS stuff */
		num = nm_ip4_config_get_num_nis_servers (config4);
		for (i = 0; i < num; i++) {
			add_string_item (rc->nis_servers,
			                 nm_utils_inet4_ntop (nm_ip4_config_get_nis_server (config4, i), buf));
		}

		if (nm_ip4_config_get_nis_domain (config4)) {
			/* FIXME: handle multiple domains */
			if (!rc->nis_domain)
				rc->nis_domain = nm_ip4_config_get_nis_domain (config4);
		}
	}
}

static GPid
run_netconfig (NMDnsManager *self, GError **error, gint *stdin_fd)
{
	char *argv[5];
	gs_free char *tmp = NULL;
	GPid pid = -1;

	argv[0] = NETCONFIG_PATH;
	argv[1] = "modify";
	argv[2] = "--service";
	argv[3] = "NetworkManager";
	argv[4] = NULL;

	_LOGD ("spawning '%s'",
	       (tmp = g_strjoinv (" ", argv)));

	if (!g_spawn_async_with_pipes (NULL, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL,
	                               NULL, &pid, stdin_fd, NULL, NULL, error))
		return -1;

	return pid;
}

static void
write_to_netconfig (NMDnsManager *self, gint fd, const char *key, const char *value)
{
	char *str;
	int x;

	str = g_strdup_printf ("%s='%s'\n", key, value);
	_LOGD ("writing to netconfig: %s", str);
	x = write (fd, str, strlen (str));
	g_free (str);
}

static SpawnResult
dispatch_netconfig (NMDnsManager *self,
                    char **searches,
                    char **nameservers,
                    const char *nis_domain,
                    char **nis_servers,
                    GError **error)
{
	char *str;
	GPid pid;
	gint fd;
	int status;

	pid = run_netconfig (self, error, &fd);
	if (pid <= 0)
		return SR_NOTFOUND;

	/* NM is writing already-merged DNS information to netconfig, so it
	 * does not apply to a specific network interface.
	 */
	write_to_netconfig (self, fd, "INTERFACE", "NetworkManager");

	if (searches) {
		str = g_strjoinv (" ", searches);
		write_to_netconfig (self, fd, "DNSSEARCH", str);
		g_free (str);
	}

	if (nameservers) {
		str = g_strjoinv (" ", nameservers);
		write_to_netconfig (self, fd, "DNSSERVERS", str);
		g_free (str);
	}

	if (nis_domain)
		write_to_netconfig (self, fd, "NISDOMAIN", nis_domain);

	if (nis_servers) {
		str = g_strjoinv (" ", nis_servers);
		write_to_netconfig (self, fd, "NISSERVERS", str);
		g_free (str);
	}

	nm_close (fd);

	/* Wait until the process exits */
	if (!nm_utils_kill_child_sync (pid, 0, LOGD_DNS, "netconfig", &status, 1000, 0)) {
		int errsv = errno;

		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		             "Error waiting for netconfig to exit: %s",
		             strerror (errsv));
		return SR_ERROR;
	}
	if (!WIFEXITED (status) || WEXITSTATUS (status) != EXIT_SUCCESS) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		             "Error calling netconfig: %s %d",
		             WIFEXITED (status) ? "exited with status" : (WIFSIGNALED (status) ? "exited with signal" : "exited with unknown reason"),
		             WIFEXITED (status) ? WEXITSTATUS (status) : (WIFSIGNALED (status) ? WTERMSIG (status) : status));
		return SR_ERROR;
	}
	return SR_SUCCESS;
}

static char *
create_resolv_conf (char **searches,
                    char **nameservers,
                    char **options)
{
	gs_free char *searches_str = NULL;
	gs_free char *nameservers_str = NULL;
	gs_free char *options_str = NULL;
	char *tmp_str;
	GString *str;
	int i;

	if (searches) {
		tmp_str = g_strjoinv (" ", searches);
		searches_str = g_strconcat ("search ", tmp_str, "\n", NULL);
		g_free (tmp_str);
	}

	if (options) {
		tmp_str = g_strjoinv (" ", options);
		options_str = g_strconcat ("options ", tmp_str, "\n", NULL);
		g_free (tmp_str);
	}

	if (nameservers) {
		int num = g_strv_length (nameservers);

		str = g_string_new ("");
		for (i = 0; i < num; i++) {
			if (i == 3) {
				g_string_append (str, "# ");
				g_string_append (str, "NOTE: the libc resolver may not support more than 3 nameservers.");
				g_string_append (str, "\n# ");
				g_string_append (str, "The nameservers listed below may not be recognized.");
				g_string_append_c (str, '\n');
			}

			g_string_append (str, "nameserver ");
			g_string_append (str, nameservers[i]);
			g_string_append_c (str, '\n');
		}
		nameservers_str = g_string_free (str, FALSE);
	}

	return g_strdup_printf ("# Generated by NetworkManager\n%s%s%s",
	                        searches_str ?: "",
	                        nameservers_str ?: "",
	                        options_str ?: "");
}

static gboolean
write_resolv_conf_contents (FILE *f,
                            const char *content,
                            GError **error)
{
	int errsv;

	if (fprintf (f, "%s", content) < 0) {
		errsv = errno;
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_FAILED,
		             "Could not write " _PATH_RESCONF ": %s",
		             g_strerror (errsv));
		errno = errsv;
		return FALSE;
	}

	return TRUE;
}

static gboolean
write_resolv_conf (FILE *f,
                   char **searches,
                   char **nameservers,
                   char **options,
                   GError **error)
{
	gs_free char *content = NULL;

	content = create_resolv_conf (searches, nameservers, options);
	return write_resolv_conf_contents (f, content, error);
}

static SpawnResult
dispatch_resolvconf (NMDnsManager *self,
                     char **searches,
                     char **nameservers,
                     char **options,
                     GError **error)
{
	gs_free char *cmd = NULL;
	FILE *f;
	gboolean success = FALSE;
	int errnosv, err;
	char *argv[] = { RESOLVCONF_PATH, "-d", "NetworkManager", NULL };
	int status;

	if (!g_file_test (RESOLVCONF_PATH, G_FILE_TEST_IS_EXECUTABLE)) {
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_FAILED,
		                     RESOLVCONF_PATH " is not executable");
		return SR_NOTFOUND;
	}

	if (!searches && !nameservers) {
		_LOGI ("Removing DNS information from %s", RESOLVCONF_PATH);

		if (!g_spawn_sync ("/", argv, NULL, 0, NULL, NULL, NULL, NULL, &status, error))
			return SR_ERROR;

		if (status != 0) {
			g_set_error (error,
			             NM_MANAGER_ERROR,
			             NM_MANAGER_ERROR_FAILED,
			             "%s returned error code",
			             RESOLVCONF_PATH);
			return SR_ERROR;
		}

		return SR_SUCCESS;
	}

	_LOGI ("Writing DNS information to %s", RESOLVCONF_PATH);

	cmd = g_strconcat (RESOLVCONF_PATH, " -a ", "NetworkManager", NULL);
	if ((f = popen (cmd, "w")) == NULL) {
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_FAILED,
		             "Could not write to %s: %s",
		             RESOLVCONF_PATH,
		             g_strerror (errno));
		return SR_ERROR;
	}

	success = write_resolv_conf (f, searches, nameservers, options, error);
	err = pclose (f);
	if (err < 0) {
		errnosv = errno;
		g_clear_error (error);
		g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errnosv),
		             "Failed to close pipe to resolvconf: %d", errnosv);
		return SR_ERROR;
	} else if (err > 0) {
		_LOGW ("resolvconf failed with status %d", err);
		g_clear_error (error);
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
		             "resolvconf failed with status %d", err);
		return SR_ERROR;
	}

	return success ? SR_SUCCESS : SR_ERROR;
}

static const char *
_read_link_cached (const char *path, gboolean *is_cached, char **cached)
{
	nm_assert (is_cached);
	nm_assert (cached);

	if (*is_cached)
		return *cached;

	nm_assert (!*cached);
	*is_cached = TRUE;
	return (*cached = g_file_read_link (path, NULL));
}

#define MY_RESOLV_CONF NMRUNDIR "/resolv.conf"
#define MY_RESOLV_CONF_TMP MY_RESOLV_CONF ".tmp"
#define RESOLV_CONF_TMP "/etc/.resolv.conf.NetworkManager"

static SpawnResult
update_resolv_conf (NMDnsManager *self,
                    char **searches,
                    char **nameservers,
                    char **options,
                    GError **error,
                    NMDnsManagerResolvConfManager rc_manager)
{
	FILE *f;
	gboolean success;
	gs_free char *content = NULL;
	SpawnResult write_file_result = SR_SUCCESS;
	int errsv;
	const char *rc_path = _PATH_RESCONF;
	nm_auto_free char *rc_path_real = NULL;
	gboolean resconf_link_cached = FALSE;
	gs_free char *resconf_link = NULL;

	/* If we are not managing /etc/resolv.conf and it points to
	 * MY_RESOLV_CONF, don't write the private DNS configuration to
	 * MY_RESOLV_CONF otherwise we would overwrite the changes done by
	 * some external application.
	 *
	 * This is the only situation, where we don't try to update our
	 * internal resolv.conf file. */
	if (rc_manager == NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED) {
		if (nm_streq0 (_read_link_cached (_PATH_RESCONF, &resconf_link_cached, &resconf_link),
		               MY_RESOLV_CONF)) {
			_LOGD ("update-resolv-conf: not updating " _PATH_RESCONF
			       " since it points to " MY_RESOLV_CONF);
			return SR_SUCCESS;
		}
	}

	content = create_resolv_conf (searches, nameservers, options);

	if (   rc_manager == NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE
	    || (   rc_manager == NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK
	        && !_read_link_cached (_PATH_RESCONF, &resconf_link_cached, &resconf_link))) {
		GError *local = NULL;

		if (rc_manager == NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE) {
			rc_path_real = realpath (rc_path, NULL);
			if (rc_path_real)
				rc_path = rc_path_real;
		}

		/* we first write to /etc/resolv.conf directly. If that fails,
		 * we still continue to write to runstatedir but remember the
		 * error. */
		if (!g_file_set_contents (rc_path, content, -1, &local)) {
			_LOGT ("update-resolv-conf: write to %s failed (rc-manager=%s, %s)",
			       rc_path, _rc_manager_to_string (rc_manager), local->message);
			write_file_result = SR_ERROR;
			g_propagate_error (error, local);
			error = NULL;
		} else {
			_LOGT ("update-resolv-conf: write to %s succeeded (rc-manager=%s)",
			       rc_path, _rc_manager_to_string (rc_manager));
		}
	}

	if ((f = fopen (MY_RESOLV_CONF_TMP, "we")) == NULL) {
		errsv = errno;
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_FAILED,
		             "Could not open %s: %s",
		             MY_RESOLV_CONF_TMP,
		             g_strerror (errsv));
		_LOGT ("update-resolv-conf: open temporary file %s failed (%s)",
		       MY_RESOLV_CONF_TMP, g_strerror (errsv));
		return SR_ERROR;
	}

	success = write_resolv_conf_contents (f, content, error);
	if (!success) {
		errsv = errno;
		_LOGT ("update-resolv-conf: write temporary file %s failed (%s)",
		       MY_RESOLV_CONF_TMP, g_strerror (errsv));
	}

	if (fclose (f) < 0) {
		if (success) {
			errsv = errno;
			/* only set an error here if write_resolv_conf() was successful,
			 * since its error is more important.
			 */
			g_set_error (error,
			             NM_MANAGER_ERROR,
			             NM_MANAGER_ERROR_FAILED,
			             "Could not close %s: %s",
			             MY_RESOLV_CONF_TMP,
			             g_strerror (errsv));
			_LOGT ("update-resolv-conf: close temporary file %s failed (%s)",
			       MY_RESOLV_CONF_TMP, g_strerror (errsv));
		}
		return SR_ERROR;
	} else if (!success)
		return SR_ERROR;

	if (rename (MY_RESOLV_CONF_TMP, MY_RESOLV_CONF) < 0) {
		errsv = errno;
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_FAILED,
		             "Could not replace %s: %s",
		             MY_RESOLV_CONF,
		             g_strerror (errno));
		_LOGT ("update-resolv-conf: failed to rename temporary file %s to %s (%s)",
		       MY_RESOLV_CONF_TMP, MY_RESOLV_CONF, g_strerror (errsv));
		return SR_ERROR;
	}

	if (rc_manager == NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE) {
		_LOGT ("update-resolv-conf: write internal file %s succeeded (rc-manager=%s)",
		       rc_path, _rc_manager_to_string (rc_manager));
		return write_file_result;
	}

	if (   rc_manager != NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK
	    || !_read_link_cached (_PATH_RESCONF, &resconf_link_cached, &resconf_link)) {
		_LOGT ("update-resolv-conf: write internal file %s succeeded", MY_RESOLV_CONF);
		return SR_SUCCESS;
	}

	if (!nm_streq0 (_read_link_cached (_PATH_RESCONF, &resconf_link_cached, &resconf_link),
	                MY_RESOLV_CONF)) {
		_LOGT ("update-resolv-conf: write internal file %s succeeded (don't touch symlink %s linking to %s)",
		       MY_RESOLV_CONF, _PATH_RESCONF,
		       _read_link_cached (_PATH_RESCONF, &resconf_link_cached, &resconf_link));
		return SR_SUCCESS;
	}

	/* By this point, /etc/resolv.conf exists and is a symlink to our internal
	 * resolv.conf. We update the symlink so that applications get an inotify
	 * notification.
	 */
	if (   unlink (RESOLV_CONF_TMP) != 0
	    && ((errsv = errno) != ENOENT)) {
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_FAILED,
		             "Could not unlink %s: %s",
		             RESOLV_CONF_TMP,
		             g_strerror (errsv));
		_LOGT ("update-resolv-conf: write internal file %s succeeded "
		       "but canot delete temporary file %s: %s",
		       MY_RESOLV_CONF, RESOLV_CONF_TMP, g_strerror (errsv));
		return SR_ERROR;
	}

	if (symlink (MY_RESOLV_CONF, RESOLV_CONF_TMP) == -1) {
		errsv = errno;
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_FAILED,
		             "Could not create symlink %s pointing to %s: %s",
		             RESOLV_CONF_TMP,
		             MY_RESOLV_CONF,
		             g_strerror (errsv));
		_LOGT ("update-resolv-conf: write internal file %s succeeded "
		       "but failed to symlink %s: %s",
		       MY_RESOLV_CONF, RESOLV_CONF_TMP, g_strerror (errsv));
		return SR_ERROR;
	}

	if (rename (RESOLV_CONF_TMP, _PATH_RESCONF) == -1) {
		errsv = errno;
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_FAILED,
		             "Could not rename %s to %s: %s",
		             RESOLV_CONF_TMP,
		             _PATH_RESCONF,
		             g_strerror (errsv));
		_LOGT ("update-resolv-conf: write internal file %s succeeded "
		       "but failed to rename temporary symlink %s to %s: %s",
		       MY_RESOLV_CONF, RESOLV_CONF_TMP, _PATH_RESCONF, g_strerror (errsv));
		return SR_ERROR;
	}

	_LOGT ("update-resolv-conf: write internal file %s succeeded and update symlink %s",
	       MY_RESOLV_CONF, _PATH_RESCONF);
	return SR_SUCCESS;
}

static void
compute_hash (NMDnsManager *self, const NMGlobalDnsConfig *global, guint8 buffer[HASH_LEN])
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);
	GChecksum *sum;
	gsize len = HASH_LEN;
	guint i;

	sum = g_checksum_new (G_CHECKSUM_SHA1);
	g_assert (len == g_checksum_type_get_length (G_CHECKSUM_SHA1));

	if (global)
		nm_global_dns_config_update_checksum (global, sum);
	else {
		for (i = 0; i < priv->configs->len; i++) {
			NMDnsIPConfigData *data = priv->configs->pdata[i];

			if (NM_IS_IP4_CONFIG (data->config))
				nm_ip4_config_hash ((NMIP4Config *) data->config, sum, TRUE);
			else if (NM_IS_IP6_CONFIG (data->config))
				nm_ip6_config_hash ((NMIP6Config *) data->config, sum, TRUE);
		}
	}

	g_checksum_get_digest (sum, buffer, &len);
	g_checksum_free (sum);
}

static gboolean
merge_global_dns_config (NMResolvConfData *rc, NMGlobalDnsConfig *global_conf)
{
	NMGlobalDnsDomain *default_domain;
	const char *const *searches;
	const char *const *options;
	const char *const *servers;
	gint i;

	if (!global_conf)
		return FALSE;

	searches = nm_global_dns_config_get_searches (global_conf);
	options = nm_global_dns_config_get_options (global_conf);

	for (i = 0; searches && searches[i]; i++) {
		if (domain_is_valid (searches[i], FALSE))
			add_string_item (rc->searches, searches[i]);
	}

	for (i = 0; options && options[i]; i++)
		add_string_item (rc->options, options[i]);

	default_domain = nm_global_dns_config_lookup_domain (global_conf, "*");
	g_assert (default_domain);
	servers = nm_global_dns_domain_get_servers (default_domain);
	for (i = 0; servers && servers[i]; i++)
		add_string_item (rc->nameservers, servers[i]);

	return TRUE;
}

static const char *
get_nameserver_list (const NMIPConfig *config, GString **str)
{
	guint num, i;
	char buf[NM_UTILS_INET_ADDRSTRLEN];
	int addr_family;

	if (*str)
		g_string_truncate (*str, 0);
	else
		*str = g_string_sized_new (64);

	addr_family = nm_ip_config_get_addr_family (config);
	num = nm_ip_config_get_num_nameservers (config);
	for (i = 0; i < num; i++) {
		nm_utils_inet_ntop (addr_family,
		                    nm_ip_config_get_nameserver (config, i),
		                    buf);
		if (i > 0)
			g_string_append_c (*str, ' ');
		g_string_append (*str, buf);
	}

	return (*str)->str;
}

static char **
_ptrarray_to_strv (GPtrArray *parray)
{
	if (parray->len > 0)
		g_ptr_array_add (parray, NULL);
	return (char **) g_ptr_array_free (parray, parray->len == 0);
}

static void
_collect_resolv_conf_data (NMDnsManager *self, /* only for logging context, no other side-effects */
                           NMGlobalDnsConfig *global_config,
                           const GPtrArray *configs,
                           const char *hostname,
                           char ***out_searches,
                           char ***out_options,
                           char ***out_nameservers,
                           char ***out_nis_servers,
                           const char **out_nis_domain)
{
	guint i, j, num, len;
	NMResolvConfData rc = {
		.nameservers = g_ptr_array_new (),
		.searches = g_ptr_array_new (),
		.options = g_ptr_array_new (),
		.nis_domain = NULL,
		.nis_servers = g_ptr_array_new (),
	};

	if (global_config)
		merge_global_dns_config (&rc, global_config);
	else {
		nm_auto_free_gstring GString *tmp_gstring = NULL;
		int prio, first_prio = 0;
		NMDnsIPConfigData *current;

		for (i = 0, j = 0; i < configs->len; i++) {
			gboolean skip = FALSE;

			current = configs->pdata[i];

			prio = nm_ip_config_get_dns_priority (current->config);

			if (i == 0)
				first_prio = prio;
			else if (first_prio < 0 && first_prio != prio)
				skip = TRUE;

			if (nm_ip_config_get_num_nameservers (current->config)) {
				_LOGT ("config: %8d %-7s v%c %-16s %s: %s",
				       prio,
				       _config_type_to_string (current->type),
				       nm_utils_addr_family_to_char (nm_ip_config_get_addr_family (current->config)),
				       current->iface,
				       skip ? "<SKIP>" : "",
				       get_nameserver_list (current->config, &tmp_gstring));
			}

			if (!skip)
				merge_one_ip_config (&rc, current->config, current->iface);
		}
	}

	/* If the hostname is a FQDN ("dcbw.example.com"), then add the domain part of it
	 * ("example.com") to the searches list, to ensure that we can still resolve its
	 * non-FQ form ("dcbw") too. (Also, if there are no other search domains specified,
	 * this makes a good default.) However, if the hostname is the top level of a domain
	 * (eg, "example.com"), then use the hostname itself as the search (since the user is
	 * unlikely to want "com" as a search domain).
	 */
	if (hostname) {
		const char *hostdomain = strchr (hostname, '.');

		if (   hostdomain
		    && !nm_utils_ipaddr_valid (AF_UNSPEC, hostname)) {
			hostdomain++;
			if (domain_is_valid (hostdomain, TRUE))
				add_string_item (rc.searches, hostdomain);
			else if (domain_is_valid (hostname, TRUE))
				add_string_item (rc.searches, hostname);
		}
	}

	/* Per 'man resolv.conf', the search list is limited to 6 domains
	 * totalling 256 characters.
	 */
	num = MIN (rc.searches->len, 6u);
	for (i = 0, len = 0; i < num; i++) {
		len += strlen (rc.searches->pdata[i]) + 1; /* +1 for spaces */
		if (len > 256)
			break;
	}
	g_ptr_array_set_size (rc.searches, i);

	*out_searches = _ptrarray_to_strv (rc.searches);
	*out_options = _ptrarray_to_strv (rc.options);
	*out_nameservers = _ptrarray_to_strv (rc.nameservers);
	*out_nis_servers = _ptrarray_to_strv (rc.nis_servers);
	*out_nis_domain = rc.nis_domain;
}

static gboolean
update_dns (NMDnsManager *self,
            gboolean no_caching,
            GError **error)
{
	NMDnsManagerPrivate *priv;
	const char *nis_domain = NULL;
	gs_strfreev char **searches = NULL;
	gs_strfreev char **options = NULL;
	gs_strfreev char **nameservers = NULL;
	gs_strfreev char **nis_servers = NULL;
	gboolean caching = FALSE, update = TRUE;
	gboolean resolv_conf_updated = FALSE;
	SpawnResult result = SR_ERROR;
	NMConfigData *data;
	NMGlobalDnsConfig *global_config;

	g_return_val_if_fail (!error || !*error, FALSE);

	priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	if (priv->is_stopped) {
		_LOGD ("update-dns: not updating resolv.conf (is stopped)");
		return TRUE;
	}

	nm_clear_g_source (&priv->plugin_ratelimit.timer);

	if (NM_IN_SET (priv->rc_manager, NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED,
	                                 NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE)) {
		update = FALSE;
		_LOGD ("update-dns: not updating resolv.conf");
	} else {
		priv->dns_touched = TRUE;
		_LOGD ("update-dns: updating resolv.conf");
	}

	data = nm_config_get_data (priv->config);
	global_config = nm_config_data_get_global_dns_config (data);

	if (priv->need_sort) {
		g_ptr_array_sort (priv->configs, ip_config_data_ptr_compare);
		priv->need_sort = FALSE;
	}

	/* Update hash with config we're applying */
	compute_hash (self, global_config, priv->hash);

	_collect_resolv_conf_data (self, global_config, priv->configs, priv->hostname,
	                           &searches, &options, &nameservers, &nis_servers, &nis_domain);

	/* Let any plugins do their thing first */
	if (priv->plugin) {
		NMDnsPlugin *plugin = priv->plugin;
		const char *plugin_name = nm_dns_plugin_get_name (plugin);

		if (nm_dns_plugin_is_caching (plugin)) {
			if (no_caching) {
				_LOGD ("update-dns: plugin %s ignored (caching disabled)",
				       plugin_name);
				goto skip;
			}
			caching = TRUE;
		}

		_LOGD ("update-dns: updating plugin %s", plugin_name);
		if (!nm_dns_plugin_update (plugin,
		                           priv->configs,
		                           global_config,
		                           priv->hostname)) {
			_LOGW ("update-dns: plugin %s update failed", plugin_name);

			/* If the plugin failed to update, we shouldn't write out a local
			 * caching DNS configuration to resolv.conf.
			 */
			caching = FALSE;
		}

	skip:
		;
	}

	/* If caching was successful, we only send 127.0.0.1 to /etc/resolv.conf
	 * to ensure that the glibc resolver doesn't try to round-robin nameservers,
	 * but only uses the local caching nameserver.
	 */
	if (caching) {
		const char *lladdr = "127.0.0.1";

		if (NM_IS_DNS_SYSTEMD_RESOLVED (priv->plugin)) {
			/* systemd-resolved uses a different link-local address */
			lladdr = "127.0.0.53";
		}

		g_strfreev (nameservers);
		nameservers = g_new0 (char *, 2);
		nameservers[0] = g_strdup (lladdr);
	}

	if (update) {
		switch (priv->rc_manager) {
		case NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK:
		case NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE:
			result = update_resolv_conf (self, searches, nameservers, options, error, priv->rc_manager);
			resolv_conf_updated = TRUE;
			/* If we have ended with no nameservers avoid updating again resolv.conf
			 * on stop, as some external changes may be applied to it in the meanwhile */
			if (!nameservers && !options)
				priv->dns_touched = FALSE;
			break;
		case NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF:
			result = dispatch_resolvconf (self, searches, nameservers, options, error);
			break;
		case NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG:
			result = dispatch_netconfig (self, searches, nameservers, nis_domain,
			                             nis_servers, error);
			break;
		default:
			g_assert_not_reached ();
		}

		if (result == SR_NOTFOUND) {
			_LOGD ("update-dns: program not available, writing to resolv.conf");
			g_clear_error (error);
			result = update_resolv_conf (self, searches, nameservers, options, error, NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK);
			resolv_conf_updated = TRUE;
		}
	}

	/* Unless we've already done it, update private resolv.conf in NMRUNDIR
	   ignoring any errors */
	if (!resolv_conf_updated)
		update_resolv_conf (self, searches, nameservers, options, NULL, NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED);

	/* signal that resolv.conf was changed */
	if (update && result == SR_SUCCESS)
		g_signal_emit (self, signals[CONFIG_CHANGED], 0);

	g_clear_pointer (&priv->config_variant, g_variant_unref);
	_notify (self, PROP_CONFIGURATION);

	return !update || result == SR_SUCCESS;
}

static void
plugin_failed (NMDnsPlugin *plugin, gpointer user_data)
{
	NMDnsManager *self = NM_DNS_MANAGER (user_data);
	GError *error = NULL;

	/* Errors with non-caching plugins aren't fatal */
	if (!nm_dns_plugin_is_caching (plugin))
		return;

	/* Disable caching until the next DNS update */
	if (!update_dns (self, TRUE, &error)) {
		_LOGW ("could not commit DNS changes: %s", error->message);
		g_clear_error (&error);
	}
}

static gboolean
plugin_child_quit_update_dns (gpointer user_data)
{
	GError *error = NULL;
	NMDnsManager *self = NM_DNS_MANAGER (user_data);

	/* Let the plugin try to spawn the child again */
	if (!update_dns (self, FALSE, &error)) {
		_LOGW ("could not commit DNS changes: %s", error->message);
		g_clear_error (&error);
	}

	return G_SOURCE_REMOVE;
}

static void
plugin_child_quit (NMDnsPlugin *plugin, int exit_status, gpointer user_data)
{
	NMDnsManager *self = NM_DNS_MANAGER (user_data);
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);
	gint64 ts = nm_utils_get_monotonic_timestamp_ms ();

	_LOGW ("plugin %s child quit unexpectedly", nm_dns_plugin_get_name (plugin));

	if (   !priv->plugin_ratelimit.ts
	    || (ts - priv->plugin_ratelimit.ts) / 1000 > PLUGIN_RATELIMIT_INTERVAL) {
		priv->plugin_ratelimit.ts = ts;
		priv->plugin_ratelimit.num_restarts = 0;
	} else {
		priv->plugin_ratelimit.num_restarts++;
		if (priv->plugin_ratelimit.num_restarts > PLUGIN_RATELIMIT_BURST) {
			_LOGW ("plugin %s child respawning too fast, delaying update for %u seconds",
			        nm_dns_plugin_get_name (plugin), PLUGIN_RATELIMIT_DELAY);
			priv->plugin_ratelimit.timer = g_timeout_add_seconds (PLUGIN_RATELIMIT_DELAY,
			                                                      plugin_child_quit_update_dns,
			                                                      self);
			return;
		}
	}

	plugin_child_quit_update_dns (self);
}

static void
ip_config_dns_priority_changed (gpointer config,
                                GParamSpec *pspec,
                                NMDnsManager *self)
{
	NM_DNS_MANAGER_GET_PRIVATE (self)->need_sort = TRUE;
}

static void
forget_data (NMDnsManager *self, NMDnsIPConfigData *data)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	if (data == priv->best_conf4)
		priv->best_conf4 = NULL;
	else if (data == priv->best_conf6)
		priv->best_conf6 = NULL;

	g_signal_handlers_disconnect_by_func (data->config, ip_config_dns_priority_changed, self);
}

gboolean
nm_dns_manager_add_ip_config (NMDnsManager *self,
                              const char *iface,
                              gpointer config,
                              NMDnsIPConfigType cfg_type)
{
	NMDnsManagerPrivate *priv;
	GError *error = NULL;
	NMDnsIPConfigData *data;
	gboolean v4 = NM_IS_IP4_CONFIG (config);
	guint i;

	g_return_val_if_fail (NM_IS_DNS_MANAGER (self), FALSE);
	g_return_val_if_fail (config, FALSE);
	g_return_val_if_fail (iface && iface[0], FALSE);
	nm_assert (NM_IS_IP_CONFIG (config));

	priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	for (i = 0; i < priv->configs->len; i++) {
		data = priv->configs->pdata[i];
		if (data->config == config) {
			if (   nm_streq (data->iface, iface)
			    && data->type == cfg_type)
				return FALSE;
			else {
				forget_data (self, data);
				g_ptr_array_remove_index_fast (priv->configs, i);
				break;
			}
		}
	}

	data = ip_config_data_new (config, cfg_type, iface);
	g_ptr_array_add (priv->configs, data);
	g_signal_connect (config,
	                  v4 ?
	                    "notify::" NM_IP4_CONFIG_DNS_PRIORITY :
	                    "notify::" NM_IP6_CONFIG_DNS_PRIORITY,
	                  (GCallback) ip_config_dns_priority_changed, self);
	priv->need_sort = TRUE;

	if (cfg_type == NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE) {
		/* Only one best-device per IP version is allowed */
		if (v4) {
			if (priv->best_conf4)
				priv->best_conf4->type = NM_DNS_IP_CONFIG_TYPE_DEFAULT;
			priv->best_conf4 = data;
		} else {
			if (priv->best_conf6)
				priv->best_conf6->type = NM_DNS_IP_CONFIG_TYPE_DEFAULT;
			priv->best_conf6 = data;
		}
	}

	if (!priv->updates_queue && !update_dns (self, FALSE, &error)) {
		_LOGW ("could not commit DNS changes: %s", error->message);
		g_clear_error (&error);
	}

	return TRUE;
}

gboolean
nm_dns_manager_remove_ip_config (NMDnsManager *self, gpointer config)
{
	NMDnsManagerPrivate *priv;
	GError *error = NULL;
	NMDnsIPConfigData *data;
	guint i;

	g_return_val_if_fail (NM_IS_DNS_MANAGER (self), FALSE);
	g_return_val_if_fail (config, FALSE);
	nm_assert (NM_IS_IP_CONFIG (config));

	priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	for (i = 0; i < priv->configs->len; i++) {
		data = priv->configs->pdata[i];

		if (data->config == config) {
			forget_data (self, data);
			g_ptr_array_remove_index (priv->configs, i);

			if (!priv->updates_queue && !update_dns (self, FALSE, &error)) {
				_LOGW ("could not commit DNS changes: %s", error->message);
				g_clear_error (&error);
			}

			return TRUE;
		}
	}
	return FALSE;
}

void
nm_dns_manager_set_initial_hostname (NMDnsManager *self,
                                     const char *hostname)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	g_free (priv->hostname);
	priv->hostname = g_strdup (hostname);
}

void
nm_dns_manager_set_hostname (NMDnsManager *self,
                             const char *hostname,
                             gboolean skip_update)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;
	const char *filtered = NULL;

	/* Certain hostnames we don't want to include in resolv.conf 'searches' */
	if (   hostname
	    && nm_utils_is_specific_hostname (hostname)
	    && !strstr (hostname, ".in-addr.arpa")
	    && strchr (hostname, '.')) {
		filtered = hostname;
	}

	if (   (!priv->hostname && !filtered)
	    || (priv->hostname && filtered && !strcmp (priv->hostname, filtered)))
		return;

	g_free (priv->hostname);
	priv->hostname = g_strdup (filtered);

	if (skip_update)
		return;
	if (!priv->updates_queue && !update_dns (self, FALSE, &error)) {
		_LOGW ("could not commit DNS changes: %s", error->message);
		g_clear_error (&error);
	}
}

gboolean
nm_dns_manager_get_resolv_conf_explicit (NMDnsManager *self)
{
	NMDnsManagerPrivate *priv;

	g_return_val_if_fail (NM_IS_DNS_MANAGER (self), FALSE);

	priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	if (   NM_IN_SET (priv->rc_manager, NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED,
	                                    NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE)
	    || priv->plugin)
		return FALSE;

	return TRUE;
}

void
nm_dns_manager_begin_updates (NMDnsManager *self, const char *func)
{
	NMDnsManagerPrivate *priv;

	g_return_if_fail (self != NULL);
	priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	/* Save current hash when starting a new batch */
	if (priv->updates_queue == 0)
		memcpy (priv->prev_hash, priv->hash, sizeof (priv->hash));

	priv->updates_queue++;

	_LOGD ("(%s): queueing DNS updates (%d)", func, priv->updates_queue);
}

void
nm_dns_manager_end_updates (NMDnsManager *self, const char *func)
{
	NMDnsManagerPrivate *priv;
	GError *error = NULL;
	gboolean changed;
	guint8 new[HASH_LEN];

	g_return_if_fail (self != NULL);

	priv = NM_DNS_MANAGER_GET_PRIVATE (self);
	g_return_if_fail (priv->updates_queue > 0);

	if (priv->need_sort) {
		g_ptr_array_sort (priv->configs, ip_config_data_ptr_compare);
		priv->need_sort = FALSE;
	}

	compute_hash (self, nm_config_data_get_global_dns_config (nm_config_get_data (priv->config)), new);
	changed = (memcmp (new, priv->prev_hash, sizeof (new)) != 0) ? TRUE : FALSE;
	_LOGD ("(%s): DNS configuration %s", func, changed ? "changed" : "did not change");

	priv->updates_queue--;
	if ((priv->updates_queue > 0) || (changed == FALSE)) {
		_LOGD ("(%s): no DNS changes to commit (%d)", func, priv->updates_queue);
		return;
	}

	/* Commit all the outstanding changes */
	_LOGD ("(%s): committing DNS changes (%d)", func, priv->updates_queue);
	if (!update_dns (self, FALSE, &error)) {
		_LOGW ("could not commit DNS changes: %s", error->message);
		g_clear_error (&error);
	}

	memset (priv->prev_hash, 0, sizeof (priv->prev_hash));
}

void
nm_dns_manager_stop (NMDnsManager *self)
{
	NMDnsManagerPrivate *priv;
	GError *error = NULL;

	priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	if (priv->is_stopped)
		g_return_if_reached ();

	_LOGT ("stopping...");

	/* If we're quitting, leave a valid resolv.conf in place, not one
	 * pointing to 127.0.0.1 if dnsmasq was active.  But if we haven't
	 * done any DNS updates yet, there's no reason to touch resolv.conf
	 * on shutdown.
	 */
	if (   priv->dns_touched
	    && priv->plugin
	    && NM_IS_DNS_DNSMASQ (priv->plugin)) {
		if (!update_dns (self, TRUE, &error)) {
			_LOGW ("could not commit DNS changes on shutdown: %s", error->message);
			g_clear_error (&error);
		}
		priv->dns_touched = FALSE;
	}

	priv->is_stopped = TRUE;
}

/*****************************************************************************/

static gboolean
_clear_plugin (NMDnsManager *self)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	if (priv->plugin) {
		g_signal_handlers_disconnect_by_func (priv->plugin, plugin_failed, self);
		g_signal_handlers_disconnect_by_func (priv->plugin, plugin_child_quit, self);
		nm_dns_plugin_stop (priv->plugin);
		g_clear_object (&priv->plugin);
		return TRUE;
	}
	priv->plugin_ratelimit.ts = 0;
	nm_clear_g_source (&priv->plugin_ratelimit.timer);
	return FALSE;
}

static NMDnsManagerResolvConfManager
_check_resconf_immutable (NMDnsManagerResolvConfManager rc_manager)
{
	struct stat st;
	int fd, flags;
	bool immutable = FALSE;

	switch (rc_manager) {
	case NM_DNS_MANAGER_RESOLV_CONF_MAN_UNKNOWN:
	case NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE:
		nm_assert_not_reached ();
		/* fall through */
	case NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED:
		return NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED;
	default:

		if (lstat (_PATH_RESCONF, &st) != 0)
			return rc_manager;

		if (S_ISLNK (st.st_mode)) {
			/* only regular files and directories can have extended file attributes. */
			switch (rc_manager) {
			case NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK:
				/* we don't care whether the link-target is immutable.
				 * If the symlink points to another file, rc-manager=symlink anyway backs off.
				 * Otherwise, we would only check whether our internal resolv.conf is immutable. */
				return NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK;
			case NM_DNS_MANAGER_RESOLV_CONF_MAN_UNKNOWN:
			case NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED:
			case NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE:
				nm_assert_not_reached ();
				/* fall through */
			case NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE:
			case NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF:
			case NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG:
				break;
			}
		}

		fd = open (_PATH_RESCONF, O_RDONLY | O_CLOEXEC);
		if (fd != -1) {
			if (ioctl (fd, FS_IOC_GETFLAGS, &flags) != -1)
				immutable = NM_FLAGS_HAS (flags, FS_IMMUTABLE_FL);
			nm_close (fd);
		}
		return immutable ? NM_DNS_MANAGER_RESOLV_CONF_MAN_IMMUTABLE : rc_manager;
	}
}

static gboolean
_resolvconf_resolved_managed (void)
{
	static const char *const RESOLVED_PATHS[] = {
		"../run/systemd/resolve/stub-resolv.conf",
		"../run/systemd/resolve/resolv.conf",
		"../lib/systemd/resolv.conf",
		"../usr/lib/systemd/resolv.conf",
		"/run/systemd/resolve/stub-resolv.conf",
		"/run/systemd/resolve/resolv.conf",
		"/lib/systemd/resolv.conf",
		"/usr/lib/systemd/resolv.conf",
	};
	struct stat st, st_test;
	guint i;

	if (lstat (_PATH_RESCONF, &st) != 0)
		return FALSE;

	if (S_ISLNK (st.st_mode)) {
		gs_free char *full_path = NULL;
		nm_auto_free char *real_path = NULL;

		/* see if resolv.conf is a symlink with a target that is
		 * exactly like one of the candidates.
		 *
		 * This check will work for symlinks, even if the target
		 * does not exist and realpath() cannot resolve anything.
		 *
		 * We want to handle that, because systemd-resolved might not
		 * have started yet. */
		full_path = g_file_read_link (_PATH_RESCONF, NULL);
		if (nm_utils_strv_find_first ((char **) RESOLVED_PATHS,
		                              G_N_ELEMENTS (RESOLVED_PATHS),
		                              full_path) >= 0)
			return TRUE;

		/* see if resolv.conf is a symlink that resolves exactly one
		 * of the candidate paths.
		 *
		 * This check will work for symlinks that can be resolved
		 * to a realpath, but the actual file might not exist.
		 *
		 * We want to handle that, because systemd-resolved might not
		 * have started yet. */
		real_path = realpath (_PATH_RESCONF, NULL);
		if (nm_utils_strv_find_first ((char **) RESOLVED_PATHS,
		                              G_N_ELEMENTS (RESOLVED_PATHS),
		                              real_path) >= 0)
			return TRUE;

		/* fall-through and resolve the symlink, to check the file
		 * it points to (below).
		 *
		 * This check is the most reliable, but it only works if
		 * systemd-resolved already started and created the file. */
		if (stat (_PATH_RESCONF, &st) != 0)
			return FALSE;
	}

	/* see if resolv.conf resolves to one of the candidate
	 * paths (or whether it is hard-linked). */
	for (i = 0; i < G_N_ELEMENTS (RESOLVED_PATHS); i++) {
		const char *p = RESOLVED_PATHS[i];

		if (   p[0] == '/'
		    && stat (p, &st_test) == 0
		    && st.st_dev == st_test.st_dev
		    && st.st_ino == st_test.st_ino)
			return TRUE;
	}

	return FALSE;
}

static void
init_resolv_conf_mode (NMDnsManager *self, gboolean force_reload_plugin)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);
	NMDnsManagerResolvConfManager rc_manager;
	const char *mode;
	gboolean param_changed = FALSE, plugin_changed = FALSE;

	mode = nm_config_data_get_dns_mode (nm_config_get_data (priv->config));

	if (nm_streq0 (mode, "none"))
		rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED;
	else {
		const char *man;

		rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_UNKNOWN;
		man = nm_config_data_get_rc_manager (nm_config_get_data (priv->config));

again:
		if (!man) {
			/* nop */
		} else if (NM_IN_STRSET (man, "symlink", "none"))
			rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK;
		else if (nm_streq (man, "file"))
			rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_FILE;
		else if (nm_streq (man, "resolvconf"))
			rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF;
		else if (nm_streq (man, "netconfig"))
			rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_NETCONFIG;
		else if (nm_streq (man, "unmanaged"))
			rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED;

		if (rc_manager == NM_DNS_MANAGER_RESOLV_CONF_MAN_UNKNOWN) {
			if (man) {
				_LOGW ("init: unknown resolv.conf manager \"%s\", fallback to \"%s\"",
				       man, ""NM_CONFIG_DEFAULT_MAIN_RC_MANAGER);
			}
			man = ""NM_CONFIG_DEFAULT_MAIN_RC_MANAGER;
			rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_SYMLINK;
			goto again;
		}
	}

	rc_manager = _check_resconf_immutable (rc_manager);

	if (   (!mode && _resolvconf_resolved_managed ())
	    || nm_streq0 (mode, "systemd-resolved")) {
		if (   force_reload_plugin
		    || !NM_IS_DNS_SYSTEMD_RESOLVED (priv->plugin)) {
			_clear_plugin (self);
			priv->plugin = nm_dns_systemd_resolved_new ();
			plugin_changed = TRUE;
		}
		mode = "systemd-resolved";
	} else if (nm_streq0 (mode, "dnsmasq")) {
		if (force_reload_plugin || !NM_IS_DNS_DNSMASQ (priv->plugin)) {
			_clear_plugin (self);
			priv->plugin = nm_dns_dnsmasq_new ();
			plugin_changed = TRUE;
		}
	} else if (nm_streq0 (mode, "unbound")) {
		if (force_reload_plugin || !NM_IS_DNS_UNBOUND (priv->plugin)) {
			_clear_plugin (self);
			priv->plugin = nm_dns_unbound_new ();
			plugin_changed = TRUE;
		}
	} else {
		if (!NM_IN_STRSET (mode, "none", "default")) {
			if (mode)
				_LOGW ("init: unknown dns mode '%s'", mode);
			mode = "default";
		}
		if (_clear_plugin (self))
			plugin_changed = TRUE;
	}

	if (plugin_changed && priv->plugin) {
		g_signal_connect (priv->plugin, NM_DNS_PLUGIN_FAILED, G_CALLBACK (plugin_failed), self);
		g_signal_connect (priv->plugin, NM_DNS_PLUGIN_CHILD_QUIT, G_CALLBACK (plugin_child_quit), self);
	}

	g_object_freeze_notify (G_OBJECT (self));

	if (!nm_streq0 (priv->mode, mode)) {
		g_free (priv->mode);
		priv->mode = g_strdup (mode);
		param_changed = TRUE;
		_notify (self, PROP_MODE);
	}

	if (priv->rc_manager != rc_manager) {
		priv->rc_manager = rc_manager;
		param_changed = TRUE;
		_notify (self, PROP_RC_MANAGER);
	}

	if (param_changed || plugin_changed) {
		_LOGI ("init: dns=%s, rc-manager=%s%s%s%s",
		       mode, _rc_manager_to_string (rc_manager),
		       NM_PRINT_FMT_QUOTED (priv->plugin, ", plugin=",
		                            nm_dns_plugin_get_name (priv->plugin), "", ""));
	}

	g_object_thaw_notify (G_OBJECT (self));
}

static void
config_changed_cb (NMConfig *config,
                   NMConfigData *config_data,
                   NMConfigChangeFlags changes,
                   NMConfigData *old_data,
                   NMDnsManager *self)
{
	GError *error = NULL;

	if (NM_FLAGS_ANY (changes, NM_CONFIG_CHANGE_DNS_MODE |
	                           NM_CONFIG_CHANGE_RC_MANAGER |
	                           NM_CONFIG_CHANGE_CAUSE_SIGHUP |
	                           NM_CONFIG_CHANGE_CAUSE_DNS_FULL)) {
		/* reload the resolv-conf mode also on SIGHUP (when DNS_MODE didn't change).
		 * The reason is, that the configuration also depends on whether resolv.conf
		 * is immutable, thus, without the configuration changing, we always want to
		 * re-configure the mode. */
		init_resolv_conf_mode (self,
		                       NM_FLAGS_ANY (changes,   NM_CONFIG_CHANGE_CAUSE_SIGHUP
		                                              | NM_CONFIG_CHANGE_CAUSE_DNS_FULL));
	}

	if (NM_FLAGS_ANY (changes, NM_CONFIG_CHANGE_CAUSE_SIGHUP |
	                           NM_CONFIG_CHANGE_CAUSE_SIGUSR1 |
	                           NM_CONFIG_CHANGE_CAUSE_DNS_RC |
	                           NM_CONFIG_CHANGE_CAUSE_DNS_FULL |
	                           NM_CONFIG_CHANGE_DNS_MODE |
	                           NM_CONFIG_CHANGE_RC_MANAGER |
	                           NM_CONFIG_CHANGE_GLOBAL_DNS_CONFIG)) {
		if (!update_dns (self, FALSE, &error)) {
			_LOGW ("could not commit DNS changes: %s", error->message);
			g_clear_error (&error);
		}
	}
}

static GVariant *
_get_global_config_variant (NMGlobalDnsConfig *global)
{
	NMGlobalDnsDomain *domain;
	GVariantBuilder builder;
	guint i, num;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));
	num = nm_global_dns_config_get_num_domains (global);
	for (i = 0; i < num; i++) {
		GVariantBuilder conf_builder;
		GVariantBuilder item_builder;
		const char *domain_name;
		const char * const *servers;

		g_variant_builder_init (&conf_builder, G_VARIANT_TYPE ("a{sv}"));

		domain = nm_global_dns_config_get_domain (global, i);
		domain_name = nm_global_dns_domain_get_name (domain);

		if (domain_name && !nm_streq0 (domain_name, "*")) {
			g_variant_builder_init (&item_builder, G_VARIANT_TYPE ("as"));
			g_variant_builder_add (&item_builder,
			                       "s",
			                       domain_name);
			g_variant_builder_add (&conf_builder,
			                       "{sv}",
			                       "domains",
			                       g_variant_builder_end (&item_builder));
		}

		g_variant_builder_init (&item_builder, G_VARIANT_TYPE ("as"));
		for (servers = nm_global_dns_domain_get_servers (domain); *servers; servers++) {
			g_variant_builder_add (&item_builder,
			                       "s",
			                       *servers);
		}
		g_variant_builder_add (&conf_builder,
		                       "{sv}",
		                       "nameservers",
		                       g_variant_builder_end (&item_builder));

		g_variant_builder_add (&conf_builder,
		                       "{sv}",
		                       "priority",
		                       g_variant_new_int32 (NM_DNS_PRIORITY_DEFAULT_NORMAL));

		g_variant_builder_add (&builder, "a{sv}", &conf_builder);
	}

	return g_variant_ref_sink (g_variant_builder_end (&builder));
}

static GVariant *
_get_config_variant (NMDnsManager *self)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);
	NMGlobalDnsConfig *global_config;
	gs_free char *str = NULL;
	GVariantBuilder builder;
	NMConfigData *data;
	guint i, j;

	if (priv->config_variant)
		return priv->config_variant;

	data = nm_config_get_data (priv->config);
	global_config = nm_config_data_get_global_dns_config (data);
	if (global_config) {
		priv->config_variant = _get_global_config_variant (global_config);
		_LOGT ("current configuration: %s", (str = g_variant_print (priv->config_variant, TRUE)));
		return priv->config_variant;
	}

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

	for (i = 0; i < priv->configs->len; i++) {
		NMDnsIPConfigData *current = priv->configs->pdata[i];
		const NMIPConfig *config = current->config;
		GVariantBuilder entry_builder;
		GVariantBuilder strv_builder;
		guint num;
		const int addr_family = nm_ip_config_get_addr_family (config);
		char buf[NM_UTILS_INET_ADDRSTRLEN];
		const NMIPAddr *addr;

		num = nm_ip_config_get_num_nameservers (config);
		if (!num)
			continue;

		g_variant_builder_init (&entry_builder, G_VARIANT_TYPE ("a{sv}"));

		g_variant_builder_init (&strv_builder, G_VARIANT_TYPE ("as"));
		for (j = 0; j < num; j++) {
			addr = nm_ip_config_get_nameserver (config, j);
			g_variant_builder_add (&strv_builder,
			                       "s",
			                       nm_utils_inet_ntop (addr_family, addr, buf));
		}
		g_variant_builder_add (&entry_builder,
		                       "{sv}",
		                       "nameservers",
		                       g_variant_builder_end (&strv_builder));

		num = nm_ip_config_get_num_domains (config);
		if (num > 0) {
			g_variant_builder_init (&strv_builder, G_VARIANT_TYPE ("as"));
			for (j = 0; j < num; j++) {
				g_variant_builder_add (&strv_builder,
				                       "s",
				                       nm_ip_config_get_domain (config, j));
			}
			g_variant_builder_add (&entry_builder,
			                       "{sv}",
			                       "domains",
			                       g_variant_builder_end (&strv_builder));
		}

		if (current->iface) {
			g_variant_builder_add (&entry_builder,
			                       "{sv}",
			                       "interface",
			                       g_variant_new_string (current->iface));
		}

		g_variant_builder_add (&entry_builder,
		                       "{sv}",
		                       "priority",
		                       g_variant_new_int32 (nm_ip_config_get_dns_priority (config)));

		g_variant_builder_add (&entry_builder,
		                       "{sv}",
		                       "vpn",
		                       g_variant_new_boolean (current->type == NM_DNS_IP_CONFIG_TYPE_VPN));

		g_variant_builder_add (&builder, "a{sv}", &entry_builder);
	}

	priv->config_variant = g_variant_ref_sink (g_variant_builder_end (&builder));
	_LOGT ("current configuration: %s", (str = g_variant_print (priv->config_variant, TRUE)));

	return priv->config_variant;
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDnsManager *self = NM_DNS_MANAGER (object);
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_MODE:
		g_value_set_string (value, priv->mode);
		break;
	case PROP_RC_MANAGER:
		g_value_set_string (value, _rc_manager_to_string (priv->rc_manager));
		break;
	case PROP_CONFIGURATION:
		g_value_set_variant (value, _get_config_variant (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_dns_manager_init (NMDnsManager *self)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	_LOGT ("creating...");

	priv->config = g_object_ref (nm_config_get ());
	priv->configs = g_ptr_array_new_full (8, ip_config_data_destroy);

	/* Set the initial hash */
	compute_hash (self, NULL, NM_DNS_MANAGER_GET_PRIVATE (self)->hash);

	g_signal_connect (G_OBJECT (priv->config),
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (config_changed_cb),
	                  self);
	init_resolv_conf_mode (self, TRUE);
}

static void
dispose (GObject *object)
{
	NMDnsManager *self = NM_DNS_MANAGER (object);
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);
	NMDnsIPConfigData *data;
	guint i;

	_LOGT ("disposing");

	if (!priv->is_stopped)
		nm_dns_manager_stop (self);

	_clear_plugin (self);

	if (priv->config) {
		g_signal_handlers_disconnect_by_func (priv->config, config_changed_cb, self);
		g_clear_object (&priv->config);
	}

	if (priv->configs) {
		for (i = 0; i < priv->configs->len; i++) {
			data = priv->configs->pdata[i];
			forget_data (self, data);
		}
		g_ptr_array_free (priv->configs, TRUE);
		priv->configs = NULL;
	}

	nm_clear_g_source (&priv->plugin_ratelimit.timer);

	G_OBJECT_CLASS (nm_dns_manager_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDnsManager *self = NM_DNS_MANAGER (object);
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	g_free (priv->hostname);
	g_free (priv->mode);

	G_OBJECT_CLASS (nm_dns_manager_parent_class)->finalize (object);
}

static void
nm_dns_manager_class_init (NMDnsManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (klass);

	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;

	exported_object_class->export_path = NM_DBUS_PATH "/DnsManager";
	exported_object_class->export_on_construction = TRUE;

	obj_properties[PROP_MODE] =
	    g_param_spec_string (NM_DNS_MANAGER_MODE, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_RC_MANAGER] =
	    g_param_spec_string (NM_DNS_MANAGER_RC_MANAGER, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CONFIGURATION] =
	    g_param_spec_variant (NM_DNS_MANAGER_CONFIGURATION, "", "",
	                          G_VARIANT_TYPE ("aa{sv}"),
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[CONFIG_CHANGED] =
	    g_signal_new (NM_DNS_MANAGER_CONFIG_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DNS_MANAGER_SKELETON,
	                                        NULL);
}

