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
 * Copyright (C) 2004 - 2010 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <ctype.h>
#include <arpa/inet.h>

#include <glib.h>

#include "nm-logging.h"
#include "nm-policy-hostname.h"
#include "nm-policy-hosts.h"

/************************************************************************/

struct HostnameThread {
	GThread *thread;

	GMutex *lock;
	gboolean dead;
	int ret;

	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	struct sockaddr *addr;
	size_t addr_size;
	char hostname[NI_MAXHOST + 1];

	HostnameThreadCallback callback;
	gpointer user_data;
};

static gboolean
hostname_thread_run_cb (gpointer user_data)
{
	HostnameThread *ht = (HostnameThread *) user_data;
	const char *hostname = NULL;

	if (strlen (ht->hostname) && strcmp (ht->hostname, "."))
		hostname = ht->hostname;

	nm_log_dbg (LOGD_DNS, "(%p) calling address reverse-lookup result handler", ht);
	(*ht->callback) (ht, ht->ret, hostname, ht->user_data);
	return FALSE;
}

static gpointer
hostname_thread_worker (gpointer data)
{
	HostnameThread *ht = (HostnameThread *) data;
	int i;

	nm_log_dbg (LOGD_DNS, "(%p) starting address reverse-lookup", ht);

	g_mutex_lock (ht->lock);
	if (ht->dead) {
		g_mutex_unlock (ht->lock);
		return (gpointer) NULL;
	}
	g_mutex_unlock (ht->lock);

	ht->ret = getnameinfo (ht->addr, ht->addr_size, ht->hostname, NI_MAXHOST, NULL, 0, NI_NAMEREQD);
	if (ht->ret == 0) {
		nm_log_dbg (LOGD_DNS, "(%p) address reverse-lookup returned hostname '%s'",
		            ht, ht->hostname);
		for (i = 0; i < strlen (ht->hostname); i++)
			ht->hostname[i] = tolower (ht->hostname[i]);
	} else {
		nm_log_dbg (LOGD_DNS, "(%p) address reverse-lookup failed: (%d) %s",
		            ht, ht->ret, gai_strerror (ht->ret));
	}

	/* Don't track the idle handler ID because by the time the g_idle_add()
	 * returns the ID, the handler may already have run and freed the
	 * HostnameThread.
	 */
	nm_log_dbg (LOGD_DNS, "(%p) scheduling address reverse-lookup result handler", ht);
	g_idle_add (hostname_thread_run_cb, ht);
	return (gpointer) TRUE;
}

void
hostname_thread_free (HostnameThread *ht)
{
	g_return_if_fail (ht != NULL);

	nm_log_dbg (LOGD_DNS, "(%p) freeing reverse-lookup thread", ht);

	g_mutex_free (ht->lock);
	memset (ht, 0, sizeof (HostnameThread));
	g_free (ht);
}

HostnameThread *
hostname4_thread_new (guint32 ip4_addr,
                      HostnameThreadCallback callback,
                      gpointer user_data)
{
	HostnameThread *ht;
	struct sockaddr_in addr4;
	char buf[INET_ADDRSTRLEN + 1];

	ht = g_malloc0 (sizeof (HostnameThread));
	g_assert (ht);

	ht->lock = g_mutex_new ();
	ht->callback = callback;
	ht->user_data = user_data;

	ht->addr4.sin_family = AF_INET;
	ht->addr4.sin_addr.s_addr = ip4_addr;
	ht->addr = (struct sockaddr *) &ht->addr4;
	ht->addr_size = sizeof (ht->addr4);

	ht->thread = g_thread_create (hostname_thread_worker, ht, FALSE, NULL);
	if (!ht->thread) {
		hostname_thread_free (ht);
		return NULL;
	}

	if (!inet_ntop (AF_INET, &addr4.sin_addr, buf, sizeof (buf)))
		strcpy (buf, "(unknown)");

	nm_log_dbg (LOGD_DNS, "(%p) started IPv4 reverse-lookup thread for address '%s'",
	            ht, buf);

	return ht;
}

HostnameThread *
hostname6_thread_new (const struct in6_addr *ip6_addr,
                      HostnameThreadCallback callback,
                      gpointer user_data)
{
	HostnameThread *ht;
	char buf[INET6_ADDRSTRLEN + 1];

	ht = g_malloc0 (sizeof (HostnameThread));
	g_assert (ht);

	ht->lock = g_mutex_new ();
	ht->callback = callback;
	ht->user_data = user_data;

	ht->addr6.sin6_family = AF_INET6;
	ht->addr6.sin6_addr = *ip6_addr;
	ht->addr = (struct sockaddr *) &ht->addr6;
	ht->addr_size = sizeof (ht->addr6);

	ht->thread = g_thread_create (hostname_thread_worker, ht, FALSE, NULL);
	if (!ht->thread) {
		hostname_thread_free (ht);
		return NULL;
	}

	if (!inet_ntop (AF_INET, ip6_addr, buf, sizeof (buf)))
		strcpy (buf, "(unknown)");

	nm_log_dbg (LOGD_DNS, "(%p) started IPv6 reverse-lookup thread for address '%s'",
	            ht, buf);

	return ht;
}

void
hostname_thread_kill (HostnameThread *ht)
{
	g_return_if_fail (ht != NULL);

	nm_log_dbg (LOGD_DNS, "(%p) stopping reverse-lookup thread", ht);

	g_mutex_lock (ht->lock);
	ht->dead = TRUE;
	g_mutex_unlock (ht->lock);
}

gboolean
hostname_thread_is_dead (HostnameThread *ht)
{
	g_return_val_if_fail (ht != NULL, TRUE);

	return ht->dead;
}

/************************************************************************/

#define FALLBACK_HOSTNAME4 "localhost.localdomain"
#define FALLBACK_HOSTNAME6 "localhost6.localdomain6"

gboolean
nm_policy_set_system_hostname (const char *new_hostname,
                               const char *ip4_addr,
                               const char *ip6_addr,
                               const char *msg)
{
	char old_hostname[HOST_NAME_MAX + 1];
	int ret = 0;
	const char *name;
	gboolean set_hostname = TRUE, changed = FALSE;

	if (new_hostname)
		g_warn_if_fail (strlen (new_hostname));

	name = (new_hostname && strlen (new_hostname)) ? new_hostname : FALLBACK_HOSTNAME4;

	old_hostname[HOST_NAME_MAX] = '\0';
	errno = 0;
	ret = gethostname (old_hostname, HOST_NAME_MAX);
	if (ret != 0) {
		nm_log_warn (LOGD_DNS, "couldn't get the system hostname: (%d) %s",
		             errno, strerror (errno));
	} else {
		/* Don't set the hostname if it isn't actually changing */
		if (   (new_hostname && !strcmp (old_hostname, new_hostname))
		    || (!new_hostname && !strcmp (old_hostname, FALLBACK_HOSTNAME4)))
			set_hostname = FALSE;
	}

	if (set_hostname) {
		nm_log_info (LOGD_DNS, "Setting system hostname to '%s' (%s)", name, msg);
		ret = sethostname (name, strlen (name));
		if (ret != 0) {
			nm_log_warn (LOGD_DNS, "couldn't set the system hostname to '%s': (%d) %s",
			             name, errno, strerror (errno));
			return FALSE;
		}
	}

	/* But even if the hostname isn't changing, always try updating /etc/hosts
	 * just in case the hostname changed while NM wasn't running; we need to
	 * make sure that /etc/hosts has valid mappings for '127.0.0.1' and the
	 * current system hostname.  If those exist,
	 * nm_policy_hosts_update_etc_hosts() will just return and won't touch
	 * /etc/hosts at all.
	 */
	if (!nm_policy_hosts_update_etc_hosts (name,
	                                       FALLBACK_HOSTNAME4,
	                                       FALLBACK_HOSTNAME6,
	                                       ip4_addr,
	                                       ip6_addr,
	                                       &changed)) {
		/* error updating /etc/hosts; fallback to localhost.localdomain */
		nm_log_info (LOGD_DNS, "Setting system hostname to '" FALLBACK_HOSTNAME4 "' (error updating /etc/hosts)");
		ret = sethostname (FALLBACK_HOSTNAME4, strlen (FALLBACK_HOSTNAME4));
		if (ret != 0) {
			nm_log_warn (LOGD_DNS, "couldn't set the fallback system hostname (%s): (%d) %s",
			             FALLBACK_HOSTNAME4, errno, strerror (errno));
		}
	}

	return changed;
}

