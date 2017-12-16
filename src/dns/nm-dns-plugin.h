/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
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
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DNS_PLUGIN_H__
#define __NETWORKMANAGER_DNS_PLUGIN_H__

#include "nm-dns-manager.h"
#include "nm-config-data.h"

#define NM_TYPE_DNS_PLUGIN            (nm_dns_plugin_get_type ())
#define NM_DNS_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DNS_PLUGIN, NMDnsPlugin))
#define NM_DNS_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DNS_PLUGIN, NMDnsPluginClass))
#define NM_IS_DNS_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DNS_PLUGIN))
#define NM_IS_DNS_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DNS_PLUGIN))
#define NM_DNS_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DNS_PLUGIN, NMDnsPluginClass))

#define NM_DNS_PLUGIN_FAILED "failed"
#define NM_DNS_PLUGIN_CHILD_QUIT "child-quit"

struct _NMDnsPluginPrivate;

typedef struct {
	GObject parent;
	struct _NMDnsPluginPrivate *_priv;
} NMDnsPlugin;

typedef struct {
	GObjectClass parent;

	/* Methods */

	/* Called when DNS information is changed.  'configs' is an array
	 * of pointers to NMDnsIPConfigData sorted by priority.
	 * 'global_config' is the optional global DNS
	 * configuration.
	 */
	gboolean (*update) (NMDnsPlugin *self,
	                    const NMGlobalDnsConfig *global_config,
	                    const CList *ip_config_lst_head,
	                    const char *hostname);

	/* Subclasses should override and return TRUE if they start a local
	 * caching nameserver that listens on localhost and would block any
	 * other local caching nameserver from operating.
	 */
	gboolean (*is_caching) (NMDnsPlugin *self);

	/* Subclasses should override this and return their plugin name */
	const char *(*get_name) (NMDnsPlugin *self);

	/* Signals */

	/* Emitted by the plugin base class when the nameserver subprocess
	 * quits.  This signal is consumed by the plugin subclasses and not
	 * by NMDnsManager.  If the subclass decides the exit status (as returned
	 * by waitpid(2)) is fatal it should then emit the 'failed' signal.
	 */
	void (*child_quit) (NMDnsPlugin *self, gint status);
} NMDnsPluginClass;

GType nm_dns_plugin_get_type (void);

gboolean nm_dns_plugin_is_caching (NMDnsPlugin *self);

const char *nm_dns_plugin_get_name (NMDnsPlugin *self);

gboolean nm_dns_plugin_update (NMDnsPlugin *self,
                               const NMGlobalDnsConfig *global_config,
                               const CList *ip_config_lst_head,
                               const char *hostname);

void nm_dns_plugin_stop (NMDnsPlugin *self);

/* For subclasses/plugins */

/* Spawn a child process and watch for it to quit.  'argv' is the NULL-terminated
 * argument vector to spawn the child with, where argv[0] is the full path to
 * the child's executable.  If 'pidfile' is given the process owning the PID
 * contained in 'pidfile' will be killed if its command line matches 'kill_match'
 * and the pidfile will be deleted.
 */
GPid nm_dns_plugin_child_spawn (NMDnsPlugin *self,
                                const char **argv,
                                const char *pidfile,
                                const char *kill_match);

GPid nm_dns_plugin_child_pid (NMDnsPlugin *self);

gboolean nm_dns_plugin_child_kill (NMDnsPlugin *self);

#endif /* __NETWORKMANAGER_DNS_PLUGIN_H__ */
