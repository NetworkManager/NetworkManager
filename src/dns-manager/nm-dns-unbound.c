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
 * Author: Pavel Šimerda <psimerda@redhat.com>
 */
#include "nm-default.h"

#include "nm-dns-unbound.h"
#include "NetworkManagerUtils.h"

G_DEFINE_TYPE (NMDnsUnbound, nm_dns_unbound, NM_TYPE_DNS_PLUGIN)

/*******************************************/

static gboolean
update (NMDnsPlugin *plugin,
        const GSList *vpn_configs,
        const GSList *dev_configs,
        const GSList *other_configs,
        const NMGlobalDnsConfig *global_config,
        const char *hostname)
{
	/* TODO: We currently call a script installed with the dnssec-trigger
	 * package that queries all information itself. Later, the dependency
	 * on that package will be optional and the only hard dependency will
	 * be unbound.
	 *
	 * Unbound configuration should be later handled by this plugin directly,
	 * without calling custom scripts. The dnssec-trigger functionality
	 * may be eventually merged into NetworkManager.
	 */
	return nm_spawn_process (DNSSEC_TRIGGER_SCRIPT " --async --update", NULL) == 0;
}

static gboolean
is_caching (NMDnsPlugin *plugin)
{
	return TRUE;
}

static const char *
get_name (NMDnsPlugin *plugin)
{
	return "unbound";
}

/****************************************************************/

NMDnsPlugin *
nm_dns_unbound_new (void)
{
	return g_object_new (NM_TYPE_DNS_UNBOUND, NULL);
}

static void
nm_dns_unbound_init (NMDnsUnbound *unbound)
{
}

static void
nm_dns_unbound_class_init (NMDnsUnboundClass *klass)
{
	NMDnsPluginClass *plugin_class = NM_DNS_PLUGIN_CLASS (klass);

	plugin_class->update = update;
	plugin_class->is_caching = is_caching;
	plugin_class->get_name = get_name;
}
