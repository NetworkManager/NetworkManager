// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 * Author: Pavel Šimerda <psimerda@redhat.com>
 */
#include "nm-default.h"

#include "nm-dns-unbound.h"

#include "NetworkManagerUtils.h"

/*****************************************************************************/

struct _NMDnsUnbound {
	NMDnsPlugin parent;
};

struct _NMDnsUnboundClass {
	NMDnsPluginClass parent;
};

G_DEFINE_TYPE (NMDnsUnbound, nm_dns_unbound, NM_TYPE_DNS_PLUGIN)

/*****************************************************************************/

static gboolean
update (NMDnsPlugin *plugin,
        const NMGlobalDnsConfig *global_config,
        const CList *ip_config_lst_head,
        const char *hostname)
{
	char *argv[] = { DNSSEC_TRIGGER_PATH, "--async", "--update", NULL };
	int status;

	/* TODO: We currently call a script installed with the dnssec-trigger
	 * package that queries all information itself. Later, the dependency
	 * on that package will be optional and the only hard dependency will
	 * be unbound.
	 *
	 * Unbound configuration should be later handled by this plugin directly,
	 * without calling custom scripts. The dnssec-trigger functionality
	 * may be eventually merged into NetworkManager.
	 */
	if (!g_spawn_sync ("/", argv, NULL, 0, NULL, NULL, NULL, NULL, &status, NULL))
		return FALSE;
	return (status == 0);
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

/*****************************************************************************/

static void
nm_dns_unbound_init (NMDnsUnbound *unbound)
{
}

NMDnsPlugin *
nm_dns_unbound_new (void)
{
	return g_object_new (NM_TYPE_DNS_UNBOUND, NULL);
}

static void
nm_dns_unbound_class_init (NMDnsUnboundClass *klass)
{
	NMDnsPluginClass *plugin_class = NM_DNS_PLUGIN_CLASS (klass);

	plugin_class->update = update;
	plugin_class->is_caching = is_caching;
	plugin_class->get_name = get_name;
}
