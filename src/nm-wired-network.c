/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include "nm-wired-network.h"

G_DEFINE_TYPE (NMWiredNetwork, nm_wired_network, G_TYPE_OBJECT)

#define NM_WIRED_NETWORK_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_WIRED_NETWORK, NMWiredNetworkPrivate))

typedef struct {
	char *network_id;
	NMAPSecurity *security;
} NMWiredNetworkPrivate;

NMWiredNetwork *
nm_wired_network_new (const char *network_id, NMAPSecurity *security)
{
	NMWiredNetwork *wired_net;
	NMWiredNetworkPrivate *priv;

	g_return_val_if_fail (network_id != NULL, NULL);
	g_return_val_if_fail (security != NULL, NULL);

	wired_net = (NMWiredNetwork *) g_object_new (NM_TYPE_WIRED_NETWORK, NULL);
	if (!wired_net)
		return NULL;

	priv = NM_WIRED_NETWORK_GET_PRIVATE (wired_net);
	priv->network_id = g_strdup (network_id);
	priv->security = g_object_ref (security);

	return wired_net;
}

const char *
nm_wired_network_get_network_id (NMWiredNetwork *net)
{
	g_return_val_if_fail (NM_IS_WIRED_NETWORK (net), NULL);

	return NM_WIRED_NETWORK_GET_PRIVATE (net)->network_id;
}

NMAPSecurity *
nm_wired_network_get_security (NMWiredNetwork *net)
{
	g_return_val_if_fail (NM_IS_WIRED_NETWORK (net), NULL);

	return NM_WIRED_NETWORK_GET_PRIVATE (net)->security;
}

void
nm_wired_network_set_security (NMWiredNetwork *net, NMAPSecurity *security)
{
	NMWiredNetworkPrivate *priv;

	g_return_if_fail (NM_IS_WIRED_NETWORK (net));

	priv = NM_WIRED_NETWORK_GET_PRIVATE (net);
	if (priv->security)
		g_object_unref (priv->security);

	priv->security = security ? g_object_ref (security) : NULL;
}


static void
nm_wired_network_init (NMWiredNetwork *wired_net)
{
}

static void
finalize (GObject *object)
{
	NMWiredNetworkPrivate *priv = NM_WIRED_NETWORK_GET_PRIVATE (object);

	g_free (priv->network_id);
	g_object_unref (priv->security);

	G_OBJECT_CLASS (nm_wired_network_parent_class)->finalize (object);
}

static void
nm_wired_network_class_init (NMWiredNetworkClass *wired_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (wired_class);

	g_type_class_add_private (wired_class, sizeof (NMWiredNetworkPrivate));

	object_class->finalize = finalize;
}
