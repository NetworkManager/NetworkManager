// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nm-l3cfg.h"

#include "platform/nm-platform.h"
#include "platform/nmp-object.h"
#include "nm-netns.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NML3Cfg,
	PROP_NETNS,
	PROP_IFINDEX,
);

typedef struct _NML3CfgPrivate {
	GArray *property_emit_list;
} NML3CfgPrivate;

struct _NML3CfgClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NML3Cfg, nm_l3cfg, G_TYPE_OBJECT)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_CORE
#define _NMLOG_PREFIX_NAME "l3cfg"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        nm_log ((level), (_NMLOG_DOMAIN), NULL, NULL, \
                "l3cfg["NM_HASH_OBFUSCATE_PTR_FMT",ifindex=%d]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                NM_HASH_OBFUSCATE_PTR (self), \
                nm_l3cfg_get_ifindex (self) \
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

/*****************************************************************************/

static void _property_emit_notify (NML3Cfg *self, NML3CfgPropertyEmitType emit_type);

/*****************************************************************************/

static void
_load_link (NML3Cfg *self, gboolean initial)
{
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	const NMPObject *obj;
	const char *ifname;
	const char *ifname_old;

	obj = nm_platform_link_get_obj (self->priv.platform, self->priv.ifindex, TRUE);

	if (   initial
	    && obj == self->priv.pllink)
		return;

	obj_old = g_steal_pointer (&self->priv.pllink);
	self->priv.pllink = nmp_object_ref (obj);

	ifname_old = nmp_object_link_get_ifname (obj_old);
	ifname = nmp_object_link_get_ifname (self->priv.pllink);

	if (initial) {
		_LOGT ("link ifname changed: %s%s%s (initial)",
		        NM_PRINT_FMT_QUOTE_STRING (ifname));
	} else if (!nm_streq0 (ifname, ifname_old)) {
		_LOGT ("link ifname changed: %s%s%s (was %s%s%s)",
		        NM_PRINT_FMT_QUOTE_STRING (ifname),
		        NM_PRINT_FMT_QUOTE_STRING (ifname_old));
	}
}

/*****************************************************************************/

void
_nm_l3cfg_notify_platform_change_on_idle (NML3Cfg *self, guint32 obj_type_flags)
{
	if (NM_FLAGS_ANY (obj_type_flags, nmp_object_type_to_flags (NMP_OBJECT_TYPE_LINK)))
		_load_link (self, FALSE);
	if (NM_FLAGS_ANY (obj_type_flags, nmp_object_type_to_flags (NMP_OBJECT_TYPE_IP4_ROUTE)))
		_property_emit_notify (self, NM_L3CFG_PROPERTY_EMIT_TYPE_IP4_ROUTE);
	if (NM_FLAGS_ANY (obj_type_flags, nmp_object_type_to_flags (NMP_OBJECT_TYPE_IP6_ROUTE)))
		_property_emit_notify (self, NM_L3CFG_PROPERTY_EMIT_TYPE_IP6_ROUTE);
}

/*****************************************************************************/

typedef struct {
	GObject *target_obj;
	const GParamSpec *target_property;
	NML3CfgPropertyEmitType emit_type;
} PropertyEmitData;

static void
_property_emit_notify (NML3Cfg *self, NML3CfgPropertyEmitType emit_type)
{
	gs_free PropertyEmitData *collected_heap = NULL;
	PropertyEmitData *collected = NULL;
	PropertyEmitData *emit_data;
	guint num;
	guint i;
	guint j;

	if (!self->priv.p->property_emit_list)
		return;

	num = 0;
	emit_data = &g_array_index (self->priv.p->property_emit_list, PropertyEmitData, 0);
	for (i = 0; i < self->priv.p->property_emit_list->len; i++, emit_data++) {
		if (emit_data->emit_type == emit_type) {
			collected = emit_data;
			num++;
		}
	}

	if (num == 0)
		return;

	if (num == 1) {
		g_object_notify_by_pspec (collected->target_obj, (GParamSpec *) collected->target_property);
		return;
	}

	if (num < 300u / sizeof (*collected))
		collected = g_alloca (sizeof (PropertyEmitData) * num);
	else {
		collected_heap = g_new (PropertyEmitData, num);
		collected = collected_heap;
	}

	emit_data = &g_array_index (self->priv.p->property_emit_list, PropertyEmitData, 0);
	for (i = 0, j = 0; i < self->priv.p->property_emit_list->len; i++, emit_data++) {
		if (emit_data->emit_type == emit_type) {
			collected[j++] = *emit_data;
			g_object_ref (collected->target_obj);
		}
	}

	nm_assert (j == num);

	for (i = 0; i < num; i++) {
		g_object_notify_by_pspec (collected[i].target_obj, (GParamSpec *) collected[i].target_property);
		if (i > 0)
			g_object_unref (collected[i].target_obj);
	}
}

void
nm_l3cfg_property_emit_register (NML3Cfg *self,
                                 GObject *target_obj,
                                 const GParamSpec *target_property,
                                 NML3CfgPropertyEmitType emit_type)
{
	PropertyEmitData *emit_data;
	guint i;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (G_IS_OBJECT (target_obj));
	nm_assert (target_property);
	nm_assert (NM_IN_SET (emit_type, NM_L3CFG_PROPERTY_EMIT_TYPE_IP4_ROUTE,
	                                 NM_L3CFG_PROPERTY_EMIT_TYPE_IP6_ROUTE));
	nm_assert (target_property == nm_g_object_class_find_property_from_gtype (G_OBJECT_TYPE (target_obj),
	                                                                          target_property->name));

	if (!self->priv.p->property_emit_list)
		self->priv.p->property_emit_list = g_array_new (FALSE, FALSE, sizeof (PropertyEmitData));
	else {
		emit_data = &g_array_index (self->priv.p->property_emit_list, PropertyEmitData, 0);
		for (i = 0; i < self->priv.p->property_emit_list->len; i++, emit_data++) {
			if (   emit_data->target_obj != target_obj
			    || emit_data->target_property != target_property)
				continue;
			nm_assert (emit_data->emit_type == emit_type);
			emit_data->emit_type = emit_type;
			return;
		}
	}

	emit_data = nm_g_array_append_new (self->priv.p->property_emit_list, PropertyEmitData);
	*emit_data = (PropertyEmitData) {
		.target_obj      = target_obj,
		.target_property = target_property,
		.emit_type       = emit_type,
	};
}

void
nm_l3cfg_property_emit_unregister (NML3Cfg *self,
                                   GObject *target_obj,
                                   const GParamSpec *target_property)
{
	PropertyEmitData *emit_data;
	guint i;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (G_IS_OBJECT (target_obj));
	nm_assert (   !target_property
	           || target_property == nm_g_object_class_find_property_from_gtype (G_OBJECT_TYPE (target_obj),
	                                                                             target_property->name));

	if (!self->priv.p->property_emit_list)
		return;

	for (i = self->priv.p->property_emit_list->len; i > 0; i--) {
		emit_data = &g_array_index (self->priv.p->property_emit_list, PropertyEmitData, i);

		if (emit_data->target_obj != target_obj)
			continue;
		if (   target_property
		    && emit_data->target_property != target_property)
			continue;

		g_array_remove_index_fast (self->priv.p->property_emit_list, i);

		if (target_property) {
			/* if a target-property is given, we don't have another entry in
			 * the list. */
			return;
		}
	}
}

/*****************************************************************************/

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	NML3Cfg *self = NM_L3CFG (object);

	switch (prop_id) {
	case PROP_NETNS:
		/* construct-only */
		self->priv.netns = g_object_ref (g_value_get_pointer (value));
		nm_assert (NM_IS_NETNS (self->priv.netns));
		break;
	case PROP_IFINDEX:
		/* construct-only */
		self->priv.ifindex = g_value_get_int (value);
		nm_assert (self->priv.ifindex > 0);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_l3cfg_init (NML3Cfg *self)
{
	NML3CfgPrivate *p;

	p = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_L3CFG, NML3CfgPrivate);

	self->priv.p = p;
}

static void
constructed (GObject *object)
{
	NML3Cfg *self = NM_L3CFG (object);

	nm_assert (NM_IS_NETNS (self->priv.netns));
	nm_assert (self->priv.ifindex > 0);

	self->priv.platform = g_object_ref (nm_netns_get_platform (self->priv.netns));
	nm_assert (NM_IS_PLATFORM (self->priv.platform));

	_LOGT ("created (netns="NM_HASH_OBFUSCATE_PTR_FMT")",
	       NM_HASH_OBFUSCATE_PTR (self->priv.netns));

	G_OBJECT_CLASS (nm_l3cfg_parent_class)->constructed (object);

	_load_link (self, TRUE);
}

NML3Cfg *
nm_l3cfg_new (NMNetns *netns, int ifindex)
{
	nm_assert (NM_IS_NETNS (netns));
	nm_assert (ifindex > 0);

	return g_object_new (NM_TYPE_L3CFG,
	                     NM_L3CFG_NETNS, netns,
	                     NM_L3CFG_IFINDEX, ifindex,
	                     NULL);
}

static void
finalize (GObject *object)
{
	NML3Cfg *self = NM_L3CFG (object);

	nm_assert (nm_g_array_len (self->priv.p->property_emit_list) == 0u);

	g_clear_object (&self->priv.netns);
	g_clear_object (&self->priv.platform);

	nm_clear_pointer (&self->priv.pllink, nmp_object_unref);

	_LOGT ("finalized");

	G_OBJECT_CLASS (nm_l3cfg_parent_class)->finalize (object);
}

static void
nm_l3cfg_class_init (NML3CfgClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NML3CfgPrivate));

	object_class->set_property = set_property;
	object_class->constructed  = constructed;
	object_class->finalize     = finalize;

	obj_properties[PROP_NETNS] =
	    g_param_spec_pointer (NM_L3CFG_NETNS, "", "",
	                          G_PARAM_WRITABLE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_IFINDEX] =
	     g_param_spec_int (NM_L3CFG_IFINDEX, "", "",
	                       0,
	                       G_MAXINT,
	                       0,
	                       G_PARAM_WRITABLE |
	                       G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
