/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

/**
 * SECTION:nmt-page-device
 * @short_description: Abstract base class for "device" editor pages
 *
 * #NmtPageDevice is the base class for #NmtEditorPage subclasses
 * representing device-type-specific data. (Eg, #NmtPageEthernet,
 * #NmtPageVlan, etc).
 *
 * FIXME: rename to NmtEditorPageDevice, so it doesn't sound like it's
 * an actual page type.
 */

#include "config.h"

#include "nmt-page-device.h"

G_DEFINE_TYPE (NmtPageDevice, nmt_page_device, NMT_TYPE_EDITOR_PAGE)

#define NMT_PAGE_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_PAGE_DEVICE, NmtPageDevicePrivate))

typedef struct {
	NmtDeviceEntry *device_entry;
	gboolean show_by_default;
} NmtPageDevicePrivate;

enum {
	PROP_0,

	PROP_DEVICE_ENTRY,
	PROP_SHOW_BY_DEFAULT,

	LAST_PROP
};

static void
nmt_page_device_init (NmtPageDevice *device)
{
}

static void
nmt_page_device_finalize (GObject *object)
{
	NmtPageDevicePrivate *priv = NMT_PAGE_DEVICE_GET_PRIVATE (object);

	g_clear_object (&priv->device_entry);

	G_OBJECT_CLASS (nmt_page_device_parent_class)->finalize (object);
}

NmtDeviceEntry *
nmt_page_device_get_device_entry (NmtPageDevice *page)
{
	NmtPageDevicePrivate *priv = NMT_PAGE_DEVICE_GET_PRIVATE (page);

	return priv->device_entry;
}

gboolean
nmt_page_device_get_show_by_default (NmtPageDevice *page)
{
	NmtPageDevicePrivate *priv = NMT_PAGE_DEVICE_GET_PRIVATE (page);

	return priv->show_by_default;
}

static void
nmt_page_device_set_property (GObject      *object,
                              guint         prop_id,
                              const GValue *value,
                              GParamSpec   *pspec)
{
	NmtPageDevicePrivate *priv = NMT_PAGE_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_DEVICE_ENTRY:
		priv->device_entry = g_value_dup_object (value);
		break;
	case PROP_SHOW_BY_DEFAULT:
		priv->show_by_default = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_page_device_get_property (GObject    *object,
                              guint       prop_id,
                              GValue     *value,
                              GParamSpec *pspec)
{
	NmtPageDevicePrivate *priv = NMT_PAGE_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_DEVICE_ENTRY:
		g_value_set_object (value, priv->device_entry);
		break;
	case PROP_SHOW_BY_DEFAULT:
		g_value_set_boolean (value, priv->show_by_default);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_page_device_class_init (NmtPageDeviceClass *page_device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (page_device_class);

	g_type_class_add_private (page_device_class, sizeof (NmtPageDevicePrivate));

	/* virtual methods */
	object_class->set_property = nmt_page_device_set_property;
	object_class->get_property = nmt_page_device_get_property;
	object_class->finalize     = nmt_page_device_finalize;

	/* properties */
	g_object_class_install_property (object_class, PROP_DEVICE_ENTRY,
	                                 g_param_spec_object ("device-entry", "", "",
	                                                      NMT_TYPE_DEVICE_ENTRY,
	                                                      G_PARAM_READWRITE |
	                                                      G_PARAM_CONSTRUCT_ONLY |
	                                                      G_PARAM_STATIC_STRINGS));
	g_object_class_install_property (object_class, PROP_SHOW_BY_DEFAULT,
	                                 g_param_spec_boolean ("show-by-default", "", "",
	                                                       TRUE,
	                                                       G_PARAM_READWRITE |
	                                                       G_PARAM_CONSTRUCT_ONLY |
	                                                       G_PARAM_STATIC_STRINGS));
}
