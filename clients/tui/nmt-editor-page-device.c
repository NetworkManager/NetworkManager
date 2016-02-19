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
 * SECTION:nmt-editor-page-device
 * @short_description: Abstract base class for "device" editor pages
 *
 * #NmtEditorPageDevice is the base class for #NmtEditorPage subclasses
 * representing device-type-specific data. (Eg, #NmtPageEthernet,
 * #NmtPageVlan, etc).
 *
 * FIXME: rename to NmtEditorPageDevice, so it doesn't sound like it's
 * an actual page type.
 */

#include "nm-default.h"

#include "nmt-editor-page-device.h"

G_DEFINE_TYPE (NmtEditorPageDevice, nmt_editor_page_device, NMT_TYPE_EDITOR_PAGE)

#define NMT_EDITOR_PAGE_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_EDITOR_PAGE_DEVICE, NmtEditorPageDevicePrivate))

typedef struct {
	NmtDeviceEntry *device_entry;
	gboolean show_by_default;
} NmtEditorPageDevicePrivate;

enum {
	PROP_0,

	PROP_DEVICE_ENTRY,

	LAST_PROP
};

static void
nmt_editor_page_device_init (NmtEditorPageDevice *device)
{
}

static void
nmt_editor_page_device_finalize (GObject *object)
{
	NmtEditorPageDevicePrivate *priv = NMT_EDITOR_PAGE_DEVICE_GET_PRIVATE (object);

	g_clear_object (&priv->device_entry);

	G_OBJECT_CLASS (nmt_editor_page_device_parent_class)->finalize (object);
}

NmtDeviceEntry *
nmt_editor_page_device_get_device_entry (NmtEditorPageDevice *page)
{
	NmtEditorPageDevicePrivate *priv = NMT_EDITOR_PAGE_DEVICE_GET_PRIVATE (page);

	return priv->device_entry;
}

static void
nmt_editor_page_device_set_property (GObject      *object,
                              guint         prop_id,
                              const GValue *value,
                              GParamSpec   *pspec)
{
	NmtEditorPageDevicePrivate *priv = NMT_EDITOR_PAGE_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_DEVICE_ENTRY:
		priv->device_entry = g_value_dup_object (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_editor_page_device_get_property (GObject    *object,
                              guint       prop_id,
                              GValue     *value,
                              GParamSpec *pspec)
{
	NmtEditorPageDevicePrivate *priv = NMT_EDITOR_PAGE_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_DEVICE_ENTRY:
		g_value_set_object (value, priv->device_entry);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_editor_page_device_class_init (NmtEditorPageDeviceClass *page_device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (page_device_class);

	g_type_class_add_private (page_device_class, sizeof (NmtEditorPageDevicePrivate));

	/* virtual methods */
	object_class->set_property = nmt_editor_page_device_set_property;
	object_class->get_property = nmt_editor_page_device_get_property;
	object_class->finalize     = nmt_editor_page_device_finalize;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_DEVICE_ENTRY,
		 g_param_spec_object ("device-entry", "", "",
		                      NMT_TYPE_DEVICE_ENTRY,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));
}
