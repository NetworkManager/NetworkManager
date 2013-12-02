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
 * SECTION:nmt-password-fields
 * @short_description: Widgets for password-related data
 *
 * #NmtPasswordFields provides an entry to type a password into, followed
 * optionally by an "Ask for this password every time" checkbox and/or a
 * "Show password" checkbox that toggles whether the password is visible.
 */

#include "config.h"

#include <glib/gi18n-lib.h>

#include "nmt-password-fields.h"

G_DEFINE_TYPE (NmtPasswordFields, nmt_password_fields, NMT_TYPE_NEWT_GRID)

#define NMT_PASSWORD_FIELDS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_PASSWORD_FIELDS, NmtPasswordFieldsPrivate))

typedef struct {
	NmtPasswordFieldsExtras extras;

	NmtNewtEntry *entry;
	NmtNewtCheckbox *always_ask;
	NmtNewtCheckbox *show_password;

	char *init_password;

} NmtPasswordFieldsPrivate;

enum {
	PROP_0,
	PROP_WIDTH,
	PROP_EXTRAS,
	PROP_PASSWORD,
	PROP_ALWAYS_ASK,
	PROP_SHOW_PASSWORD,

	LAST_PROP
};

/**
 * NmtPasswordFieldsExtras:
 * @NMT_PASSWORD_FIELDS_ALWAYS_ASK: show an "Always ask" checkbox
 * @NMT_PASSWORD_FIELDS_SHOW_PASSWORD: show a "Show password" checkbox
 *
 * Extra widgets to include in an #NmtPasswordFields
 */

/**
 * nmt_password_fields_new:
 * @width: width in characters of the password entry
 * @extras: extra widgets to show
 *
 * Creates a new #NmtPasswordFields
 *
 * Returns: a new #NmtPasswordFields
 */
NmtNewtWidget *
nmt_password_fields_new (int                     width,
                         NmtPasswordFieldsExtras extras)
{
	return g_object_new (NMT_TYPE_PASSWORD_FIELDS,
	                     "width", width,
	                     "extras", extras,
	                     NULL);
}

static void
nmt_password_fields_set_password (NmtPasswordFields *fields,
                                  const char        *password)
{
	NmtPasswordFieldsPrivate *priv = NMT_PASSWORD_FIELDS_GET_PRIVATE (fields);

	if (!g_strcmp0 (password, nmt_newt_entry_get_text (priv->entry)))
		return;

	nmt_newt_entry_set_text (priv->entry, password);
	g_object_notify (G_OBJECT (fields), "password");
}

static const char *
nmt_password_fields_get_password (NmtPasswordFields *fields)
{
	NmtPasswordFieldsPrivate *priv = NMT_PASSWORD_FIELDS_GET_PRIVATE (fields);

	return nmt_newt_entry_get_text (priv->entry);
}

static void
always_ask_changed (GObject    *object,
                    GParamSpec *pspec,
                    gpointer    fields)
{
	g_object_notify (fields, "always-ask");
}

static void
show_password_changed (GObject    *object,
                       GParamSpec *pspec,
                       gpointer    fields)
{
	g_object_notify (fields, "show-password");
}

static void
nmt_password_fields_init (NmtPasswordFields *fields)
{
	NmtPasswordFieldsPrivate *priv = NMT_PASSWORD_FIELDS_GET_PRIVATE (fields);

	priv->entry = NMT_NEWT_ENTRY (nmt_newt_entry_new (-1, 0));
	priv->always_ask = NMT_NEWT_CHECKBOX (nmt_newt_checkbox_new (_("Ask for this password every time")));
	priv->show_password = NMT_NEWT_CHECKBOX (nmt_newt_checkbox_new (_("Show password")));
}

static void
nmt_password_fields_constructed (GObject *object)
{
	NmtPasswordFieldsPrivate *priv = NMT_PASSWORD_FIELDS_GET_PRIVATE (object);
	NmtNewtGrid *grid = NMT_NEWT_GRID (object);

	nmt_newt_grid_add (grid, NMT_NEWT_WIDGET (priv->entry), 0, 0);

	if (priv->extras & NMT_PASSWORD_FIELDS_ALWAYS_ASK) {
		nmt_newt_grid_add (grid, NMT_NEWT_WIDGET (priv->always_ask), 0, 1);
		g_signal_connect (priv->always_ask, "notify::active",
		                  G_CALLBACK (always_ask_changed), object);
	} else
		g_clear_object (&priv->always_ask);

	if (priv->extras & NMT_PASSWORD_FIELDS_SHOW_PASSWORD) {
		nmt_newt_grid_add (grid, NMT_NEWT_WIDGET (priv->show_password), 0, 2);
		g_signal_connect (priv->show_password, "notify::active",
		                  G_CALLBACK (show_password_changed), object);
		g_object_bind_property (priv->show_password, "active",
		                        priv->entry, "password",
		                        G_BINDING_INVERT_BOOLEAN | G_BINDING_SYNC_CREATE);
	} else
		g_clear_object (&priv->show_password);

	G_OBJECT_CLASS (nmt_password_fields_parent_class)->constructed (object);
}

static void
nmt_password_fields_finalize (GObject *object)
{
	NmtPasswordFieldsPrivate *priv = NMT_PASSWORD_FIELDS_GET_PRIVATE (object);

	if (priv->always_ask) {
		g_signal_handlers_disconnect_by_func (priv->always_ask,
		                                      G_CALLBACK (always_ask_changed), object);
	}
	if (priv->show_password) {
		g_signal_handlers_disconnect_by_func (priv->show_password,
		                                      G_CALLBACK (show_password_changed), object);
	}

	G_OBJECT_CLASS (nmt_password_fields_parent_class)->finalize (object);
}

static void
nmt_password_fields_set_property (GObject      *object,
                                  guint         prop_id,
                                  const GValue *value,
                                  GParamSpec   *pspec)
{
	NmtPasswordFields *fields = NMT_PASSWORD_FIELDS (object);
	NmtPasswordFieldsPrivate *priv = NMT_PASSWORD_FIELDS_GET_PRIVATE (fields);

	switch (prop_id) {
	case PROP_WIDTH:
		nmt_newt_entry_set_width (priv->entry, g_value_get_int (value));
		break;
	case PROP_EXTRAS:
		priv->extras = g_value_get_uint (value);
		nmt_newt_widget_needs_rebuild (NMT_NEWT_WIDGET (fields));
		break;
	case PROP_PASSWORD:
		nmt_password_fields_set_password (fields, g_value_get_string (value));
		break;
	case PROP_ALWAYS_ASK:
		if (priv->always_ask)
			nmt_newt_checkbox_set_active (priv->always_ask, g_value_get_boolean (value));
		break;
	case PROP_SHOW_PASSWORD:
		if (priv->show_password)
			nmt_newt_checkbox_set_active (priv->show_password, g_value_get_boolean (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_password_fields_get_property (GObject    *object,
                                  guint       prop_id,
                                  GValue     *value,
                                  GParamSpec *pspec)
{
	NmtPasswordFields *entry = NMT_PASSWORD_FIELDS (object);
	NmtPasswordFieldsPrivate *priv = NMT_PASSWORD_FIELDS_GET_PRIVATE (entry);

	switch (prop_id) {
	case PROP_WIDTH:
		g_value_set_int (value, nmt_newt_entry_get_width (priv->entry));
		break;
	case PROP_EXTRAS:
		g_value_set_uint (value, priv->extras);
		break;
	case PROP_PASSWORD:
		g_value_set_string (value, nmt_password_fields_get_password (entry));
		break;
	case PROP_ALWAYS_ASK:
		if (priv->always_ask)
			g_value_set_boolean (value, nmt_newt_checkbox_get_active (priv->always_ask));
		break;
	case PROP_SHOW_PASSWORD:
		if (priv->show_password)
			g_value_set_boolean (value, nmt_newt_checkbox_get_active (priv->show_password));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_password_fields_class_init (NmtPasswordFieldsClass *entry_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (entry_class);

	g_type_class_add_private (entry_class, sizeof (NmtPasswordFieldsPrivate));

	/* virtual methods */
	object_class->constructed  = nmt_password_fields_constructed;
	object_class->set_property = nmt_password_fields_set_property;
	object_class->get_property = nmt_password_fields_get_property;
	object_class->finalize     = nmt_password_fields_finalize;

	/**
	 * NmtPasswordFields:width:
	 *
	 * The width in characters of the password entry
	 */
	g_object_class_install_property (object_class, PROP_WIDTH,
	                                 g_param_spec_int ("width", "", "",
	                                                   -1, 80, -1,
	                                                   G_PARAM_READWRITE |
	                                                   G_PARAM_STATIC_STRINGS));
	/**
	 * NmtPasswordFields:extras:
	 *
	 * The extra widgets to show
	 */
	g_object_class_install_property (object_class, PROP_EXTRAS,
	                                 g_param_spec_uint ("extras", "", "",
	                                                    0, 0xFFFF, 0,
	                                                    G_PARAM_READWRITE |
	                                                    G_PARAM_CONSTRUCT_ONLY |
	                                                    G_PARAM_STATIC_STRINGS));
	/**
	 * NmtPasswordFields:password:
	 *
	 * The entered password.
	 */
	g_object_class_install_property (object_class, PROP_PASSWORD,
	                                 g_param_spec_string ("password", "", "",
	                                                      NULL,
	                                                      G_PARAM_READWRITE |
	                                                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtPasswordFields:always-ask:
	 *
	 * The current state of the "Always ask" checkbox.
	 */
	g_object_class_install_property (object_class, PROP_ALWAYS_ASK,
	                                 g_param_spec_boolean ("always-ask", "", "",
	                                                       FALSE,
	                                                       G_PARAM_READWRITE |
	                                                       G_PARAM_STATIC_STRINGS));
	/**
	 * NmtPasswordFields:show-password:
	 *
	 * The current state of the "Show password" checkbox.
	 */
	g_object_class_install_property (object_class, PROP_SHOW_PASSWORD,
	                                 g_param_spec_boolean ("show-password", "", "",
	                                                       FALSE,
	                                                       G_PARAM_READWRITE |
	                                                       G_PARAM_STATIC_STRINGS));
}
