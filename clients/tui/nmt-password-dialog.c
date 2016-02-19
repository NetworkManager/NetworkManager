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
 * SECTION:nmt-password-dialog
 * @short_description: A password dialog
 *
 * #NmtPasswordDialog is the password dialog used to get connection
 * secrets when activating a connection.
 */

#include "nm-default.h"

#include "nmt-password-dialog.h"
#include "nm-secret-agent-simple.h"
#include "nmtui.h"

G_DEFINE_TYPE (NmtPasswordDialog, nmt_password_dialog, NMT_TYPE_NEWT_FORM)

#define NMT_PASSWORD_DIALOG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NMT_TYPE_PASSWORD_DIALOG, NmtPasswordDialogPrivate))

typedef struct {
	char *request_id;
	char *prompt;
	GPtrArray *secrets;
	GPtrArray *entries;

	NmtNewtWidget *ok, *cancel;
	NmtNewtWidget *last_entry;
	NmtNewtWidget *secret_grid;

	gboolean succeeded;
} NmtPasswordDialogPrivate;

enum {
	PROP_0,
	PROP_REQUEST_ID,
	PROP_PROMPT,
	PROP_SECRETS,

	LAST_PROP
};

/**
 * nmt_password_dialog_new:
 * @request_id: the request ID from the #NMSecretAgentSimple
 * @title: the dialog title
 * @prompt: the prompt text to display
 * @secrets: (element-type #NMSecretAgentSimpleSecret): the secrets requested
 *
 * Creates a new #NmtPasswordDialog to request passwords from
 * the user.
 *
 * Returns: a new #NmtPasswordDialog.
 */
NmtNewtForm *
nmt_password_dialog_new (const char *request_id,
                         const char *title,
                         const char *prompt,
                         GPtrArray  *secrets)
{
	return g_object_new (NMT_TYPE_PASSWORD_DIALOG,
	                     "request-id", request_id,
	                     "title", title,
	                     "prompt", prompt,
	                     "secrets", secrets,
	                     "escape-exits", TRUE,
	                     NULL);
}

static void
nmt_password_dialog_init (NmtPasswordDialog *dialog)
{
	NmtPasswordDialogPrivate *priv = NMT_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	priv->entries = g_ptr_array_new ();
}

static void
maybe_save_input_and_exit (NmtNewtWidget *widget,
                           gpointer       dialog)
{
	NmtPasswordDialogPrivate *priv = NMT_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	int i;

	/* This gets invoked when the user types Return in the final entry,
	 * but the form may not be fully valid in that case.
	 */
	if (!nmt_newt_widget_get_valid (priv->secret_grid))
		return;

	priv->succeeded = TRUE;

	for (i = 0; i < priv->secrets->len; i++) {
		NMSecretAgentSimpleSecret *secret = priv->secrets->pdata[i];

		g_free (secret->value);
		g_object_get (priv->entries->pdata[i], "text", &secret->value, NULL);
	}

	nmt_newt_form_quit (nmt_newt_widget_get_form (widget));
}

static void
nmt_password_dialog_constructed (GObject *object)
{
	NmtPasswordDialog *dialog = NMT_PASSWORD_DIALOG (object);
	NmtPasswordDialogPrivate *priv = NMT_PASSWORD_DIALOG_GET_PRIVATE (dialog);
	NmtNewtWidget *widget;
	NmtNewtGrid *grid, *secret_grid;
	NmtNewtButtonBox *bbox;
	int i;

	widget = nmt_newt_grid_new ();
	nmt_newt_form_set_content (NMT_NEWT_FORM (dialog), widget);
	grid = NMT_NEWT_GRID (widget);

	widget = nmt_newt_textbox_new (0, 60);
	nmt_newt_textbox_set_text (NMT_NEWT_TEXTBOX (widget), priv->prompt);
	nmt_newt_grid_add (grid, widget, 0, 0);

	widget = nmt_newt_grid_new ();
	nmt_newt_grid_add (grid, widget, 0, 1);
	nmt_newt_widget_set_padding (widget, 0, 1, 0, 1);
	priv->secret_grid = widget;
	secret_grid = NMT_NEWT_GRID (widget);

	for (i = 0; i < priv->secrets->len; i++) {
		NMSecretAgentSimpleSecret *secret = priv->secrets->pdata[i];
		NmtNewtEntryFlags flags;

		widget = nmt_newt_label_new (secret->name);
		nmt_newt_grid_add (secret_grid, widget, 0, i);
		nmt_newt_widget_set_padding (widget, 4, 0, 1, 0);

		flags = NMT_NEWT_ENTRY_NONEMPTY;
		if (secret->password)
			flags |= NMT_NEWT_ENTRY_PASSWORD;
		widget = nmt_newt_entry_new (30, flags);
		if (secret->value)
			nmt_newt_entry_set_text (NMT_NEWT_ENTRY (widget), secret->value);
		nmt_newt_grid_add (secret_grid, widget, 1, i);
		g_ptr_array_add (priv->entries, widget);

		if (i == priv->secrets->len - 1) {
			priv->last_entry = widget;
			g_signal_connect (widget, "activated",
			                  G_CALLBACK (maybe_save_input_and_exit), dialog);
		}
	}

	widget = nmt_newt_button_box_new (NMT_NEWT_BUTTON_BOX_HORIZONTAL);
	nmt_newt_grid_add (grid, widget, 0, 2);
	bbox = NMT_NEWT_BUTTON_BOX (widget);

	priv->cancel = nmt_newt_button_box_add_end (NMT_NEWT_BUTTON_BOX (bbox), _("Cancel"));
	nmt_newt_widget_set_exit_on_activate (priv->cancel, TRUE);

	priv->ok = nmt_newt_button_box_add_end (NMT_NEWT_BUTTON_BOX (bbox), _("OK"));
	g_signal_connect (priv->ok, "activated",
	                  G_CALLBACK (maybe_save_input_and_exit), dialog);
	g_object_bind_property (priv->secret_grid, "valid",
	                        priv->ok, "sensitive",
	                        G_BINDING_SYNC_CREATE);

	G_OBJECT_CLASS (nmt_password_dialog_parent_class)->constructed (object);
}

static void
nmt_password_dialog_finalize (GObject *object)
{
	NmtPasswordDialogPrivate *priv = NMT_PASSWORD_DIALOG_GET_PRIVATE (object);

	g_free (priv->request_id);
	g_free (priv->prompt);
	g_clear_pointer (&priv->entries, g_ptr_array_unref);
	g_clear_pointer (&priv->secrets, g_ptr_array_unref);

	G_OBJECT_CLASS (nmt_password_dialog_parent_class)->finalize (object);
}

static void
nmt_password_dialog_set_property (GObject      *object,
                                  guint         prop_id,
                                  const GValue *value,
                                  GParamSpec   *pspec)
{
	NmtPasswordDialogPrivate *priv = NMT_PASSWORD_DIALOG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_REQUEST_ID:
		priv->request_id = g_value_dup_string (value);
		break;
	case PROP_PROMPT:
		priv->prompt = g_value_dup_string (value);
		break;
	case PROP_SECRETS:
		priv->secrets = g_value_dup_boxed (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_password_dialog_get_property (GObject    *object,
                                  guint       prop_id,
                                  GValue     *value,
                                  GParamSpec *pspec)
{
	NmtPasswordDialogPrivate *priv = NMT_PASSWORD_DIALOG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_REQUEST_ID:
		g_value_set_string (value, priv->request_id);
		break;
	case PROP_PROMPT:
		g_value_set_string (value, priv->prompt);
		break;
	case PROP_SECRETS:
		g_value_set_boxed (value, priv->secrets);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nmt_password_dialog_class_init (NmtPasswordDialogClass *dialog_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (dialog_class);

	g_type_class_add_private (dialog_class, sizeof (NmtPasswordDialogPrivate));

	/* virtual methods */
	object_class->constructed  = nmt_password_dialog_constructed;
	object_class->set_property = nmt_password_dialog_set_property;
	object_class->get_property = nmt_password_dialog_get_property;
	object_class->finalize     = nmt_password_dialog_finalize;

	/**
	 * NmtPasswordDialog:request-id:
	 *
	 * The request ID from the #NMSecretAgentSimple
	 */
	g_object_class_install_property
		(object_class, PROP_REQUEST_ID,
		 g_param_spec_string ("request-id", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtPasswordDialog:prompt:
	 *
	 * The prompt text.
	 */
	g_object_class_install_property
		(object_class, PROP_PROMPT,
		 g_param_spec_string ("prompt", "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));
	/**
	 * NmtPasswordDialog:secrets:
	 *
	 * The array of request secrets
	 *
	 * Element-Type: #NMSecretAgentSimpleSecret.
	 */
	g_object_class_install_property
		(object_class, PROP_SECRETS,
		 g_param_spec_boxed ("secrets", "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READWRITE |
		                     G_PARAM_CONSTRUCT_ONLY |
		                     G_PARAM_STATIC_STRINGS));
}

/**
 * nmt_password_dialog_succeeded:
 * @dialog: the #NmtPasswordDialog
 *
 * After the dialog has exited, returns %TRUE if the user clicked
 * "OK", %FALSE if "Cancel".
 *
 * Returns: whether the dialog succeeded.
 */
gboolean
nmt_password_dialog_succeeded (NmtPasswordDialog *dialog)
{
	NmtPasswordDialogPrivate *priv = NMT_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	return priv->succeeded;
}

/**
 * nmt_password_dialog_get_request_id:
 * @dialog: the #NmtPasswordDialog
 *
 * Gets the dialog's request ID.
 *
 * Returns: the dialog's request ID.
 */
const char *
nmt_password_dialog_get_request_id (NmtPasswordDialog *dialog)
{
	NmtPasswordDialogPrivate *priv = NMT_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	return priv->request_id;
}

/**
 * nmt_password_dialog_get_secrets:
 * @dialog: the #NmtPasswordDialog
 *
 * Gets the dialog's secrets array.
 *
 * Returns: (transfer none): the dialog's secrets array.
 */
GPtrArray *
nmt_password_dialog_get_secrets (NmtPasswordDialog *dialog)
{
	NmtPasswordDialogPrivate *priv = NMT_PASSWORD_DIALOG_GET_PRIVATE (dialog);

	return priv->secrets;
}
