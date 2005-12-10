/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <glib.h>
#include <glib/gi18n.h>
#include <string.h>
#include <glade/glade.h>

#include "wireless-security-common.h"
#include "cipher.h"
#include "applet.h"
#include "cipher-wep-passphrase.h"
#include "cipher-wep-hex.h"
#include "cipher-wep-ascii.h"
#include "cipher-wpa-psk-passphrase.h"

static const char * wsm_get_glade_file (WirelessSecurityManager *wsm);
static NMWirelessApplet * wsm_get_applet (WirelessSecurityManager *wsm);


/* Encapsulates and controls a single wireless security option */
struct WirelessSecurityOption
{
	/* Human readable name for the option */
	char *		name;

	/* Corresponding IEEE_802_11_Cipher objects */
	GSList *		ciphers;

	/* Name of the widget for this item */
	const char *	widget_name;

	/* The Glade UI for this option */
	GladeXML *	uixml;
};

struct WirelessSecurityManager
{
	NMWirelessApplet *	applet;
	GSList *			options;
};


static const char * wso_get_name (WirelessSecurityOption * opt)
{
	g_return_val_if_fail (opt != NULL, NULL);

	return opt->name;
}

#define WS_TAG_MAGIC	0xa7f4
#define WS_TAG_NAME		"ws-tag"
static GtkWidget * wso_get_widget (WirelessSecurityOption *opt)
{
	GtkWidget * widget = NULL;

	g_return_val_if_fail (opt != NULL, NULL);

	/* Some options may not have any UI */
	if (opt->uixml)
	{
		widget = glade_xml_get_widget (opt->uixml, opt->widget_name);
		g_object_set_data (G_OBJECT (widget), WS_TAG_NAME, GINT_TO_POINTER (WS_TAG_MAGIC));
	}

	return widget;
}


static void wso_free (WirelessSecurityOption * opt)
{
	g_free (opt->name);
	if (opt->uixml)
		g_object_unref (opt->uixml);
	g_slist_foreach (opt->ciphers, (GFunc) ieee_802_11_cipher_unref, NULL);
	g_slist_free (opt->ciphers);
	memset (opt, 0, sizeof (WirelessSecurityOption));
	g_free (opt);
}


static WirelessSecurityOption * wsm_opt_none_init (WirelessSecurityManager *wsm)
{
	WirelessSecurityOption * opt = NULL;

	g_return_val_if_fail (wsm != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	opt->name = g_strdup (_("None"));
	return opt;
}


static WirelessSecurityOption * wsm_opt_wep_passphrase_init (WirelessSecurityManager *wsm)
{
	WirelessSecurityOption * opt = NULL;
	GladeXML *			xml = NULL;

	g_return_val_if_fail (wsm != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	opt->name = g_strdup (_("WEP Passphrase"));
	opt->widget_name = "wep_key_notebook";

	if (!(opt->uixml = glade_xml_new (wsm_get_glade_file (wsm), "wep_key_notebook", NULL)))
	{
		nmwa_schedule_warning_dialog (wsm_get_applet (wsm),
			_("The NetworkManager Applet could not find some required resources (the glade file was not found)."));
		wso_free (opt);
		return NULL;
	}
	opt->ciphers = g_slist_append (opt->ciphers, cipher_wep128_passphrase_new ());
	return opt;
}


static WirelessSecurityOption * wsm_opt_wep_hex_init (WirelessSecurityManager *wsm)
{
	WirelessSecurityOption * opt = NULL;
	GladeXML *			xml = NULL;

	g_return_val_if_fail (wsm != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	opt->name = g_strdup (_("WEP 40/128-bit hex"));
	opt->widget_name = "wep_key_notebook";

	if (!(opt->uixml = glade_xml_new (wsm_get_glade_file (wsm), "wep_key_notebook", NULL)))
	{
		nmwa_schedule_warning_dialog (wsm_get_applet (wsm),
			_("The NetworkManager Applet could not find some required resources (the glade file was not found)."));
		wso_free (opt);
		return NULL;
	}
	opt->ciphers = g_slist_append (opt->ciphers, cipher_wep128_hex_new ());
	opt->ciphers = g_slist_append (opt->ciphers, cipher_wep64_hex_new ());
	return opt;
}


static WirelessSecurityOption * wsm_opt_wep_ascii_init (WirelessSecurityManager *wsm)
{
	WirelessSecurityOption * opt = NULL;
	GladeXML *			xml = NULL;

	g_return_val_if_fail (wsm != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	opt->name = g_strdup (_("WEP 40/128-bit ASCII"));
	opt->widget_name = "wep_key_notebook";

	if (!(opt->uixml = glade_xml_new (wsm_get_glade_file (wsm), "wep_key_notebook", NULL)))
	{
		nmwa_schedule_warning_dialog (wsm_get_applet (wsm),
			_("The NetworkManager Applet could not find some required resources (the glade file was not found)."));
		wso_free (opt);
		return NULL;
	}
	opt->ciphers = g_slist_append (opt->ciphers, cipher_wep128_ascii_new ());
	opt->ciphers = g_slist_append (opt->ciphers, cipher_wep64_ascii_new ());
	return opt;
}


static WirelessSecurityOption * wsm_opt_wpa_psk_passphrase_init (WirelessSecurityManager *wsm)
{
	WirelessSecurityOption * opt = NULL;
	GladeXML *			xml = NULL;

	g_return_val_if_fail (wsm != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	opt->name = g_strdup (_("WPA Personal Passphrase"));
	opt->widget_name = "wpa_psk_notebook";

	if (!(opt->uixml = glade_xml_new (wsm_get_glade_file (wsm), "wpa_psk_notebook", NULL)))
	{
		nmwa_schedule_warning_dialog (wsm_get_applet (wsm),
			_("The NetworkManager Applet could not find some required resources (the glade file was not found)."));
		wso_free (opt);
		return NULL;
	}
	opt->ciphers = g_slist_append (opt->ciphers, cipher_wpa_psk_passphrase_new ());
	return opt;
}


WirelessSecurityManager * wsm_new (NMWirelessApplet *applet)
{
	WirelessSecurityManager *	wsm = NULL;
	WirelessSecurityOption *		opt;

	g_return_val_if_fail (applet, NULL);

	wsm = g_malloc0 (sizeof (WirelessSecurityManager));
	wsm->applet = applet;

	/* Add the items */
	if ((opt = wsm_opt_none_init (wsm)))
		wsm->options = g_slist_append (wsm->options, opt);

	if ((opt = wsm_opt_wep_passphrase_init (wsm)))
		wsm->options = g_slist_append (wsm->options, opt);

	if ((opt = wsm_opt_wep_hex_init (wsm)))
		wsm->options = g_slist_append (wsm->options, opt);

	if ((opt = wsm_opt_wep_ascii_init (wsm)))
		wsm->options = g_slist_append (wsm->options, opt);

/*
	if ((opt = wsm_opt_wpa_psk_passphrase_init (wsm)))
		wsm->options = g_slist_append (wsm->options, opt);
*/

	return wsm;
}


void wsm_populate_combo (WirelessSecurityManager *wsm, GtkComboBox *combo)
{
	GtkListStore *	model;
	GSList *		elt;

	g_return_if_fail (wsm != NULL);
	g_return_if_fail (combo != NULL);

	model = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_POINTER);

	for (elt = wsm->options; elt; elt = elt->next)
	{
		WirelessSecurityOption * opt = (WirelessSecurityOption *) (elt->data);
		GtkTreeIter			iter;

		g_assert (opt);

		gtk_list_store_append (model, &iter);
		gtk_list_store_set (model, &iter, 0, wso_get_name (opt), 1, opt, -1);
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (model));
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 0);
}


GtkWidget * wsm_get_widget_for_index (WirelessSecurityManager *wsm, guint index)
{
	GtkWidget * widget = NULL;
	WirelessSecurityOption * opt;

	g_return_val_if_fail (wsm != NULL, NULL);
	g_return_val_if_fail (index >= 0, NULL);
	g_return_val_if_fail (index < g_slist_length (wsm->options), NULL);

	if ((opt = g_slist_nth_data (wsm->options, index)))
		widget = wso_get_widget (opt);

	return widget;	
}


gboolean wsm_is_ws_widget (WirelessSecurityManager *wsm, GtkWidget * widget)
{
	gpointer	tag;

	g_return_val_if_fail (wsm != NULL, FALSE);
	g_return_val_if_fail (widget != NULL, FALSE);

	tag = g_object_get_data (G_OBJECT (widget), WS_TAG_NAME);
	if (tag && (GPOINTER_TO_INT (tag) == WS_TAG_MAGIC))
		return TRUE;
	return FALSE;
}

static const char * wsm_get_glade_file (WirelessSecurityManager *wsm)
{
	g_return_val_if_fail (wsm != NULL, NULL);
	g_return_val_if_fail (wsm->applet != NULL, NULL);

	return wsm->applet->glade_file;
}

static NMWirelessApplet * wsm_get_applet (WirelessSecurityManager *wsm)
{
	g_return_val_if_fail (wsm != NULL, NULL);

	return wsm->applet;
}

void wsm_free (WirelessSecurityManager *wsm)
{
	g_return_if_fail (wsm != NULL);

	g_slist_foreach (wsm->options, (GFunc) wso_free, NULL);
	g_slist_free (wsm->options);
	memset (wsm, 0, sizeof (WirelessSecurityManager));
	g_free (wsm);
}
