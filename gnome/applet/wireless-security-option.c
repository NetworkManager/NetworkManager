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

#include "wireless-security-option.h"

#include "cipher.h"
#include "cipher-wep-passphrase.h"
#include "cipher-wep-hex.h"
#include "cipher-wep-ascii.h"
#include "cipher-wpa-psk-passphrase.h"

#define WS_TAG_MAGIC	0xa7f4
#define WS_TAG_NAME		"ws-tag"

struct WirelessSecurityOption
{
	/* Human readable name for the option */
	char *		name;

	/* Corresponding IEEE_802_11_Cipher objects */
	GSList *		ciphers;

	/* Name of the widget for this item */
	const char *	widget_name;

	/* Notebook widget (once created) for this option */
	GtkWidget *	widget;

	/* The Glade UI for this option */
	GladeXML *	uixml;

	/* Glade object names for sub-widgets */
	GSList *		subwidget_names;
};

gboolean wso_is_wso_widget (GtkWidget * widget)
{
	gpointer	tag;

	g_return_val_if_fail (widget != NULL, FALSE);

	tag = g_object_get_data (G_OBJECT (widget), WS_TAG_NAME);
	if (tag && (GPOINTER_TO_INT (tag) == WS_TAG_MAGIC))
		return TRUE;
	return FALSE;
}


WirelessSecurityOption * wso_none_new (const char *glade_file)
{
	WirelessSecurityOption * opt = NULL;

	g_return_val_if_fail (glade_file != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	opt->name = g_strdup (_("None"));
	return opt;
}


WirelessSecurityOption * wso_wep_passphrase_new (const char *glade_file)
{
	WirelessSecurityOption * opt = NULL;
	GladeXML *			xml = NULL;

	g_return_val_if_fail (glade_file != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	opt->name = g_strdup (_("WEP Passphrase"));
	opt->widget_name = "wep_passphrase_notebook";
	opt->subwidget_names = g_slist_append (opt->subwidget_names, "wep_passphrase_entry");

	if (!(opt->uixml = glade_xml_new (glade_file, opt->widget_name, NULL)))
	{
		wso_free (opt);
		return NULL;
	}
	opt->ciphers = g_slist_append (opt->ciphers, cipher_wep128_passphrase_new ());
	return opt;
}


WirelessSecurityOption * wso_wep_hex_new (const char *glade_file)
{
	WirelessSecurityOption * opt = NULL;
	GladeXML *			xml = NULL;

	g_return_val_if_fail (glade_file != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	opt->name = g_strdup (_("WEP 40/128-bit hex"));
	opt->widget_name = "wep_key_notebook";
	opt->subwidget_names = g_slist_append (opt->subwidget_names, "wep_key_entry");

	if (!(opt->uixml = glade_xml_new (glade_file, opt->widget_name, NULL)))
	{
		wso_free (opt);
		return NULL;
	}
	opt->ciphers = g_slist_append (opt->ciphers, cipher_wep128_hex_new ());
	opt->ciphers = g_slist_append (opt->ciphers, cipher_wep64_hex_new ());
	return opt;
}


WirelessSecurityOption * wso_wep_ascii_new (const char *glade_file)
{
	WirelessSecurityOption * opt = NULL;
	GladeXML *			xml = NULL;

	g_return_val_if_fail (glade_file != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	opt->name = g_strdup (_("WEP 40/128-bit ASCII"));
	opt->widget_name = "wep_key_notebook";
	opt->subwidget_names = g_slist_append (opt->subwidget_names, "wep_key_entry");

	if (!(opt->uixml = glade_xml_new (glade_file, opt->widget_name, NULL)))
	{
		wso_free (opt);
		return NULL;
	}
	opt->ciphers = g_slist_append (opt->ciphers, cipher_wep128_ascii_new ());
	opt->ciphers = g_slist_append (opt->ciphers, cipher_wep64_ascii_new ());
	return opt;
}


WirelessSecurityOption * wso_wpa_psk_passphrase_new (const char *glade_file)
{
	WirelessSecurityOption * opt = NULL;
	GladeXML *			xml = NULL;

	g_return_val_if_fail (glade_file != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	opt->name = g_strdup (_("WPA Personal Passphrase"));
	opt->widget_name = "wpa_psk_notebook";
	opt->subwidget_names = g_slist_append (opt->subwidget_names, "wpa_psk_entry");

	if (!(opt->uixml = glade_xml_new (glade_file, opt->widget_name, NULL)))
	{
		wso_free (opt);
		return NULL;
	}
	opt->ciphers = g_slist_append (opt->ciphers, cipher_wpa_psk_passphrase_new ());
	return opt;
}


const char * wso_get_name (WirelessSecurityOption * opt)
{
	g_return_val_if_fail (opt != NULL, NULL);

	return opt->name;
}


GtkWidget * wso_get_widget (WirelessSecurityOption * opt)
{
	g_return_val_if_fail (opt != NULL, NULL);

	/* Some options may not have any UI */
	if (!opt->widget && opt->uixml)
	{
		opt->widget = glade_xml_get_widget (opt->uixml, opt->widget_name);
		g_object_ref (G_OBJECT (opt->widget));
		g_object_set_data (G_OBJECT (opt->widget), WS_TAG_NAME, GINT_TO_POINTER (WS_TAG_MAGIC));
	}

	return opt->widget;
}


gboolean wso_validate_input (WirelessSecurityOption * opt)
{
	g_return_val_if_fail (opt != NULL, FALSE);

	return TRUE;
}


void wso_free (WirelessSecurityOption * opt)
{
	g_free (opt->name);
	if (opt->uixml)
		g_object_unref (opt->uixml);
	if (opt->widget)
		g_object_unref (opt->widget);
	g_slist_foreach (opt->ciphers, (GFunc) ieee_802_11_cipher_unref, NULL);
	g_slist_free (opt->ciphers);
	memset (opt, 0, sizeof (WirelessSecurityOption));
	g_free (opt);
}

