/* menu-info.c - Class to represent the 
 *
 * Jonathan Blandford <jrb@redhat.com>
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
 * This also uses code from eel-vfs-extentions available under the LGPL:
 *     Authors: Darin Adler <darin@eazel.com>
 * 	    Pavel Cisler <pavel@eazel.com>
 * 	    Mike Fleming  <mfleming@eazel.com>
 *          John Sullivan <sullivan@eazel.com>
 *
 * (C) Copyright 2004 Red Hat, Inc.
 * Copyright (C) 1999, 2000 Eazel, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <glib/gi18n.h>
#include <string.h>

#include "menu-info.h"
#include "NMWirelessAppletDbus.h"


/****************************************************************
 *   Wired menu item
 ****************************************************************/

struct NMWiredMenuItem
{
	GtkCheckMenuItem	*check_item;
	GtkLabel			*label;
};


NMWiredMenuItem *wired_menu_item_new (void)
{
	NMWiredMenuItem	*item = g_malloc0 (sizeof (NMWiredMenuItem));

	g_return_val_if_fail (item != NULL, NULL);

	item->check_item = GTK_CHECK_MENU_ITEM (gtk_check_menu_item_new ());
	item->label = GTK_LABEL (gtk_label_new (NULL));
	gtk_misc_set_alignment (GTK_MISC (item->label), 0.0, 0.5);
	gtk_container_add (GTK_CONTAINER (item->check_item), GTK_WIDGET (item->label));
	gtk_widget_show (GTK_WIDGET (item->label));

	return item;
}

GtkCheckMenuItem *wired_menu_item_get_check_item (NMWiredMenuItem *item)
{
	g_return_val_if_fail (item != NULL, NULL);

	return item->check_item;
}

void wired_menu_item_update (NMWiredMenuItem *item, NetworkDevice *dev, const gint n_devices)
{
	gchar *text;
	gchar *dev_name;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (item != NULL);
	g_assert (dev->type == DEVICE_TYPE_WIRED_ETHERNET);

	dev_name = dev->hal_name ? dev->hal_name : dev->nm_name;

	if (n_devices > 1)
		text = g_strdup_printf (_("Wired Network (%s)"), dev_name);
	else
		text = g_strdup (_("Wired Network"));

	gtk_label_set_text (GTK_LABEL (item->label), text);

	/* Only dim the item if the device supports carrier detection AND
	 * we know it doesn't have a link.
	 */
	if (dev->driver_support_level != NM_DRIVER_NO_CARRIER_DETECT)
		gtk_widget_set_sensitive (GTK_WIDGET (item->check_item), dev->link);
}


/****************************************************************
 *   Wireless menu item
 ****************************************************************/

struct NMWirelessMenuItem
{
	GtkMenuItem	*menu_item;
	GtkLabel		*label;
};


static gboolean label_expose (GtkWidget *widget)
{
	/* Bad hack to make the label draw normally, instead of insensitive. */
	widget->state = GTK_STATE_NORMAL;
  
	return FALSE;
}

NMWirelessMenuItem *wireless_menu_item_new (void)
{
	NMWirelessMenuItem	*item = g_malloc0 (sizeof (NMWirelessMenuItem));

	g_return_val_if_fail (item != NULL, NULL);

	item->menu_item = GTK_MENU_ITEM (gtk_menu_item_new ());

	/* Make sure it looks slightly different if the label determines the width of the widget */
	item->label = GTK_LABEL (gtk_label_new (NULL));
	gtk_misc_set_padding (GTK_MISC (item->label), 6, 0);
	g_signal_connect (G_OBJECT (item->label), "expose-event", G_CALLBACK (label_expose), NULL);

	gtk_container_add (GTK_CONTAINER (item->menu_item), GTK_WIDGET (item->label));
	gtk_widget_show (GTK_WIDGET (item->label));

	gtk_widget_set_sensitive (GTK_WIDGET (item->menu_item), FALSE);

	return item;
}

GtkMenuItem *wireless_menu_item_get_item (NMWirelessMenuItem *item)
{
	g_return_val_if_fail (item != NULL, NULL);

	return item->menu_item;
}

void wireless_menu_item_update (NMWirelessMenuItem *item, NetworkDevice *dev, const gint n_devices)
{
	char *text;
	const char *dev_name;
	gint n_essids;

	n_essids = g_slist_length (dev->networks);
	dev_name = dev->hal_name ? dev->hal_name : dev->nm_name;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (item != NULL);
	g_assert (dev->type == DEVICE_TYPE_WIRELESS_ETHERNET);

	if (n_devices > 1)
		text = g_strdup_printf (ngettext ("Wireless Network (%s)", "Wireless Networks (%s)", n_essids), dev_name);
	else
		text = g_strdup (ngettext ("Wireless Network", "Wireless Networks", n_essids));

	gtk_label_set_markup (GTK_LABEL (item->label), text);
	g_free (text);
}


/****************************************************************
 *   Wireless Network menu item
 ****************************************************************/

struct NMNetworkMenuItem
{
	GtkCheckMenuItem	*check_item;
	GtkLabel			*label;
	GtkWidget			*progress;
	GtkWidget			*security_image;
};


NMNetworkMenuItem *network_menu_item_new (GtkSizeGroup *encryption_size_group)
{
	GtkWidget			*hbox;
	NMNetworkMenuItem	*item = g_malloc0 (sizeof (NMNetworkMenuItem));
	PangoFontDescription *fontdesc;
	PangoFontMetrics *metrics;
	PangoContext *context;
	PangoLanguage *lang;
	int ascent;	

	g_return_val_if_fail (item != NULL, NULL);

	item->check_item = GTK_CHECK_MENU_ITEM (gtk_check_menu_item_new ());
	gtk_check_menu_item_set_draw_as_radio (item->check_item, TRUE);

	hbox = gtk_hbox_new (FALSE, 6);
	item->label = GTK_LABEL (gtk_label_new (NULL));
	gtk_misc_set_alignment (GTK_MISC (item->label), 0.0, 0.5);

	item->security_image = gtk_image_new ();
	gtk_size_group_add_widget (encryption_size_group, item->security_image);

	gtk_container_add (GTK_CONTAINER (item->check_item), hbox);
	gtk_box_pack_start (GTK_BOX (hbox), GTK_WIDGET (item->label), TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (hbox), item->security_image, FALSE, FALSE, 0);

	item->progress = gtk_progress_bar_new ();
	
	/* get the font ascent for the current font and language */
	context = gtk_widget_get_pango_context (item->progress);
	fontdesc = pango_context_get_font_description (context);
	lang = pango_context_get_language (context);
	metrics = pango_context_get_metrics (context, fontdesc, lang);
	ascent = pango_font_metrics_get_ascent (metrics) * 1.5 / PANGO_SCALE;
	pango_font_metrics_unref (metrics);

	/* size our progress bar to be five ascents long, one high */
	gtk_widget_set_size_request (item->progress, ascent * 5, -1);

	gtk_box_pack_end (GTK_BOX (hbox), item->progress, FALSE, TRUE, 0);

	gtk_widget_show (GTK_WIDGET (item->label));
	gtk_widget_show (item->progress);
	gtk_widget_show (hbox);

	return item;
}

GtkCheckMenuItem *network_menu_item_get_check_item (NMNetworkMenuItem *item)
{
	g_return_val_if_fail (item != NULL, NULL);

	return item->check_item;
}

/* has_encrypted means that the wireless network has an encrypted
 * area, and thus we need to allow for spacing.
 */
void network_menu_item_update (NMNetworkMenuItem *item, WirelessNetwork *network, const gboolean is_encrypted)
{
	char *display_essid;
	gdouble percent;

	g_return_if_fail (item != NULL);
	g_return_if_fail (network != NULL);

	display_essid = nm_menu_network_escape_essid_for_display (network->essid);
	gtk_label_set_text (GTK_LABEL (item->label), display_essid);
	g_free (display_essid);

	percent = (double) CLAMP (network->strength, 0, 100) / 100.0;
	gtk_progress_set_percentage (GTK_PROGRESS (item->progress), percent);

	/* Deal with the encrypted icon */
	g_object_set (item->security_image, "visible", is_encrypted, NULL);

	if (network->encrypted)
		gtk_image_set_from_stock (GTK_IMAGE (item->security_image), "gnome-lockscreen", GTK_ICON_SIZE_MENU);
	else
		gtk_image_set_from_stock (GTK_IMAGE (item->security_image), NULL, GTK_ICON_SIZE_MENU);
}




/****************************************************************
 *   Utility stuff
 ****************************************************************/

/* This is copied from eel.
 */
static char *eel_make_valid_utf8 (const char *name)
{
	GString *string;
	const char *remainder, *invalid;
	int remaining_bytes, valid_bytes;

	string = NULL;
	remainder = name;
	remaining_bytes = strlen (name);

	while (remaining_bytes != 0) {
		if (g_utf8_validate (remainder, remaining_bytes, &invalid)) {
			break;
		}
		valid_bytes = invalid - remainder;

		if (string == NULL) {
			string = g_string_sized_new (remaining_bytes);
		}
		g_string_append_len (string, remainder, valid_bytes);
		g_string_append_c (string, '?');

		remaining_bytes -= valid_bytes + 1;
		remainder = invalid + 1;
	}

	if (string == NULL) {
		return g_strdup (name);
	}

	g_string_append (string, remainder);
	g_string_append (string, _(" (invalid Unicode)"));
	g_assert (g_utf8_validate (string->str, -1, NULL));

	return g_string_free (string, FALSE);
}

char *nm_menu_network_escape_essid_for_display (const char *essid)
{
	if (g_utf8_validate (essid, -1, NULL))
		return g_strdup (essid);
	else
		return eel_make_valid_utf8 (essid);
}
