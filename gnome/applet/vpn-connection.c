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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#include <string.h>
#include "vpn-connection.h"


struct VPNConnection
{
	int   refcount;
	char	*name;
	char *user_name;
};


VPNConnection *nmwa_vpn_connection_new (const char *name)
{
	VPNConnection *vpn;

	g_return_val_if_fail (name != NULL, NULL);

	vpn = g_malloc0 (sizeof (VPNConnection));
	vpn->refcount = 1;
	vpn->name = g_strdup (name);

	return vpn;
}


VPNConnection *nmwa_vpn_connection_copy (VPNConnection *src_vpn)
{
	VPNConnection *dst_vpn;

	g_return_val_if_fail (src_vpn != NULL, NULL);

	dst_vpn = g_malloc0 (sizeof (VPNConnection));
	dst_vpn->refcount = 1;
	dst_vpn->name = g_strdup (src_vpn->name);
	dst_vpn->user_name = src_vpn->user_name ? g_strdup (src_vpn->user_name) : NULL;
	
	return dst_vpn;
}


void nmwa_vpn_connection_ref (VPNConnection *vpn)
{
	g_return_if_fail (vpn != NULL);

	vpn->refcount++;
}


void nmwa_vpn_connection_unref (VPNConnection *vpn)
{
	g_return_if_fail (vpn != NULL);

	vpn->refcount--;
	if (vpn->refcount <= 0)
	{
		g_free (vpn->name);
		g_free (vpn->user_name);
		memset (vpn, 0, sizeof (VPNConnection));
		g_free (vpn);
	}
}


const char *nmwa_vpn_connection_get_name (VPNConnection *vpn)
{
	g_return_val_if_fail (vpn != NULL, NULL);

	return vpn->name;
}


const char *nmwa_vpn_connection_get_user_name (VPNConnection *vpn)
{
	g_return_val_if_fail (vpn != NULL, NULL);

	return vpn->user_name;
}


void nmwa_vpn_connection_set_user_name (VPNConnection *vpn, const char *user_name)
{
	g_return_if_fail (vpn != NULL);
	g_return_if_fail (user_name != NULL);

	g_free (vpn->user_name);
	vpn->user_name = g_strdup (user_name);
}



static int is_same_name (VPNConnection *vpn, const char *name)
{
	if (!vpn || !name || !nmwa_vpn_connection_get_name (vpn))
		return -1;

	return strcmp (nmwa_vpn_connection_get_name (vpn), name);
}


VPNConnection *nmwa_vpn_connection_find_by_name (GSList *list, const char *name)
{
	GSList		*elt;
	VPNConnection	*vpn = NULL;

	g_return_val_if_fail (name != NULL, NULL);

	if (!list)
		return NULL;

	if ((elt = g_slist_find_custom (list, name, (GCompareFunc) is_same_name)))
		vpn = elt->data;

	return vpn;	
}


