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

#include <stdlib.h>
#include <glib.h>

#include "cipher-manager.h"
#include "cipher.h"

struct CipherManager
{
	GSList *	ciphers;
};


/* Singleton instance of the Cipher Manager */
static CipherManager * cipher_manager = NULL;


CipherManager * cipher_manager_get_instance (void)
{
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;

	g_static_mutex_lock (&mutex);
	if (!cipher_manager)
		cipher_manager = g_malloc0 (sizeof (CipherManager));
	g_static_mutex_unlock (&mutex);

	return cipher_manager;
}

int cipher_manager_register_cipher (CipherManager *cm, IEEE_802_11_Cipher *cipher)
{
	g_return_val_if_fail (cm != NULL, -1);
	g_return_val_if_fail (cipher != NULL, -1);

	ieee_802_11_cipher_ref (cipher);
	cm->ciphers = g_slist_prepend (cm->ciphers, cipher);

	return 0;
}
