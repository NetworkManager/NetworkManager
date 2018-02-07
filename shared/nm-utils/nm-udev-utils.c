/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-udev-utils.c - udev utils functions
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-udev-utils.h"

#include <libudev.h>

struct _NMPUdevClient {
	char **subsystems;
	GSource *watch_source;
	struct udev *udev;
	struct udev_monitor *monitor;
	NMUdevClientEvent event_handler;
	gpointer event_user_data;
};

/*****************************************************************************/

gboolean
nm_udev_utils_property_as_boolean (const char *uproperty)
{
	/* taken from g_udev_device_get_property_as_boolean() */

	if (uproperty) {
		if (   strcmp (uproperty, "1") == 0
		    || g_ascii_strcasecmp (uproperty, "true") == 0)
			return TRUE;
	}
	return FALSE;
}

const char *
nm_udev_utils_property_decode (const char *uproperty, char **to_free)
{
	const char *p;
	char *unescaped = NULL;
	char *n = NULL;

	if (!uproperty) {
		*to_free = NULL;
		return NULL;
	}

	p = uproperty;
	while (*p) {
		int a, b;

		if (   p[0] == '\\'
		    && p[1] == 'x'
		    && (a = g_ascii_xdigit_value (p[2])) >= 0
		    && (b = g_ascii_xdigit_value (p[3])) >= 0
		    && (a || b)) {
			if (!n) {
				gssize l = p - uproperty;

				unescaped = g_malloc (l + strlen (p) + 1 - 3);
				memcpy (unescaped, uproperty, l);
				n = &unescaped[l];
			}
			*n++ = (a << 4) | b;
			p += 4;
		} else {
			if (n)
				*n++ = *p;
			p++;
		}
	}

	if (!n) {
		*to_free = NULL;
		return uproperty;
	}

	*n++ = '\0';
	return (*to_free = unescaped);
}

char *
nm_udev_utils_property_decode_cp (const char *uproperty)
{
	char *cpy;

	uproperty = nm_udev_utils_property_decode (uproperty, &cpy);
	return cpy ?: g_strdup (uproperty);
}

/*****************************************************************************/

static void
_subsystem_split (const char *subsystem_full,
                  const char **out_subsystem,
                  const char **out_devtype,
                  char **to_free)
{
	char *tmp, *s;

	nm_assert (subsystem_full);
	nm_assert (out_subsystem);
	nm_assert (out_devtype);
	nm_assert (to_free);

	s = strstr (subsystem_full, "/");
	if (s) {
		tmp = g_strdup (subsystem_full);
		s = &tmp[s - subsystem_full];
		*s = '\0';
		*out_subsystem = tmp;
		*out_devtype = &s[1];
		*to_free = tmp;
	} else {
		*out_subsystem = subsystem_full;
		*out_devtype = NULL;
		*to_free = NULL;
	}
}

static struct udev_enumerate *
nm_udev_utils_enumerate (struct udev *uclient,
                         const char *const*subsystems)
{
	struct udev_enumerate *enumerate;
	guint n;

	enumerate = udev_enumerate_new (uclient);

	if (subsystems) {
		for (n = 0; subsystems[n]; n++) {
			const char *subsystem;
			const char *devtype;
			gs_free char *to_free = NULL;

			_subsystem_split (subsystems[n], &subsystem, &devtype, &to_free);

			udev_enumerate_add_match_subsystem (enumerate, subsystem);

			if (devtype != NULL)
				udev_enumerate_add_match_property (enumerate, "DEVTYPE", devtype);
		}
	}

	return enumerate;
}

struct udev *
nm_udev_client_get_udev (NMUdevClient *self)
{
	g_return_val_if_fail (self, NULL);

	return self->udev;
}

struct udev_enumerate *
nm_udev_client_enumerate_new (NMUdevClient *self)
{
	g_return_val_if_fail (self, NULL);

	return nm_udev_utils_enumerate (self->udev, (const char *const*) self->subsystems);
}

/*****************************************************************************/

static gboolean
monitor_event (GIOChannel *source,
               GIOCondition condition,
               gpointer user_data)
{
	NMUdevClient *self = user_data;
	struct udev_device *udevice;

	if (!self->monitor)
		goto out;

	udevice = udev_monitor_receive_device (self->monitor);
	if (udevice == NULL)
		goto out;

	self->event_handler (self,
	                     udevice,
	                     self->event_user_data);
	udev_device_unref (udevice);

out:
	return TRUE;
}

/**
 * nm_udev_client_new:
 * @subsystems: the subsystems
 * @event_handler: callback for events
 * @event_user_data: user-data for @event_handler
 *
 * Basically, it is g_udev_client_new(), and most notably
 * g_udev_client_constructed().
 *
 * Returns: a new NMUdevClient instance.
 */
NMUdevClient *
nm_udev_client_new (const char *const*subsystems,
                    NMUdevClientEvent event_handler,
                    gpointer event_user_data)
{
	NMUdevClient *self;
	GIOChannel *channel;
	guint n;

	self = g_slice_new0 (NMUdevClient);

	self->event_handler = event_handler;
	self->event_user_data = event_user_data;
	self->subsystems = subsystems && subsystems[0] ? g_strdupv ((char **) subsystems) : NULL;

	self->udev = udev_new ();
	if (!self->udev)
		goto fail;

	/* connect to event source */
	if (self->event_handler) {
		self->monitor = udev_monitor_new_from_netlink (self->udev, "udev");
		if (!self->monitor)
			goto fail;

		if (self->subsystems) {
			/* install subsystem filters to only wake up for certain events */
			for (n = 0; self->subsystems[n]; n++) {
				if (self->monitor) {
					gs_free char *to_free = NULL;
					const char *subsystem;
					const char *devtype;

					_subsystem_split (self->subsystems[n], &subsystem, &devtype, &to_free);
					udev_monitor_filter_add_match_subsystem_devtype (self->monitor, subsystem, devtype);
				}
			}

			/* listen to events, and buffer them */
			if (self->monitor) {
				udev_monitor_enable_receiving (self->monitor);
				channel = g_io_channel_unix_new (udev_monitor_get_fd (self->monitor));
				self->watch_source = g_io_create_watch (channel, G_IO_IN);
				g_io_channel_unref (channel);
				g_source_set_callback (self->watch_source, (GSourceFunc)(void (*) (void)) monitor_event, self, NULL);
				g_source_attach (self->watch_source, g_main_context_get_thread_default ());
				g_source_unref (self->watch_source);
			}
		}
	}

	return self;

fail:
	return nm_udev_client_unref (self);
}

NMUdevClient *
nm_udev_client_unref (NMUdevClient *self)
{
	if (!self)
		return NULL;

	if (self->watch_source) {
		g_source_destroy (self->watch_source);
		self->watch_source = NULL;
	}

	udev_monitor_unref (self->monitor);
	self->monitor = NULL;
	udev_unref (self->udev);
	self->udev = NULL;

	g_strfreev (self->subsystems);

	g_slice_free (NMUdevClient, self);

	return NULL;
}
