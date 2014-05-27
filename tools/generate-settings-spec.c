/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2009 - 2013 Red Hat, Inc.
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <glib.h>
#include <dbus/dbus-glib.h>
#include "config.h"

#include <nm-setting.h>
#include <nm-setting-8021x.h>
#include <nm-setting-adsl.h>
#include <nm-setting-bluetooth.h>
#include <nm-setting-bond.h>
#include <nm-setting-bridge.h>
#include <nm-setting-bridge-port.h>
#include <nm-setting-cdma.h>
#include <nm-setting-connection.h>
#include <nm-setting-dcb.h>
#include <nm-setting-gsm.h>
#include <nm-setting-infiniband.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-olpc-mesh.h>
#include <nm-setting-ppp.h>
#include <nm-setting-pppoe.h>
#include <nm-setting-serial.h>
#include <nm-setting-team.h>
#include <nm-setting-team-port.h>
#include <nm-setting-vlan.h>
#include <nm-setting-vpn.h>
#include <nm-setting-wimax.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>

#include <nm-utils.h>

typedef NMSetting* (*SettingNewFunc) (void);

static SettingNewFunc funcs[] = {
	nm_setting_802_1x_new,
	nm_setting_adsl_new,
	nm_setting_bluetooth_new,
	nm_setting_bond_new,
	nm_setting_bridge_new,
	nm_setting_bridge_port_new,
	nm_setting_cdma_new,
	nm_setting_connection_new,
	nm_setting_dcb_new,
	nm_setting_gsm_new,
	nm_setting_infiniband_new,
	nm_setting_ip4_config_new,
	nm_setting_ip6_config_new,
	nm_setting_olpc_mesh_new,
	nm_setting_ppp_new,
	nm_setting_pppoe_new,
	nm_setting_serial_new,
	nm_setting_team_new,
	nm_setting_team_port_new,
	nm_setting_vlan_new,
	nm_setting_vpn_new,
	nm_setting_wimax_new,
	nm_setting_wired_new,
	nm_setting_wireless_new,
	nm_setting_wireless_security_new,
	NULL
};

typedef struct {
	const char *gvalue_name;
	const char *new_name;
} TypeNameElement;

static TypeNameElement name_map[] = {
	{ "gchararray", "string" },
	{ "GSList_gchararray_", "array of string" },
	{ "GArray_guchar_", "byte array" },
	{ "gboolean", "boolean" },
	{ "guint64", "uint64" },
	{ "gint", "int32" },
	{ "guint", "uint32" },
	{ "GArray_guint_", "array of uint32" },
	{ "GPtrArray_GArray_guint__", "array of array of uint32" },
	{ "GPtrArray_GArray_guchar__", "array of byte array" },
	{ "GPtrArray_gchararray_", "array of string" },
	{ "GHashTable_gchararray+gchararray_", "dict of (string::string)" },
	{ "GPtrArray_GValueArray_GArray_guchar_+guint+GArray_guchar___", "array of (byte array, uint32, byte array)" },
	{ "GPtrArray_GValueArray_GArray_guchar_+guint+GArray_guchar_+guint__", "array of (byte array, uint32, byte array, uint32)" },
	{ NULL, NULL }
};

static void
write_one_setting (FILE *f, gboolean book, SettingNewFunc func)
{
	NMSetting *s;
	GParamSpec **props, **iter;
	guint num;
	const char *row_fmt_str;

	s = func ();

	/* write out section header */
	(void) fprintf (f,
		"<table>\n"
		"  <title>%s setting</title>\n"
		"  <tgroup cols=\"4\">\n"
		"    <thead>\n"
		"      <row>\n"
		"        <entry>Key Name</entry>\n"
		"        <entry>Value Type</entry>\n"
		"        <entry>Default Value</entry>\n"
		"        <entry>Value Description</entry>\n"
		"      </row>\n"
		"    </thead>\n"
		"    <tbody>\n",
		nm_setting_get_name (s));

	props = g_object_class_list_properties (G_OBJECT_GET_CLASS (G_OBJECT (s)), &num);
	for (iter = props; iter && *iter; iter++) {
		const char *key_name, *value_type, *value_desc;
		char *default_value;
		TypeNameElement *name_iter;
		GValue value = G_VALUE_INIT;
		char *flags_str = NULL;

		value_type = g_type_name (G_PARAM_SPEC_VALUE_TYPE (*iter));
		for (name_iter = &name_map[0]; name_iter && name_iter->gvalue_name; name_iter++) {
			if (!strcmp (value_type, name_iter->gvalue_name)) {
				value_type = name_iter->new_name;
				break;
			}
		}

		key_name = g_param_spec_get_name (*iter);
		value_desc = g_param_spec_get_blurb (*iter);

		g_value_init (&value, G_PARAM_SPEC_VALUE_TYPE (*iter));
		g_param_value_set_default (*iter, &value);
		default_value = g_strdup_value_contents (&value);
		if (default_value && !strcmp (default_value, "NULL")) {
			g_free (default_value);
			default_value = NULL;
		}

		if (!strcmp (key_name, NM_SETTING_NAME)) {
			g_free (default_value);
			default_value = NULL;
			g_object_get (G_OBJECT (s), NM_SETTING_NAME, &default_value, NULL);
		}

		if (g_str_has_suffix (key_name, "-flags"))
			flags_str = g_strdup_printf (" (see <xref linkend=\"secrets-flags\"/> for flag values)");

		if (book)
			row_fmt_str =
			"      <row>\n"
			"        <entry><screen>%s</screen></entry>\n"
			"        <entry><screen>%s</screen></entry>\n"
			"        <entry><screen>%s</screen></entry>\n"
			"        <entry>%s%s</entry>\n"
			"      </row>\n";
		else
			row_fmt_str =
			"      <row>\n"
			"        <entry align=\"left\">%s</entry>\n"
			"        <entry align=\"left\">%s</entry>\n"
			"        <entry align=\"left\">%s</entry>\n"
			"        <entry>%s%s</entry>\n"
			"      </row>\n";

		(void) fprintf (f, row_fmt_str,
			key_name,
			value_type,
			default_value ? default_value : "",
			value_desc,
			flags_str ? flags_str : "");

		g_free (flags_str);
		g_free (default_value);
	}

	(void) fprintf (f,
		"    </tbody>\n"
		"  </tgroup>\n"
		"</table>\n");

	g_object_unref (s);
}

static void
writer_header_docbook_section (FILE *f)
{
	(void) fprintf (f,
		"<?xml version=\"1.0\"?>\n"
		"<!DOCTYPE section PUBLIC \"-//OASIS//DTD DocBook XML V4.3//EN\"\n"
		"               \"http://www.oasis-open.org/docbook/xml/4.3/docbookx.dtd\" [\n"
		"<!ENTITY %% local.common.attrib \"xmlns:xi  CDATA  #FIXED 'http://www.w3.org/2003/XInclude'\">"
		"]>"
		"<section>\n"
		"  <title>Configuration Settings</title>\n"
		"  <para>\n");
}

static void
writer_footer_docbook_section (FILE *f)
{
	(void) fprintf (f,
		"  </para>\n"
		"</section>\n");
}

static void
writer_header_docbook_manpage (FILE *f)
{
	char time_str[64];
	time_t t;

	t = time (NULL);
	strftime (time_str, sizeof (time_str), "%d %B %Y", localtime (&t));

	(void) fprintf (f,
		"<?xml version=\"1.0\"?>\n"
		"<!DOCTYPE refentry PUBLIC \"-//OASIS//DTD DocBook XML V4.3//EN\"\n"
		"               \"http://www.oasis-open.org/docbook/xml/4.3/docbookx.dtd\" [\n"
		"<!ENTITY %% local.common.attrib \"xmlns:xi  CDATA  #FIXED 'http://www.w3.org/2003/XInclude'\">"
		"]>"
		"<refentry id=\"nm-settings\">\n"
		"  <refentryinfo>\n"
		"    <date>%s</date>\n"
		"  </refentryinfo>\n"
		"  <refmeta>\n"
		"    <refentrytitle>nm-settings</refentrytitle>\n"
		"    <manvolnum>5</manvolnum>\n"
		"    <refmiscinfo class=\"source\">NetworkManager</refmiscinfo>\n"
		"    <refmiscinfo class=\"manual\">Configuration</refmiscinfo>\n"
		"    <refmiscinfo class=\"version\">%s</refmiscinfo>\n"
		"  </refmeta>\n"
		"  <refnamediv>\n"
		"    <refname>nm-settings</refname>\n"
		"    <refpurpose>Description of settings and properties of NetworkManager connection profiles</refpurpose>\n"
		"  </refnamediv>\n"
		"  <refsect1>\n"
		"    <title>DESCRIPTION</title>\n"
		"    <para>\n"
		"      NetworkManager is based on a concept of connection profiles, sometimes referred to as\n"
		"      connections only. These connection profiles contain a network configuration. When\n"
		"      NetworkManager activates a connection profile on a network device the configuration will\n"
		"      be applied and an active network connection will be established. Users are free to create\n"
		"      as many connection profiles as they see fit. Thus they are flexible in having various network\n"
		"      configurations for different networking needs. The connection profiles are handled by\n"
		"      NetworkManager via <emphasis>settings service</emphasis> and are exported on D-Bus\n"
		"      (<emphasis>/org/freedesktop/NetworkManager/Settings/&lt;num&gt;</emphasis> objects).\n"
		"      The conceptual objects can be described as follows:\n"
		"      <variablelist>\n"
		"        <varlistentry>\n"
		"          <term>Connection (profile)</term>\n"
		"          <listitem>\n"
		"            <para>\n"
		"              A specific, encapsulated, independent group of settings describing\n"
		"              all the configuration required to connect to a specific network.\n"
		"              It is referred to by a unique identifier called the UUID. A connection\n"
		"              is tied to a one specific device type, but not necessarily a specific\n"
		"              hardware device. It is composed of one or more <emphasis>Settings</emphasis>\n"
		"              objects.\n"
		"            </para>\n"
		"          </listitem>\n"
		"        </varlistentry>\n"
		"      </variablelist>\n"
		"      <variablelist>\n"
		"        <varlistentry>\n"
		"          <term>Setting</term>\n"
		"          <listitem>\n"
		"            <para>\n"
		"              A group of related key/value pairs describing a specific piece of a\n"
		"              <emphasis>Connection (profile)</emphasis>. Settings keys and allowed values are\n"
		"              described in the tables below. Keys are also reffered to as properties.\n"
		"              Developers can find the setting objects and their properties in the libnm-util\n"
		"              sources. Look for the <function>class_init</function> functions near the bottom of\n"
		"              each setting source file.\n"
		"            </para>\n"
		"          </listitem>\n"
		"        </varlistentry>\n"
		"      </variablelist>\n"
		"      <variablelist>\n"
		"        <para>\n"
		"          The settings and properties shown in tables below list all available connection\n"
		"          configuration options. However, note that not all settings are applicable to all\n"
		"          connection types. NetworkManager provides a command-line tool <emphasis>nmcli</emphasis>\n"
		"          that allows direct configuration of the settings and properties according to a connection\n"
		"          profile type. <emphasis>nmcli</emphasis> connection editor has also a built-in\n"
		"          <emphasis>describe</emphasis> command that can display description of particular settings\n"
		"          and properties of this page.\n"
		"        </para>\n"
		"      </variablelist>\n",
		time_str, VERSION);
}

static void
writer_footer_docbook_manpage (FILE *f)
{
	(void) fprintf (f,
		"    </para>\n"
		"    <refsect2 id=\"secrets-flags\">\n"
		"      <title>Secret flag types:</title>\n"
		"      <para>\n"
		"      Each secret property in a setting has an associated <emphasis>flags</emphasis> property\n"
		"      that describes how to handle that secret. The <emphasis>flags</emphasis> property is a bitfield\n"
		"      that contains zero or more of the following values logically OR-ed together.\n"
		"      </para>\n"
		"      <itemizedlist>\n"
		"        <listitem>\n"
		"          <para>0x0 (none) - the system is responsible for providing and storing this secret.</para>\n"
		"        </listitem>\n"
		"        <listitem>\n"
		"          <para>0x1 (agent-owned) - a user-session secret agent is responsible for providing and storing\n"
		"          this secret; when it is required, agents will be asked to provide it.</para>\n"
		"        </listitem>\n"
		"        <listitem>\n"
		"          <para>0x2 (not-saved) - this secret should not be saved but should be requested from the user\n"
		"          each time it is required. This flag should be used for One-Time-Pad secrets, PIN codes from hardware tokens,\n"
		"          or if the user simply does not want to save the secret.</para>\n"
		"        </listitem>\n"
		"        <listitem>\n"
		"          <para>0x4 (not-required) - in some situations it cannot be automatically determined that a secret\n"
		"          is required or not. This flag hints that the secret is not required and should not be requested from the user.</para>\n"
		"        </listitem>\n"
		"      </itemizedlist>\n"
		"     </refsect2>\n"
		"  </refsect1>\n"
		"  <refsect1>\n"
		"    <title>AUTHOR</title>\n"
		"    <para>\n"
		"      <author>\n"
		"        <firstname>NetworkManager developers</firstname>\n"
		"      </author>\n"
		"    </para>\n"
		"  </refsect1>\n"
		"  <refsect1>\n"
		"    <title>FILES</title>\n"
		"    <para>/etc/NetworkManager/system-connections</para>\n"
		"    <para>or distro plugin-specific location</para>\n"
		"  </refsect1>\n"
		"  <refsect1>\n"
		"    <title>SEE ALSO</title>\n"
		"    <para>https://live.gnome.org/NetworkManagerConfiguration</para>\n"
		"    <para>NetworkManager(8), nmcli(1), nmcli-examples(5), NetworkManager.conf(5)</para>\n"
		"  </refsect1>\n"
		"</refentry>\n");
}

static void
usage (const char *str)
{
	fprintf (stderr, "Usage: %s <type> <output file> [<type> <output file>]\n"
		 "<type> := book|refentry\n",
	         str);
	_exit (1);
}

int
main (int argc, char *argv[])
{
	GError *error = NULL;
	FILE *f1 = NULL, *f2 = NULL;
	SettingNewFunc *fptr;
	const char *book_file = NULL, *refentry_file = NULL;;

	if (argc != 3 && argc != 5)
		usage (argv[0]);

	if (strcmp (argv[1], "book") == 0)
		book_file = argv[2];
	else if (strcmp (argv[1], "refentry") == 0)
		refentry_file = argv[2];
	else
		usage (argv[0]);

	if (argc == 5) {
		if (strcmp (argv[3], "book") == 0 && !book_file)
			book_file = argv[4];
		else if (strcmp (argv[3], "refentry") == 0 && !refentry_file)
			refentry_file = argv[4];
		else
			usage (argv[0]);
	}

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	if (!nm_utils_init (&error)) {
		fprintf (stderr, "ERR: failed to initialize libnm-util: %s", error->message);
		_exit (2);
	}

	if (book_file) {
		f1 = fopen (book_file, "w");
		if (!f1) {
			fprintf (stderr, "ERR: could not create %s: %d\n", book_file, errno);
			_exit (3);
		}
	}
	if (refentry_file) {
		f2 = fopen (refentry_file, "w");
		if (!f2) {
			fprintf (stderr, "ERR: could not create %s: %d\n", refentry_file, errno);
			_exit (3);
		}
	}

	/* Write out docbook 'book' xml - for html generation */
	if (f1) {
		writer_header_docbook_section (f1);
		for (fptr = funcs; fptr && *fptr; fptr++)
			write_one_setting (f1, TRUE, *fptr);
		writer_footer_docbook_section (f1);
	}

	/* Write out docbook 'refentry' xml - for man page generation */
	if (f2) {
		writer_header_docbook_manpage (f2);
		for (fptr = funcs; fptr && *fptr; fptr++)
			write_one_setting (f2, FALSE, *fptr);
		writer_footer_docbook_manpage (f2);
	}

	if (f1)
		fclose (f1);
	if (f2)
		fclose (f2);
	_exit (0);
}

