// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-match.h"

#include "nm-setting-private.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-match
 * @short_description: Properties to match a connection with a device.
 * @include: nm-setting-match.h
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSettingMatch,
	PROP_INTERFACE_NAME,
	PROP_KERNEL_COMMAND_LINE,
	PROP_DRIVER,
	PROP_PATH,
);

/**
 * NMSettingMatch:
 *
 * Match settings
 *
 * Since: 1.14
 */
struct _NMSettingMatch {
	NMSetting parent;
	GArray *interface_name;
	GArray *kernel_command_line;
	GArray *driver;
	GArray *path;
};

struct _NMSettingMatchClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE (NMSettingMatch, nm_setting_match, NM_TYPE_SETTING)

/*****************************************************************************/

/**
 * nm_setting_match_get_num_interface_names:
 * @setting: the #NMSettingMatch
 *
 * Returns: the number of configured interface names
 *
 * Since: 1.14
 **/
guint
nm_setting_match_get_num_interface_names (NMSettingMatch *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), 0);

	return nm_g_array_len (setting->interface_name);
}

/**
 * nm_setting_match_get_interface_name:
 * @setting: the #NMSettingMatch
 * @idx: index number of the DNS search domain to return
 *
 * Returns: the interface name at index @idx
 *
 * Since: 1.14
 **/
const char *
nm_setting_match_get_interface_name (NMSettingMatch *setting, int idx)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), NULL);

	g_return_val_if_fail (setting->interface_name && idx >= 0 && idx < setting->interface_name->len, NULL);

	return g_array_index (setting->interface_name, const char *, idx);
}

/**
 * nm_setting_match_add_interface_name:
 * @setting: the #NMSettingMatch
 * @interface_name: the interface name to add
 *
 * Adds a new interface name to the setting.
 *
 * Since: 1.14
 **/
void
nm_setting_match_add_interface_name (NMSettingMatch *setting,
                                     const char *interface_name)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));
	g_return_if_fail (interface_name != NULL);
	g_return_if_fail (interface_name[0] != '\0');

	nm_strvarray_add (nm_strvarray_ensure (&setting->interface_name), interface_name);
	_notify (setting, PROP_INTERFACE_NAME);
}

/**
 * nm_setting_match_remove_interface_name:
 * @setting: the #NMSettingMatch
 * @idx: index number of the interface name
 *
 * Removes the interface name at index @idx.
 *
 * Since: 1.14
 **/
void
nm_setting_match_remove_interface_name (NMSettingMatch *setting, int idx)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));

	g_return_if_fail (setting->interface_name && idx >= 0 && idx < setting->interface_name->len);

	g_array_remove_index (setting->interface_name, idx);
	_notify (setting, PROP_INTERFACE_NAME);
}

/**
 * nm_setting_match_remove_interface_name_by_value:
 * @setting: the #NMSettingMatch
 * @interface_name: the interface name to remove
 *
 * Removes @interface_name.
 *
 * Returns: %TRUE if the interface name was found and removed; %FALSE if it was not.
 *
 * Since: 1.14
 **/
gboolean
nm_setting_match_remove_interface_name_by_value (NMSettingMatch *setting,
                                                 const char *interface_name)
{
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), FALSE);
	g_return_val_if_fail (interface_name != NULL, FALSE);
	g_return_val_if_fail (interface_name[0] != '\0', FALSE);

	if (!setting->interface_name)
		return FALSE;

	for (i = 0; i < setting->interface_name->len; i++) {
		if (nm_streq (interface_name, g_array_index (setting->interface_name, const char *, i))) {
			g_array_remove_index (setting->interface_name, i);
			_notify (setting, PROP_INTERFACE_NAME);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_match_clear_interface_names:
 * @setting: the #NMSettingMatch
 *
 * Removes all configured interface names.
 *
 * Since: 1.14
 **/
void
nm_setting_match_clear_interface_names (NMSettingMatch *setting)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));

	if (nm_g_array_len (setting->interface_name) != 0) {
		nm_clear_pointer (&setting->interface_name, g_array_unref);
		_notify (setting, PROP_INTERFACE_NAME);
	}
}

/**
 * nm_setting_match_get_interface_names:
 * @setting: the #NMSettingMatch
 * @length: (out) (allow-none): the length of the returned interface names array.
 *
 * Returns all the interface names.
 *
 * Returns: (transfer none) (array length=length): the NULL terminated list of
 *   configured interface names.
 *
 * Before 1.26, the returned array was not %NULL terminated and you MUST provide a length.
 *
 * Since: 1.14
 **/
const char *const *
nm_setting_match_get_interface_names (NMSettingMatch *setting, guint *length)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), NULL);

	return nm_strvarray_get_strv (&setting->interface_name, length);
}

/*****************************************************************************/

/**
 * nm_setting_match_get_num_kernel_command_lines:
 * @setting: the #NMSettingMatch
 *
 * Returns: the number of configured kernel command line arguments
 *
 * Since: 1.26
 **/
guint
nm_setting_match_get_num_kernel_command_lines (NMSettingMatch *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), 0);

	return nm_g_array_len (setting->kernel_command_line);
}

/**
 * nm_setting_match_get_kernel_command_line:
 * @setting: the #NMSettingMatch
 * @idx: index number of the kernel command line argument to return
 *
 * Returns: the kernel command line argument at index @idx
 *
 * Since: 1.26
 **/
const char *
nm_setting_match_get_kernel_command_line (NMSettingMatch *setting, guint idx)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), NULL);

	g_return_val_if_fail (setting->kernel_command_line && idx < setting->kernel_command_line->len, NULL);

	return g_array_index (setting->kernel_command_line, const char *, idx);
}

/**
 * nm_setting_match_add_kernel_command_line:
 * @setting: the #NMSettingMatch
 * @kernel_command_line: the kernel command line argument to add
 *
 * Adds a new kernel command line argument to the setting.
 *
 * Since: 1.26
 **/
void
nm_setting_match_add_kernel_command_line (NMSettingMatch *setting,
                                          const char *kernel_command_line)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));
	g_return_if_fail (kernel_command_line != NULL);
	g_return_if_fail (kernel_command_line[0] != '\0');

	nm_strvarray_add (nm_strvarray_ensure (&setting->kernel_command_line), kernel_command_line);
	_notify (setting, PROP_KERNEL_COMMAND_LINE);
}

/**
 * nm_setting_match_remove_kernel_command_line:
 * @setting: the #NMSettingMatch
 * @idx: index number of the kernel command line argument
 *
 * Removes the kernel command line argument at index @idx.
 *
 * Since: 1.26
 **/
void
nm_setting_match_remove_kernel_command_line (NMSettingMatch *setting, guint idx)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));

	g_return_if_fail (setting->kernel_command_line && idx < setting->kernel_command_line->len);

	g_array_remove_index (setting->kernel_command_line, idx);
	_notify (setting, PROP_KERNEL_COMMAND_LINE);
}

/**
 * nm_setting_match_remove_kernel_command_line_by_value:
 * @setting: the #NMSettingMatch
 * @kernel_command_line: the kernel command line argument name to remove
 *
 * Removes @kernel_command_line.
 *
 * Returns: %TRUE if the kernel command line argument was found and removed; %FALSE if it was not.
 *
 * Since: 1.26
 **/
gboolean
nm_setting_match_remove_kernel_command_line_by_value (NMSettingMatch *setting,
                                                      const char *kernel_command_line)
{
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), FALSE);
	g_return_val_if_fail (kernel_command_line != NULL, FALSE);
	g_return_val_if_fail (kernel_command_line[0] != '\0', FALSE);

	if (!setting->kernel_command_line)
		return FALSE;

	for (i = 0; i < setting->kernel_command_line->len; i++) {
		if (nm_streq (kernel_command_line, g_array_index (setting->kernel_command_line, const char *, i))) {
			g_array_remove_index (setting->kernel_command_line, i);
			_notify (setting, PROP_KERNEL_COMMAND_LINE);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_match_clear_kernel_command_lines:
 * @setting: the #NMSettingMatch
 *
 * Removes all configured kernel command line arguments.
 *
 * Since: 1.26
 **/
void
nm_setting_match_clear_kernel_command_lines (NMSettingMatch *setting)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));

	if (nm_g_array_len (setting->kernel_command_line) != 0) {
		nm_clear_pointer (&setting->kernel_command_line, g_array_unref);
		_notify (setting, PROP_KERNEL_COMMAND_LINE);
	}
}

/**
 * nm_setting_match_get_kernel_command_lines:
 * @setting: the #NMSettingMatch
 * @length: (out) (allow-none): the length of the returned interface names array.
 *
 * Returns all the interface names.
 *
 * Returns: (transfer none) (array length=length): the configured interface names.
 *
 * Since: 1.26
 **/
const char *const *
nm_setting_match_get_kernel_command_lines (NMSettingMatch *setting, guint *length)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), NULL);

	return nm_strvarray_get_strv (&setting->kernel_command_line, length);
}

/*****************************************************************************/

/**
 * nm_setting_match_get_num_drivers:
 * @setting: the #NMSettingMatch
 *
 * Returns: the number of configured drivers
 *
 * Since: 1.26
 **/
guint
nm_setting_match_get_num_drivers (NMSettingMatch *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), 0);

	return nm_g_array_len (setting->driver);
}

/**
 * nm_setting_match_get_driver:
 * @setting: the #NMSettingMatch
 * @idx: index number of the DNS search domain to return
 *
 * Returns: the driver at index @idx
 *
 * Since: 1.26
 **/
const char *
nm_setting_match_get_driver (NMSettingMatch *setting, guint idx)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), NULL);

	g_return_val_if_fail (setting->driver && idx < setting->driver->len, NULL);

	return g_array_index (setting->driver, const char *, idx);
}

/**
 * nm_setting_match_add_driver:
 * @setting: the #NMSettingMatch
 * @driver: the driver to add
 *
 * Adds a new driver to the setting.
 *
 * Since: 1.26
 **/
void
nm_setting_match_add_driver (NMSettingMatch *setting,
                             const char *driver)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));
	g_return_if_fail (driver != NULL);
	g_return_if_fail (driver[0] != '\0');

	nm_strvarray_add (nm_strvarray_ensure (&setting->driver), driver);
	_notify (setting, PROP_DRIVER);
}

/**
 * nm_setting_match_remove_driver:
 * @setting: the #NMSettingMatch
 * @idx: index number of the driver
 *
 * Removes the driver at index @idx.
 *
 * Since: 1.26
 **/
void
nm_setting_match_remove_driver (NMSettingMatch *setting, guint idx)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));

	g_return_if_fail (setting->driver && idx < setting->driver->len);

	g_array_remove_index (setting->driver, idx);
	_notify (setting, PROP_DRIVER);
}

/**
 * nm_setting_match_remove_driver_by_value:
 * @setting: the #NMSettingMatch
 * @driver: the driver to remove
 *
 * Removes @driver.
 *
 * Returns: %TRUE if the driver was found and removed; %FALSE if it was not.
 *
 * Since: 1.26
 **/
gboolean
nm_setting_match_remove_driver_by_value (NMSettingMatch *setting,
                                         const char *driver)
{
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), FALSE);
	g_return_val_if_fail (driver != NULL, FALSE);
	g_return_val_if_fail (driver[0] != '\0', FALSE);

	if (!setting->driver)
		return FALSE;

	for (i = 0; i < setting->driver->len; i++) {
		if (nm_streq (driver, g_array_index (setting->driver, const char *, i))) {
			g_array_remove_index (setting->driver, i);
			_notify (setting, PROP_DRIVER);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_match_clear_drivers:
 * @setting: the #NMSettingMatch
 *
 * Removes all configured drivers.
 *
 * Since: 1.26
 **/
void
nm_setting_match_clear_drivers (NMSettingMatch *setting)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));

	if (nm_g_array_len (setting->driver) != 0) {
		nm_clear_pointer (&setting->driver, g_array_unref);
		_notify (setting, PROP_DRIVER);
	}
}

/**
 * nm_setting_match_get_drivers:
 * @setting: the #NMSettingMatch
 * @length: (out) (allow-none): the length of the returned interface names array.
 *
 * Returns all the drivers.
 *
 * Returns: (transfer none) (array length=length): the configured drivers.
 *
 * Since: 1.26
 **/
const char *const *
nm_setting_match_get_drivers (NMSettingMatch *setting, guint *length)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), NULL);

	return nm_strvarray_get_strv (&setting->driver, length);
}

/*****************************************************************************/

/**
 * nm_setting_match_get_num_paths:
 * @setting: the #NMSettingMatch
 *
 * Returns: the number of configured paths
 *
 * Since: 1.26
 **/
guint
nm_setting_match_get_num_paths (NMSettingMatch *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), 0);

	return nm_g_array_len (setting->path);
}

/**
 * nm_setting_match_get_path:
 * @setting: the #NMSettingMatch
 * @idx: index number of the path to return
 *
 * Returns: the path at index @idx
 *
 * Since: 1.26
 **/
const char *
nm_setting_match_get_path (NMSettingMatch *setting, guint idx)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), NULL);

	g_return_val_if_fail (setting->path && idx < setting->path->len, NULL);

	return g_array_index (setting->path, const char *, idx);
}

/**
 * nm_setting_match_add_path:
 * @setting: the #NMSettingMatch
 * @path: the path to add
 *
 * Adds a new path to the setting.
 *
 * Since: 1.26
 **/
void
nm_setting_match_add_path (NMSettingMatch *setting,
                           const char *path)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));
	g_return_if_fail (path != NULL);
	g_return_if_fail (path[0] != '\0');

	nm_strvarray_add (nm_strvarray_ensure (&setting->path), path);
	_notify (setting, PROP_PATH);
}

/**
 * nm_setting_match_remove_path:
 * @setting: the #NMSettingMatch
 * @idx: index number of the path
 *
 * Removes the path at index @idx.
 *
 * Since: 1.26
 **/
void
nm_setting_match_remove_path (NMSettingMatch *setting, guint idx)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));

	g_return_if_fail (setting->path && idx < setting->path->len);

	g_array_remove_index (setting->path, idx);
	_notify (setting, PROP_PATH);
}

/**
 * nm_setting_match_remove_path_by_value:
 * @setting: the #NMSettingMatch
 * @path: the path to remove
 *
 * Removes @path.
 *
 * Returns: %TRUE if the path was found and removed; %FALSE if it was not.
 *
 * Since: 1.26
 **/
gboolean
nm_setting_match_remove_path_by_value (NMSettingMatch *setting,
                                       const char *path)
{
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), FALSE);
	g_return_val_if_fail (path != NULL, FALSE);
	g_return_val_if_fail (path[0] != '\0', FALSE);

	if (!setting->path)
		return FALSE;

	for (i = 0; i < setting->path->len; i++) {
		if (nm_streq (path, g_array_index (setting->path, const char *, i))) {
			g_array_remove_index (setting->path, i);
			_notify (setting, PROP_PATH);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_match_clear_paths:
 * @setting: the #NMSettingMatch
 *
 * Removes all configured paths.
 *
 * Since: 1.26
 **/
void
nm_setting_match_clear_paths (NMSettingMatch *setting)
{
	g_return_if_fail (NM_IS_SETTING_MATCH (setting));

	if (nm_g_array_len (setting->path) != 0) {
		nm_clear_pointer (&setting->path, g_array_unref);
		_notify (setting, PROP_PATH);
	}
}

/**
 * nm_setting_match_get_paths:
 * @setting: the #NMSettingMatch
 * @length: (out) (allow-none): the length of the returned paths array.
 *
 * Returns all the paths.
 *
 * Returns: (transfer none) (array length=length): the configured paths.
 *
 * Since: 1.26
 **/
const char *const *
nm_setting_match_get_paths (NMSettingMatch *setting, guint *length)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), NULL);

	return nm_strvarray_get_strv (&setting->path, length);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingMatch *self = NM_SETTING_MATCH (object);

	switch (prop_id) {
	case PROP_INTERFACE_NAME:
		g_value_set_boxed (value, nm_strvarray_get_strv_non_empty (self->interface_name, NULL));
		break;
	case PROP_KERNEL_COMMAND_LINE:
		g_value_set_boxed (value, nm_strvarray_get_strv_non_empty (self->kernel_command_line, NULL));
		break;
	case PROP_DRIVER:
		g_value_set_boxed (value, nm_strvarray_get_strv_non_empty (self->driver, NULL));
		break;
	case PROP_PATH:
		g_value_set_boxed (value, nm_strvarray_get_strv_non_empty (self->path, NULL));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingMatch *self = NM_SETTING_MATCH (object);

	switch (prop_id) {
	case PROP_INTERFACE_NAME:
		nm_strvarray_set_strv (&self->interface_name, g_value_get_boxed (value));
		break;
	case PROP_KERNEL_COMMAND_LINE:
		nm_strvarray_set_strv (&self->kernel_command_line, g_value_get_boxed (value));
		break;
	case PROP_DRIVER:
		nm_strvarray_set_strv (&self->driver, g_value_get_boxed (value));
		break;
	case PROP_PATH:
		nm_strvarray_set_strv (&self->path, g_value_get_boxed (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_match_init (NMSettingMatch *setting)
{
}

/**
 * nm_setting_match_new:
 *
 * Creates a new #NMSettingMatch object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingMatch object
 *
 * Since: 1.14
 **/
NMSetting *
nm_setting_match_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_MATCH, NULL);
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingMatch *self = NM_SETTING_MATCH (setting);
	guint i;

	if (self->interface_name) {
		for (i = 0; i < self->interface_name->len; i++) {
			if (nm_str_is_empty (g_array_index (self->interface_name, const char *, i))) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("is empty"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_MATCH_SETTING_NAME,
				                NM_SETTING_MATCH_INTERFACE_NAME);
				return FALSE;
			}
		}
	}

	if (self->kernel_command_line) {
		for (i = 0; i < self->kernel_command_line->len; i++) {
			if (nm_str_is_empty (g_array_index (self->kernel_command_line, const char *, i))) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("is empty"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_MATCH_SETTING_NAME,
				                NM_SETTING_MATCH_KERNEL_COMMAND_LINE);
				return FALSE;
			}
		}
	}

	if (self->driver) {
		for (i = 0; i < self->driver->len; i++) {
			if (nm_str_is_empty (g_array_index (self->driver, const char *, i))) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("is empty"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_MATCH_SETTING_NAME,
				                NM_SETTING_MATCH_DRIVER);
				return FALSE;
			}
		}
	}

	if (self->path) {
		for (i = 0; i < self->path->len; i++) {
			if (nm_str_is_empty (g_array_index (self->path, const char *, i))) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("is empty"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_MATCH_SETTING_NAME,
				                NM_SETTING_MATCH_PATH);
				return FALSE;
			}
		}
	}

	return TRUE;
}

static void
finalize (GObject *object)
{
	NMSettingMatch *self = NM_SETTING_MATCH (object);

	nm_clear_pointer (&self->interface_name, g_array_unref);
	nm_clear_pointer (&self->kernel_command_line, g_array_unref);
	nm_clear_pointer (&self->driver, g_array_unref);
	nm_clear_pointer (&self->path, g_array_unref);

	G_OBJECT_CLASS (nm_setting_match_parent_class)->finalize (object);
}

static void
nm_setting_match_class_init (NMSettingMatchClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify      = verify;

	/**
	 * NMSettingMatch:interface-name
	 *
	 * A list of interface names to match. Each element is a shell wildcard
	 * pattern.
	 *
	 * An element can be prefixed with a pipe symbol (|) or an ampersand (&).
	 * The former means that the element is optional and the latter means that
	 * it is mandatory. If there are any optional elements, than the match
	 * evaluates to true if at least one of the optional element matches
	 * (logical OR). If there are any mandatory elements, then they all
	 * must match (logical AND). By default, an element is optional. This means
	 * that an element "foo" behaves the same as "|foo". An element can also be inverted
	 * with exclamation mark (!) between the pipe symbol (or the ampersand) and before
	 * the pattern. Note that "!foo" is a shortcut for the mandatory match "&!foo". Finally,
	 * a backslash can be used at the beginning of the element (after the optional special characters)
	 * to escape the start of the pattern. For example, "&\\!a" is an mandatory match for literally "!a".
	 *
	 * Since: 1.14
	 **/
	obj_properties[PROP_INTERFACE_NAME] =
	    g_param_spec_boxed (NM_SETTING_MATCH_INTERFACE_NAME, "", "",
	                        G_TYPE_STRV,
	                        NM_SETTING_PARAM_FUZZY_IGNORE |
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingMatch:kernel-command-line
	 *
	 * A list of kernel command line arguments to match. This may be used to check
	 * whether a specific kernel command line option is set (or if prefixed with
	 * the exclamation mark unset). The argument must either be a single word, or
	 * an assignment (i.e. two words, separated "="). In the former case the kernel
	 * command line is searched for the word appearing as is, or as left hand side
	 * of an assignment. In the latter case, the exact assignment is looked for
	 * with right and left hand side matching.
	 *
	 * See NMSettingMatch:interface-name for how special characters '|', '&',
	 * '!' and '\\' are used for optional and mandatory matches and inverting the
	 * pattern.
	 *
	 * Since: 1.26
	 **/
	obj_properties[PROP_KERNEL_COMMAND_LINE] =
	    g_param_spec_boxed (NM_SETTING_MATCH_KERNEL_COMMAND_LINE, "", "",
	                        G_TYPE_STRV,
	                        NM_SETTING_PARAM_FUZZY_IGNORE |
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingMatch:driver
	 *
	 * A list of driver names to match. Each element is a shell wildcard pattern.
	 *
	 * See NMSettingMatch:interface-name for how special characters '|', '&',
	 * '!' and '\\' are used for optional and mandatory matches and inverting the
	 * pattern.
	 *
	 * Since: 1.26
	 **/
	obj_properties[PROP_DRIVER] =
	    g_param_spec_boxed (NM_SETTING_MATCH_DRIVER, "", "",
	                        G_TYPE_STRV,
	                        NM_SETTING_PARAM_FUZZY_IGNORE |
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingMatch:path
	 *
	 * A list of paths to match against the ID_PATH udev property of
	 * devices. ID_PATH represents the topological persistent path of a
	 * device. It typically contains a subsystem string (pci, usb, platform,
	 * etc.) and a subsystem-specific identifier.
	 *
	 * For PCI devices the path has the form
	 * "pci-$domain:$bus:$device.$function", where each variable is an
	 * hexadecimal value; for example "pci-0000:0a:00.0".
	 *
	 * The path of a device can be obtained with "udevadm info
	 * /sys/class/net/$dev | grep ID_PATH=" or by looking at the "path"
	 * property exported by NetworkManager ("nmcli -f general.path device
	 * show $dev").
	 *
	 * Each element of the list is a shell wildcard pattern.
	 *
	 * See NMSettingMatch:interface-name for how special characters '|', '&',
	 * '!' and '\\' are used for optional and mandatory matches and inverting the
	 * pattern.
	 *
	 * Since: 1.26
	 **/
	/* ---ifcfg-rh---
	 * property: path
	 * variable: MATCH_PATH
	 * description: space-separated list of paths to match against the udev
	 *   property ID_PATHS of devices
	 * example: MATCH_PATH="pci-0000:01:00.0 pci-0000:0c:00.0"
	 * ---end---
	 */
	obj_properties[PROP_PATH] =
	    g_param_spec_boxed (NM_SETTING_MATCH_PATH, "", "",
	                        G_TYPE_STRV,
	                        NM_SETTING_PARAM_FUZZY_IGNORE |
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit (setting_class, NM_META_SETTING_TYPE_MATCH);
}
