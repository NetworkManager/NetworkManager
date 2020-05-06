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
	GPtrArray *interface_name;
	GPtrArray *kernel_command_line;
	GPtrArray *driver;
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

	return setting->interface_name->len;
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

	g_return_val_if_fail (idx >= 0 && idx < setting->interface_name->len, NULL);

	return setting->interface_name->pdata[idx];
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

	g_ptr_array_add (setting->interface_name, g_strdup (interface_name));
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

	g_return_if_fail (idx >= 0 && idx < setting->interface_name->len);

	g_ptr_array_remove_index (setting->interface_name, idx);
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

	for (i = 0; i < setting->interface_name->len; i++) {
		if (nm_streq (interface_name, setting->interface_name->pdata[i])) {
			g_ptr_array_remove_index (setting->interface_name, i);
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

	if (setting->interface_name->len != 0) {
		g_ptr_array_set_size (setting->interface_name, 0);
		_notify (setting, PROP_INTERFACE_NAME);
	}
}

/**
 * nm_setting_match_get_interface_names:
 * @setting: the #NMSettingMatch
 * @length: (out): the length of the returned interface names array.
 *
 * Returns all the interface names.
 *
 * Returns: (transfer none) (array length=length): the configured interface names.
 *
 * Since: 1.14
 **/
const char *const *
nm_setting_match_get_interface_names (NMSettingMatch *setting, guint *length)
{
	g_return_val_if_fail (NM_IS_SETTING_MATCH (setting), NULL);
	g_return_val_if_fail (length, NULL);

	NM_SET_OUT (length, setting->interface_name->len);
	return (const char *const *) setting->interface_name->pdata;
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

	return setting->kernel_command_line->len;
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

	g_return_val_if_fail (idx < setting->kernel_command_line->len, NULL);

	return setting->kernel_command_line->pdata[idx];
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

	g_ptr_array_add (setting->kernel_command_line, g_strdup (kernel_command_line));
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

	g_return_if_fail (idx < setting->kernel_command_line->len);

	g_ptr_array_remove_index (setting->kernel_command_line, idx);
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

	for (i = 0; i < setting->kernel_command_line->len; i++) {
		if (nm_streq (kernel_command_line, setting->kernel_command_line->pdata[i])) {
			g_ptr_array_remove_index (setting->kernel_command_line, i);
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

	if (setting->kernel_command_line->len != 0) {
		g_ptr_array_set_size (setting->kernel_command_line, 0);
		_notify (setting, PROP_KERNEL_COMMAND_LINE);
	}
}

/**
 * nm_setting_match_get_kernel_command_lines:
 * @setting: the #NMSettingMatch
 * @length: (out): the length of the returned interface names array.
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
	g_return_val_if_fail (length, NULL);

	NM_SET_OUT (length, setting->kernel_command_line->len);
	return (const char *const *) setting->kernel_command_line->pdata;
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

	return setting->driver->len;
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

	g_return_val_if_fail (idx < setting->driver->len, NULL);

	return setting->driver->pdata[idx];
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

	g_ptr_array_add (setting->driver, g_strdup (driver));
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

	g_return_if_fail (idx < setting->driver->len);

	g_ptr_array_remove_index (setting->driver, idx);
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

	for (i = 0; i < setting->driver->len; i++) {
		if (nm_streq (driver, setting->driver->pdata[i])) {
			g_ptr_array_remove_index (setting->driver, i);
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

	if (setting->driver->len != 0) {
		g_ptr_array_set_size (setting->driver, 0);
		_notify (setting, PROP_DRIVER);
	}
}

/**
 * nm_setting_match_get_drivers:
 * @setting: the #NMSettingMatch
 * @length: (out): the length of the returned interface names array.
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
	g_return_val_if_fail (length, NULL);

	NM_SET_OUT (length, setting->driver->len);
	return (const char *const *) setting->driver->pdata;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingMatch *self = NM_SETTING_MATCH (object);

	switch (prop_id) {
	case PROP_INTERFACE_NAME:
		g_value_take_boxed (value, _nm_utils_ptrarray_to_strv (self->interface_name));
		break;
	case PROP_KERNEL_COMMAND_LINE:
		g_value_take_boxed (value, _nm_utils_ptrarray_to_strv (self->kernel_command_line));
		break;
	case PROP_DRIVER:
		g_value_take_boxed (value, _nm_utils_ptrarray_to_strv (self->driver));
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
		g_ptr_array_unref (self->interface_name);
		self->interface_name = _nm_utils_strv_to_ptrarray (g_value_get_boxed (value));
		break;
	case PROP_KERNEL_COMMAND_LINE:
		g_ptr_array_unref (self->kernel_command_line);
		self->kernel_command_line = _nm_utils_strv_to_ptrarray (g_value_get_boxed (value));
		break;
	case PROP_DRIVER:
		g_ptr_array_unref (self->driver);
		self->driver = _nm_utils_strv_to_ptrarray (g_value_get_boxed (value));
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
	setting->interface_name = g_ptr_array_new_with_free_func (g_free);
	setting->kernel_command_line = g_ptr_array_new_with_free_func (g_free);
	setting->driver = g_ptr_array_new_with_free_func (g_free);
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

	for (i = 0; i < self->interface_name->len; i++) {
		if (!nm_str_not_empty (self->interface_name->pdata[i])) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_MATCH_SETTING_NAME,
			                NM_SETTING_MATCH_INTERFACE_NAME);
			return FALSE;
		}
	}

	for (i = 0; i < self->kernel_command_line->len; i++) {
		if (!nm_str_not_empty (self->kernel_command_line->pdata[i])) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_MATCH_SETTING_NAME,
			                NM_SETTING_MATCH_KERNEL_COMMAND_LINE);
			return FALSE;
		}
	}

	for (i = 0; i < self->driver->len; i++) {
		if (!nm_str_not_empty (self->driver->pdata[i])) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_MATCH_SETTING_NAME,
			                NM_SETTING_MATCH_DRIVER);
			return FALSE;
		}
	}

	return TRUE;
}

static void
finalize (GObject *object)
{
	NMSettingMatch *self = NM_SETTING_MATCH (object);

	g_ptr_array_unref (self->interface_name);
	g_ptr_array_unref (self->kernel_command_line);
	g_ptr_array_unref (self->driver);

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
	 * pattern.  When an element is prefixed with exclamation mark (!) the
	 * condition is inverted.
	 *
	 * A candidate interface name is considered matching when both these
	 * conditions are satisfied: (a) any of the elements not prefixed with '!'
	 * matches or there aren't such elements; (b) none of the elements
	 * prefixed with '!' match.
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
	 * When an element is prefixed with exclamation mark (!) the condition is
	 * inverted. A candidate driver name is considered matching when both these
	 * conditions are satisfied: (a) any of the elements not prefixed with '!'
	 * matches or there aren't such elements; (b) none of the elements prefixed
	 * with '!' match.
	 *
	 * Since: 1.26
	 **/
	obj_properties[PROP_DRIVER] =
	    g_param_spec_boxed (NM_SETTING_MATCH_DRIVER, "", "",
	                        G_TYPE_STRV,
	                        NM_SETTING_PARAM_FUZZY_IGNORE |
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit (setting_class, NM_META_SETTING_TYPE_MATCH);
}
