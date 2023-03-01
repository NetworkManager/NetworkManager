/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-match.h"

#include "nm-setting-private.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-match
 * @short_description: Properties to match a connection with a device.
 * @include: nm-setting-match.h
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMSettingMatch,
                             PROP_INTERFACE_NAME,
                             PROP_KERNEL_COMMAND_LINE,
                             PROP_DRIVER,
                             PROP_PATH, );

/**
 * NMSettingMatch:
 *
 * Match settings
 *
 * Since: 1.14
 */
struct _NMSettingMatch {
    NMSetting   parent;
    NMValueStrv interface_name;
    NMValueStrv kernel_command_line;
    NMValueStrv driver;
    NMValueStrv path;
};

struct _NMSettingMatchClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingMatch, nm_setting_match, NM_TYPE_SETTING)

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
nm_setting_match_get_num_interface_names(NMSettingMatch *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), 0);

    return nm_g_array_len(setting->interface_name.arr);
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
nm_setting_match_get_interface_name(NMSettingMatch *setting, int idx)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), NULL);

    g_return_val_if_fail(setting->interface_name.arr && idx >= 0
                             && idx < setting->interface_name.arr->len,
                         NULL);

    return nm_strvarray_get_idx(setting->interface_name.arr, idx);
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
nm_setting_match_add_interface_name(NMSettingMatch *setting, const char *interface_name)
{
    g_return_if_fail(NM_IS_SETTING_MATCH(setting));
    g_return_if_fail(interface_name);

    nm_strvarray_add(nm_strvarray_ensure(&setting->interface_name.arr), interface_name);
    _notify(setting, PROP_INTERFACE_NAME);
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
nm_setting_match_remove_interface_name(NMSettingMatch *setting, int idx)
{
    g_return_if_fail(NM_IS_SETTING_MATCH(setting));

    g_return_if_fail(setting->interface_name.arr && idx >= 0
                     && idx < setting->interface_name.arr->len);

    g_array_remove_index(setting->interface_name.arr, idx);
    _notify(setting, PROP_INTERFACE_NAME);
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
nm_setting_match_remove_interface_name_by_value(NMSettingMatch *setting, const char *interface_name)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), FALSE);
    g_return_val_if_fail(interface_name, FALSE);

    if (nm_strvarray_remove_first(setting->interface_name.arr, interface_name)) {
        _notify(setting, PROP_INTERFACE_NAME);
        return TRUE;
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
nm_setting_match_clear_interface_names(NMSettingMatch *setting)
{
    g_return_if_fail(NM_IS_SETTING_MATCH(setting));

    if (nm_g_array_len(setting->interface_name.arr) != 0) {
        nm_clear_pointer(&setting->interface_name.arr, g_array_unref);
        _notify(setting, PROP_INTERFACE_NAME);
    }
}

/**
 * nm_setting_match_get_interface_names:
 * @setting: the #NMSettingMatch
 * @length: (out) (optional): the length of the returned interface names array.
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
nm_setting_match_get_interface_names(NMSettingMatch *setting, guint *length)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), NULL);

    return nm_strvarray_get_strv(&setting->interface_name.arr, length);
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
nm_setting_match_get_num_kernel_command_lines(NMSettingMatch *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), 0);

    return nm_g_array_len(setting->kernel_command_line.arr);
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
nm_setting_match_get_kernel_command_line(NMSettingMatch *setting, guint idx)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), NULL);

    g_return_val_if_fail(setting->kernel_command_line.arr
                             && idx < setting->kernel_command_line.arr->len,
                         NULL);

    return nm_strvarray_get_idx(setting->kernel_command_line.arr, idx);
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
nm_setting_match_add_kernel_command_line(NMSettingMatch *setting, const char *kernel_command_line)
{
    g_return_if_fail(NM_IS_SETTING_MATCH(setting));
    g_return_if_fail(kernel_command_line);

    nm_strvarray_add(nm_strvarray_ensure(&setting->kernel_command_line.arr), kernel_command_line);
    _notify(setting, PROP_KERNEL_COMMAND_LINE);
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
nm_setting_match_remove_kernel_command_line(NMSettingMatch *setting, guint idx)
{
    g_return_if_fail(NM_IS_SETTING_MATCH(setting));

    g_return_if_fail(setting->kernel_command_line.arr
                     && idx < setting->kernel_command_line.arr->len);

    g_array_remove_index(setting->kernel_command_line.arr, idx);
    _notify(setting, PROP_KERNEL_COMMAND_LINE);
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
nm_setting_match_remove_kernel_command_line_by_value(NMSettingMatch *setting,
                                                     const char     *kernel_command_line)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), FALSE);
    g_return_val_if_fail(kernel_command_line, FALSE);

    if (nm_strvarray_remove_first(setting->kernel_command_line.arr, kernel_command_line)) {
        _notify(setting, PROP_KERNEL_COMMAND_LINE);
        return TRUE;
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
nm_setting_match_clear_kernel_command_lines(NMSettingMatch *setting)
{
    g_return_if_fail(NM_IS_SETTING_MATCH(setting));

    if (nm_g_array_len(setting->kernel_command_line.arr) != 0) {
        nm_clear_pointer(&setting->kernel_command_line.arr, g_array_unref);
        _notify(setting, PROP_KERNEL_COMMAND_LINE);
    }
}

/**
 * nm_setting_match_get_kernel_command_lines:
 * @setting: the #NMSettingMatch
 * @length: (out) (optional): the length of the returned interface names array.
 *
 * Returns all the interface names.
 *
 * Returns: (transfer none) (array length=length): the configured interface names.
 *
 * Since: 1.26
 **/
const char *const *
nm_setting_match_get_kernel_command_lines(NMSettingMatch *setting, guint *length)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), NULL);

    return nm_strvarray_get_strv(&setting->kernel_command_line.arr, length);
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
nm_setting_match_get_num_drivers(NMSettingMatch *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), 0);

    return nm_g_array_len(setting->driver.arr);
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
nm_setting_match_get_driver(NMSettingMatch *setting, guint idx)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), NULL);

    g_return_val_if_fail(setting->driver.arr && idx < setting->driver.arr->len, NULL);

    return nm_strvarray_get_idx(setting->driver.arr, idx);
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
nm_setting_match_add_driver(NMSettingMatch *setting, const char *driver)
{
    g_return_if_fail(NM_IS_SETTING_MATCH(setting));
    g_return_if_fail(driver);

    nm_strvarray_add(nm_strvarray_ensure(&setting->driver.arr), driver);
    _notify(setting, PROP_DRIVER);
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
nm_setting_match_remove_driver(NMSettingMatch *setting, guint idx)
{
    g_return_if_fail(NM_IS_SETTING_MATCH(setting));

    g_return_if_fail(setting->driver.arr && idx < setting->driver.arr->len);

    g_array_remove_index(setting->driver.arr, idx);
    _notify(setting, PROP_DRIVER);
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
nm_setting_match_remove_driver_by_value(NMSettingMatch *setting, const char *driver)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), FALSE);
    g_return_val_if_fail(driver, FALSE);

    if (nm_strvarray_remove_first(setting->driver.arr, driver)) {
        _notify(setting, PROP_DRIVER);
        return TRUE;
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
nm_setting_match_clear_drivers(NMSettingMatch *setting)
{
    g_return_if_fail(NM_IS_SETTING_MATCH(setting));

    if (nm_g_array_len(setting->driver.arr) != 0) {
        nm_clear_pointer(&setting->driver.arr, g_array_unref);
        _notify(setting, PROP_DRIVER);
    }
}

/**
 * nm_setting_match_get_drivers:
 * @setting: the #NMSettingMatch
 * @length: (out) (optional): the length of the returned interface names array.
 *
 * Returns all the drivers.
 *
 * Returns: (transfer none) (array length=length): the configured drivers.
 *
 * Since: 1.26
 **/
const char *const *
nm_setting_match_get_drivers(NMSettingMatch *setting, guint *length)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), NULL);

    return nm_strvarray_get_strv(&setting->driver.arr, length);
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
nm_setting_match_get_num_paths(NMSettingMatch *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), 0);

    return nm_g_array_len(setting->path.arr);
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
nm_setting_match_get_path(NMSettingMatch *setting, guint idx)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), NULL);

    g_return_val_if_fail(setting->path.arr && idx < setting->path.arr->len, NULL);

    return nm_strvarray_get_idx(setting->path.arr, idx);
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
nm_setting_match_add_path(NMSettingMatch *setting, const char *path)
{
    g_return_if_fail(NM_IS_SETTING_MATCH(setting));
    g_return_if_fail(path);

    nm_strvarray_add(nm_strvarray_ensure(&setting->path.arr), path);
    _notify(setting, PROP_PATH);
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
nm_setting_match_remove_path(NMSettingMatch *setting, guint idx)
{
    g_return_if_fail(NM_IS_SETTING_MATCH(setting));

    g_return_if_fail(setting->path.arr && idx < setting->path.arr->len);

    g_array_remove_index(setting->path.arr, idx);
    _notify(setting, PROP_PATH);
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
nm_setting_match_remove_path_by_value(NMSettingMatch *setting, const char *path)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), FALSE);
    g_return_val_if_fail(path, FALSE);

    if (nm_strvarray_remove_first(setting->path.arr, path)) {
        _notify(setting, PROP_PATH);
        return TRUE;
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
nm_setting_match_clear_paths(NMSettingMatch *setting)
{
    g_return_if_fail(NM_IS_SETTING_MATCH(setting));

    if (nm_g_array_len(setting->path.arr) != 0) {
        nm_clear_pointer(&setting->path.arr, g_array_unref);
        _notify(setting, PROP_PATH);
    }
}

/**
 * nm_setting_match_get_paths:
 * @setting: the #NMSettingMatch
 * @length: (out) (optional): the length of the returned paths array.
 *
 * Returns all the paths.
 *
 * Returns: (transfer none) (array length=length): the configured paths.
 *
 * Since: 1.26
 **/
const char *const *
nm_setting_match_get_paths(NMSettingMatch *setting, guint *length)
{
    g_return_val_if_fail(NM_IS_SETTING_MATCH(setting), NULL);

    return nm_strvarray_get_strv(&setting->path.arr, length);
}

/*****************************************************************************/

static void
nm_setting_match_init(NMSettingMatch *setting)
{}

/**
 * nm_setting_match_new:
 *
 * Creates a new #NMSettingMatch object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingMatch object
 *
 * Note that this function was present in header files since version 1.14.
 * But due to a bug the symbol is only exposed and usable since version 1.32.
 * As workaround, use g_object_new(NM_TYPE_SETTING_MATCH) which works with all
 * versions since 1.14.
 *
 * Since: 1.32
 **/
NMSetting *
nm_setting_match_new(void)
{
    /* Note that function nm_setting_match_new() was libnm headers from 1.14+,
     * but due to a bug was the symbol only exposed since version 1.32+.
     *
     * The workaround is to always use g_object_new(), which works for all
     * versions since 1.14.
     *
     * As such, this function must never do anything except calling
     * g_object_new() to not break the workaround. */
    return g_object_new(NM_TYPE_SETTING_MATCH, NULL);
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingMatch *self = NM_SETTING_MATCH(setting);
    guint           i;

    if (self->interface_name.arr) {
        for (i = 0; i < self->interface_name.arr->len; i++) {
            if (nm_str_is_empty(nm_strvarray_get_idx(self->interface_name.arr, i))) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("is empty"));
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_MATCH_SETTING_NAME,
                               NM_SETTING_MATCH_INTERFACE_NAME);
                return FALSE;
            }
        }
    }

    if (self->kernel_command_line.arr) {
        for (i = 0; i < self->kernel_command_line.arr->len; i++) {
            if (nm_str_is_empty(nm_strvarray_get_idx(self->kernel_command_line.arr, i))) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("is empty"));
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_MATCH_SETTING_NAME,
                               NM_SETTING_MATCH_KERNEL_COMMAND_LINE);
                return FALSE;
            }
        }
    }

    if (self->driver.arr) {
        for (i = 0; i < self->driver.arr->len; i++) {
            if (nm_str_is_empty(nm_strvarray_get_idx(self->driver.arr, i))) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("is empty"));
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_MATCH_SETTING_NAME,
                               NM_SETTING_MATCH_DRIVER);
                return FALSE;
            }
        }
    }

    if (self->path.arr) {
        for (i = 0; i < self->path.arr->len; i++) {
            if (nm_str_is_empty(nm_strvarray_get_idx(self->path.arr, i))) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("is empty"));
                g_prefix_error(error,
                               "%s.%s: ",
                               NM_SETTING_MATCH_SETTING_NAME,
                               NM_SETTING_MATCH_PATH);
                return FALSE;
            }
        }
    }

    return TRUE;
}

static void
finalize(GObject *object)
{
    NMSettingMatch *self = NM_SETTING_MATCH(object);

    nm_clear_pointer(&self->interface_name.arr, g_array_unref);
    nm_clear_pointer(&self->kernel_command_line.arr, g_array_unref);
    nm_clear_pointer(&self->driver.arr, g_array_unref);
    nm_clear_pointer(&self->path.arr, g_array_unref);

    G_OBJECT_CLASS(nm_setting_match_parent_class)->finalize(object);
}

static void
nm_setting_match_class_init(NMSettingMatchClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;
    object_class->finalize     = finalize;

    setting_class->verify = verify;

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
    _nm_setting_property_define_direct_strv(properties_override,
                                            obj_properties,
                                            NM_SETTING_MATCH_INTERFACE_NAME,
                                            PROP_INTERFACE_NAME,
                                            NM_SETTING_PARAM_FUZZY_IGNORE,
                                            NMSettingMatch,
                                            interface_name);

    /**
     * NMSettingMatch:kernel-command-line
     *
     * A list of kernel command line arguments to match. This may be used to check
     * whether a specific kernel command line option is set (or unset, if prefixed with
     * the exclamation mark). The argument must either be a single word, or
     * an assignment (i.e. two words, joined by "="). In the former case the kernel
     * command line is searched for the word appearing as is, or as left hand side
     * of an assignment. In the latter case, the exact assignment is looked for
     * with right and left hand side matching. Wildcard patterns are not supported.
     *
     * See NMSettingMatch:interface-name for how special characters '|', '&',
     * '!' and '\\' are used for optional and mandatory matches and inverting the
     * match.
     *
     * Since: 1.26
     **/
    _nm_setting_property_define_direct_strv(properties_override,
                                            obj_properties,
                                            NM_SETTING_MATCH_KERNEL_COMMAND_LINE,
                                            PROP_KERNEL_COMMAND_LINE,
                                            NM_SETTING_PARAM_FUZZY_IGNORE,
                                            NMSettingMatch,
                                            kernel_command_line);

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
    _nm_setting_property_define_direct_strv(properties_override,
                                            obj_properties,
                                            NM_SETTING_MATCH_DRIVER,
                                            PROP_DRIVER,
                                            NM_SETTING_PARAM_FUZZY_IGNORE,
                                            NMSettingMatch,
                                            driver);

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
    _nm_setting_property_define_direct_strv(properties_override,
                                            obj_properties,
                                            NM_SETTING_MATCH_PATH,
                                            PROP_PATH,
                                            NM_SETTING_PARAM_FUZZY_IGNORE,
                                            NMSettingMatch,
                                            path);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_MATCH,
                             NULL,
                             properties_override,
                             0);
}
