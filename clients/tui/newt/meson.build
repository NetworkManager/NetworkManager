# SPDX-License-Identifier: LGPL-2.1-or-later

libnmt_newt = static_library(
  'nmt-newt',
  sources: files(
    'nmt-newt-button-box.c',
    'nmt-newt-button.c',
    'nmt-newt-checkbox.c',
    'nmt-newt-component.c',
    'nmt-newt-container.c',
    'nmt-newt-entry.c',
    'nmt-newt-entry-numeric.c',
    'nmt-newt-form.c',
    'nmt-newt-grid.c',
    'nmt-newt-hacks.c',
    'nmt-newt-label.c',
    'nmt-newt-listbox.c',
    'nmt-newt-popup.c',
    'nmt-newt-section.c',
    'nmt-newt-separator.c',
    'nmt-newt-stack.c',
    'nmt-newt-textbox.c',
    'nmt-newt-toggle-button.c',
    'nmt-newt-utils.c',
    'nmt-newt-widget.c',
  ),
  dependencies: [
    libnm_nm_default_dep,
    newt_dep,
  ],
  c_args: [
    '-DG_LOG_DOMAIN="nmtui"',
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
  ],
)

libnmt_newt_dep = declare_dependency(
  include_directories: include_directories('.'),
  dependencies: newt_dep,
  link_with: libnmt_newt,
)
