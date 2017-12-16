sources = files(
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
  'nmt-newt-widget.c'
)

libnmt_newt = static_library(
  'nmt-newt',
  sources: sources + [libnm_core_enum[1]],
  include_directories: incs,
  dependencies: deps,
  c_args: cflags
)

libnmt_newt_dep = declare_dependency(
  link_with: libnmt_newt,
  include_directories: include_directories('.')
)
