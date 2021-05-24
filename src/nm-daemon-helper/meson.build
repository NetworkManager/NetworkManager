executable(
  'nm-daemon-helper',
  'nm-daemon-helper.c',
  include_directories : [
    src_inc,
    top_inc,
  ],
  link_with: [
    libnm_std_aux,
  ],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)
