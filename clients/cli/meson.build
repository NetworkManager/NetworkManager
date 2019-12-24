name = 'nmcli'

# FIXME: nmcli-completion should be renamed to nmcli
install_data(
  'nmcli-completion',
  install_dir: join_paths(nm_datadir, 'bash-completion', 'completions'),
)

deps = [
  libnmc_base_dep,
  libnmc_dep,
  readline_dep,
  libnm_libnm_aux_dep,
]

executable(
  name,
  files(
    'agent.c',
    'common.c',
    'connections.c',
    'devices.c',
    'general.c',
    'nmcli.c',
    'polkit-agent.c',
    'settings.c',
    'utils.c',
  ),
  dependencies: deps,
  c_args: clients_c_flags + ['-DG_LOG_DOMAIN="@0@"'.format(name)],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
)
