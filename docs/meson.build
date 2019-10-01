version_conf = configuration_data()
version_conf.set('VERSION', nm_version)

subdir('libnm')
subdir('api')

test(
  'check-docs',
  find_program(join_paths(source_root, 'tools', 'check-docs.sh')),
  args: [source_root, build_root],
)
