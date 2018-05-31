test_unit = 'test-ibft'

test_ibft_dir = meson.current_source_dir()

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_nm_dep,
  c_args: nm_build_cflags,
  link_with: libnms_ibft_core
)

test(
  'ibft/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()]
)
