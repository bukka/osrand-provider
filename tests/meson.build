conf_env = environment({
  'LIBSPATH': meson.project_build_root() / 'src',
  'TESTSSRCDIR': meson.current_source_dir(),
  'TESTBLDDIR': meson.current_build_dir(),
  'SHARED_EXT': shlext,
})

setup_script=find_program('setup.sh')
test(
  'setup',
  setup_script,
  env: conf_env,
  is_parallel: false,
)

test_env = environment({
  'TEST_PATH': meson.current_source_dir(),
  'TESTBLDDIR': meson.current_build_dir(),
})

test_programs = {
  'trand': ['trand.c'],
}

test_executables = []
foreach t, sources : test_programs
  t = executable(t, sources,
                 build_by_default: false,
                 include_directories: [configinc],
                 dependencies: [libcrypto, libssl])
  test_executables += [t]
endforeach

trabd_wrapper = find_program('trand-wrapper.sh')

test(
  'trand',
  trabd_wrapper,
  env: test_env,
  is_parallel: false,
)
