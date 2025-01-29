test_env = environment({
  'LIBSPATH': meson.project_build_root() / 'src',
  'TESTSSRCDIR': meson.current_source_dir(),
  'TESTBLDDIR': meson.current_build_dir(),
  'SHARED_EXT': shlext,
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

trand_wrapper = find_program('trand-wrapper.sh')

test(
  'trand',
  trand_wrapper,
  env: test_env,
  depends: test_executables,
  is_parallel: false,
)
