osrand_provider_sources = [
  'provider.c',
]

osrand_provider_map = meson.current_source_dir() / 'provider.map'
osrand_provider_ldflags = cc.get_supported_link_arguments([
  '-Wl,--version-script,' + osrand_provider_map
])

osrand_provider = shared_module(
  'osrand',
  osrand_provider_sources,
  name_prefix: '',
  dependencies: [libcrypto],
  include_directories: [configinc],
  link_depends: [osrand_provider_map],
  link_args: osrand_provider_ldflags,
  install: true,
  install_dir: provider_path,
)
