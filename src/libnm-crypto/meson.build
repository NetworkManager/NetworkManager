# SPDX-License-Identifier: LGPL-2.1-or-later

if crypto_nss_dep.found()
  libnm_crypto_nss = static_library(
    'nm-crypto-nss',
    sources: 'nm-crypto-nss.c',
    include_directories: [
      top_inc,
      src_inc,
    ],
    dependencies: [
      glib_dep,
      crypto_nss_dep,
    ],
  )
endif

if crypto_gnutls_dep.found()
  libnm_crypto_gnutls = static_library(
    'nm-crypto-gnutls',
    sources: 'nm-crypto-gnutls.c',
    include_directories: [
      top_inc,
      src_inc,
    ],
    dependencies: [
      glib_dep,
      crypto_gnutls_dep,
    ],
  )
endif

libnm_crypto_null = static_library(
  'nm-crypto-null',
  sources: 'nm-crypto-null.c',
  include_directories: [
    top_inc,
    src_inc,
  ],
  dependencies: [
    glib_dep,
  ],
)

if crypto == 'nss'
  libnm_crypto_impl = libnm_crypto_nss
elif crypto == 'gnutls'
  libnm_crypto_impl = libnm_crypto_gnutls
else
  assert(crypto == 'null', 'Unexpected setting "crypto=' + crypto + '"')
  libnm_crypto_impl = libnm_crypto_null
endif

libnm_crypto = static_library(
  'nm-crypto',
  sources: [
    'nm-crypto.c',
  ],
  include_directories: [
    top_inc,
    src_inc,
  ],
  link_with: [
    libnm_crypto_impl,
  ],
  dependencies: [
    glib_dep,
  ],
)
