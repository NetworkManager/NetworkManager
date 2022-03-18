libnm-crypto
============

libnm-core has a dependency on crypto code (either backed by
"gnutls", "nss" or the "null" dummy implementation).

libnm-core gets then statically linked into the daemon and into libnm.so.
