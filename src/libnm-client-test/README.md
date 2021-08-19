libnm-client-test
=================

A static helper library that is used by unit tests
on top of libnm. Mostly it's D-Bus helpers.

It has no purpose in non-test code.

Unit tests may not dynamically link with libnm. They
may also statically link with the relevant parts of libnm,
and still be able to use this helper.
