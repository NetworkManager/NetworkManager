nm-compat-headers
=================

When we build against older system headers, we sometimes
want to use newer features. This directory contains compat
headers that patch the included sources with what we need.

The goal is similar to linux-headers directory, but the approach
is different. The former completely replaces system headers
while this uses system headers and extends them.
