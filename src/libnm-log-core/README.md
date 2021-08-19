libnm-log-core
==============

libnm-glib-aux has a forward-declaration of logging API.
If a libnm-glib-aux user uses that API for logging, it must
link the final binary with an implementation.

There are two implementations: libnm-log-core and
[../libnm-log-null/(..libnm-log-null/). This one is the implementation
used by the daemon and logs to syslog/journald.
