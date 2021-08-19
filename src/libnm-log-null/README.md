libnm-log-null
==============

libnm-glib-aux has a forward-declaration of logging API.
If a libnm-glib-aux user uses that API for logging, it must
link the final binary with an implementation.

There are two implementations: libnm-log-null and
[../libnm-log-core/(..libnm-log-core/). This one is a dummy implementation
that drops all logging.
