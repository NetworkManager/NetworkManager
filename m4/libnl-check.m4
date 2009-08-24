AC_DEFUN([NM_LIBNL_CHECK], [
    AC_MSG_CHECKING([for libnl address caching bug])
    save_CFLAGS="$CFLAGS"
    save_LDFLAGS="$LDFLAGS"
    CFLAGS="$CFLAGS $LIBNL_CFLAGS"
    LDFLAGS="$LDFLAGS $LIBNL_LIBS"
    AC_RUN_IFELSE([
#include <stdio.h>
#include <netlink/route/addr.h>
#include <netlink/object-api.h>

int
main (int argc, char **argv)
{
	struct nl_handle *nlh;
	struct nl_cache *cache;
	struct nl_object *obj;

	nlh = nl_handle_alloc ();
	if (nl_connect (nlh, NETLINK_ROUTE) < 0) {
		fprintf (stderr, "couldn't connect to netlink: %s", nl_geterror ());
		return 3;
	}

	cache = rtnl_addr_alloc_cache (nlh);
	if (!cache || nl_cache_nitems (cache) == 0) {
		fprintf (stderr, "couldn't fill address cache: %s", nl_geterror ());
		return 3;
	}

	obj = nl_cache_get_first (cache);
	if (nl_object_identical (obj, obj))
		return 0;

	nl_cache_get_ops (cache)->co_obj_ops->oo_id_attrs &= ~0x80;
	if (nl_object_identical (obj, obj))
		return 1;
	else
		return 2;
}
], libnl_bug=$?, libnl_bug=$?, libnl_bug=cross)

    CFLAGS="$save_CFLAGS"
    LDFLAGS="$save_LDFLAGS"

    case $libnl_bug in
    0) AC_MSG_RESULT([no])
       ;;

    1) AC_MSG_RESULT([yes, using workaround])
       AC_DEFINE(LIBNL_NEEDS_ADDR_CACHING_WORKAROUND, 1, [Define this to hack around buggy libnl rtnl_addr caching])
       ;;

    2) AC_MSG_RESULT([yes, and workaround doesn't work])
       AC_MSG_ERROR([Installed libnl has broken address caching; please patch or upgrade])
       ;;

    cross) AC_MSG_RESULT([cross-compiling... assuming it works!])
           ;;

    *) AC_MSG_RESULT([?])
       AC_MSG_ERROR([libnl test program failed])
       ;;
esac
])
