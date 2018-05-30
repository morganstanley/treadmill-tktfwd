AC_INIT(treadmill-tktfwd, m4_esyscmd_s([git describe --tags HEAD --long --match "v*" 2>/dev/null | cut -b 2- | cut -d '-' -f 1]), andreikeis@noreply.users.github.com)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(src/tkt_send.cpp)
AM_INIT_AUTOMAKE([tar-pax])
CXXFLAGS="$CXXFLAGS -std=c++0x"
AC_PROG_CXX
AC_CHECK_HEADERS([gssapi/gssapi.h])
AC_CHECK_HEADERS([event.h])
AC_CHECK_LIB(
    [gssapi_krb5], 
    [gss_accept_sec_context], [], 
    [AC_MSG_ERROR([GSSAPI library check failed])]
)
AC_CHECK_LIB(
    [krb5], 
    [krb5_cc_get_name], [], 
    [AC_MSG_ERROR([krb5 library check failed])]
)
AC_CHECK_LIB(
    [com_err], 
    [error_message], [], 
    [AC_MSG_ERROR([com_err library check failed])]
)
AC_CHECK_LIB(
    [event], 
    [event_add], [], 
    [AC_MSG_ERROR([libevent library check failed])]
)
AC_OUTPUT(Makefile src/Makefile)

