AC_INIT([libpam-freerdp], [2.0.0])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

AM_INIT_AUTOMAKE([-Wno-portability subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
# the Google Test targets are cpp
AC_PROG_CXX
AC_PROG_LIBTOOL

LT_INIT([disable-static])

###########################
# PAM
###########################

have_pam=no
AC_CHECK_LIB(pam, pam_getenv, have_pam=yes)
if test "x$have_pam" = "xno"; then
  AC_MSG_ERROR([Required library PAM was not found])
fi

###########################
# FreeRDP
###########################

# FreeRDPv3
PKG_CHECK_MODULES([FREERDP3],
                  [freerdp3],
                  [freerdp3_modules=yes],
                  [freerdp3_modules=no])
AC_SUBST([FREERDP3_CFLAGS])
AC_SUBST([FREERDP3_LIBS])
AC_SUBST([FREERDP3_LDFLAGS])
PKG_CHECK_MODULES([WINPR3],
                  [winpr3],
                  [],
                  [])
AC_SUBST([WINPR3_CFLAGS])
AC_SUBST([WINPR3_LIBS])
AC_SUBST([WINPR3_LDFLAGS])
AC_MSG_CHECKING([for FreeRDPv3 libraries])
AC_MSG_RESULT([$freerdp3_modules])

# FreeRDPv2
PKG_CHECK_MODULES([FREERDP2],
                  [freerdp2],
                  [freerdp2_modules=yes],
                  [freerdp2_modules=no])
AC_SUBST([FREERDP2_CFLAGS])
AC_SUBST([FREERDP2_LIBS])
AC_SUBST([FREERDP2_LDFLAGS])
PKG_CHECK_MODULES([WINPR2],
                  [winpr2],
                  [],
                  [])
AC_SUBST([WINPR2_CFLAGS])
AC_SUBST([WINPR2_LIBS])
AC_SUBST([WINPR2_LDFLAGS])
AC_MSG_CHECKING([for FreeRDPv2 libraries])
AC_MSG_RESULT([$freerdp2_modules])

dnl FreeRDP detection version selection.
AC_MSG_CHECKING([Whether to build against old FreeRDPv2])
AC_ARG_WITH([freerdp2],
            [AS_HELP_STRING([--with-freerdp2],
                            [Build against old FreeRDPv2])])

AS_IF([test "x$with_freerdp2" = 'xyes'],
      [AC_MSG_RESULT(yes)
       AS_IF([test "x$freerdp2_modules" = 'xno'],
             [AC_MSG_ERROR([requested FreeRDPv2, but not found])])],
      [AC_MSG_RESULT([not requested explicitly])])

AM_CONDITIONAL([HAVE_FREERDP3], [test "x$freerdp3_modules" = 'xyes' && test "x$with_freerdp2" != 'xyes'])

###########################
# PAM Module dir
###########################

PAMMODULEDIR="/lib/security"
AC_SUBST(PAMMODULEDIR)

###########################
# Google Test Dependencies
###########################

m4_include([m4/gtest.m4])
CHECK_GTEST
if test "x$have_gtest" != "xyes"; then
   AC_MSG_WARN([tests were requested but gtest is not installed.])
fi
AM_CONDITIONAL([HAVE_GTEST], [test "$have_gtest" != "no"])

###########################
# gcov coverage reporting
###########################

m4_include([m4/gcov.m4])
AC_TDD_GCOV
AM_CONDITIONAL([HAVE_GCOV], [test "x$ac_cv_check_gcov" = xyes])
AM_CONDITIONAL([HAVE_LCOV], [test "x$ac_cv_check_lcov" = xyes])
AM_CONDITIONAL([HAVE_GCOVR], [test "x$ac_cv_check_gcovr" = xyes])
AC_SUBST(COVERAGE_CFLAGS)
AC_SUBST(COVERAGE_CXXFLAGS)
AC_SUBST(COVERAGE_LDFLAGS)



AC_CONFIG_FILES([
  Makefile
  src/Makefile
  tests/Makefile
])
AC_OUTPUT
