NULL =

pamlibdir = $(PAMMODULEDIR)
pamlib_LTLIBRARIES = pam_freerdp.la

pam_freerdp_la_SOURCES = \
        auth-check-path.c auth-check-path.h			\
        pam-freerdp.c						\
        pam-freerdp-children.c					\
        $(NULL)

pam_freerdp_la_LDFLAGS =					\
        -no-undefined						\
        -module							\
        -avoid-version						\
        $(COVERAGE_LDFLAGS)					\
        $(NULL)

pam_freerdp_la_CFLAGS =						\
        -Wall -Werror						\
        -DAUTH_CHECK="\"$(libexecdir)/freerdp-auth-check\""	\
        $(COVERAGE_CFLAGS)					\
        $(NULL)

pam_freerdp_la_CPPFLAGS =					\
        -I$(top_srcdir)/include					\
        $(NULL)

pam_freerdp_la_LIBADD = \
        -lpam							\
        $(NULL)

pam_freerdpincludedir = $(includedir)/security/
pam_freerdpinclude_HEADERS =					\
        $(top_srcdir)/include/pam-freerdp.h			\
        $(NULL)

libexec_PROGRAMS =						\
        freerdp-auth-check					\
        $(NULL)

freerdp_auth_check_SOURCES =					\
        freerdp-auth-check.c					\
        $(NULL)

freerdp_auth_check_CFLAGS =					\
        -Wall -Werror						\
        $(FREERDP_CFLAGS)					\
        $(WINPR_CFLAGS)						\
        $(COVERAGE_CFLAGS)					\
        $(NULL)

freerdp_auth_check_LDADD =					\
        $(FREERDP_LIBS)						\
        $(WINPR_LIBS)						\
        $(NULL)

freerdp_auth_check_LDFLAGS =					\
        $(FREERDP_LDFLAGS)					\
        $(WINPR_LDFLAGS)					\
        $(COVERAGE_LDFLAGS)					\
        $(NULL)
