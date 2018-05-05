NULL =

pamlibdir = $(PAMMODULEDIR)
pamlib_LTLIBRARIES = pam_freerdp2.la

pam_freerdp2_la_SOURCES = \
        auth-check-path.c auth-check-path.h			\
        pam-freerdp2.c						\
        pam-freerdp2-children.c					\
        $(NULL)

pam_freerdp2_la_LDFLAGS =					\
        -no-undefined						\
        -module							\
        -avoid-version						\
        $(COVERAGE_LDFLAGS)					\
        $(NULL)

pam_freerdp2_la_CFLAGS =					\
        -Wall -Werror						\
        -DAUTH_CHECK="\"$(libexecdir)/freerdp2-auth-check\""	\
        $(COVERAGE_CFLAGS)					\
        $(NULL)

pam_freerdp2_la_CPPFLAGS =					\
        -I$(top_srcdir)/include					\
        $(NULL)

pam_freerdp2_la_LIBADD = \
        -lpam							\
        $(NULL)

pam_freerdp2includedir = $(includedir)/security/
pam_freerdp2include_HEADERS =					\
        $(top_srcdir)/include/pam-freerdp2.h			\
        $(NULL)

libexec_PROGRAMS =						\
        freerdp2-auth-check					\
        $(NULL)

freerdp2_auth_check_SOURCES =					\
        freerdp2-auth-check.c					\
        $(NULL)

freerdp2_auth_check_CFLAGS =					\
        $(FREERDP2_CFLAGS)					\
        $(WINPR2_CFLAGS)					\
        $(COVERAGE_CFLAGS)					\
        $(NULL)

freerdp2_auth_check_LDADD =					\
        $(FREERDP2_LIBS)					\
        $(WINPR2_LIBS)						\
        $(NULL)

freerdp2_auth_check_LDFLAGS =					\
        $(FREERDP2_LDFLAGS)					\
        $(WINPR2_LDFLAGS)					\
        $(COVERAGE_LDFLAGS)					\
        $(NULL)
