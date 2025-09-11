# Bugs in this Makefile:
#
# 1. $(EXEEXT) not included for scripts.

## C programs

bin_PROGRAMS = clearly

clearly_SOURCES = clearly.c ../cmd/net.c ../cmd/misc.c
clearly_CFLAGS = @LIBNL_CFLAGS@ -DCMDDIR="\"$(pkglibexecdir)\"" -DSYSCONFDIR="\"$(sysconfdir)/clearly\"" -I$(top_srcdir)/cmd
clearly_LDADD = @LIBMNL_LIBS@ @LIBNFTNL_LIBS@ @LIBNL_LIBS@