testdir = $(pkgdatadir)

# These test files require no special handling.
testfiles = \
.dockerignore \
Dockerfile.argenv \
Dockerfile.quick \
bucache/a.df \
bucache/a-fail.df \
bucache/argenv.df \
bucache/argenv-special.df \
bucache/argenv2.df \
bucache/b.df \
bucache/c.df \
bucache/copy.df \
bucache/difficult.df \
bucache/force.df \
bucache/from.df \
bucache/rsync.df \
build/10_sanity.bats \
build/40_pull.bats \
build/50_image.bats \
build/50_dockerfile.bats \
build/50_localregistry.bats \
build/50_misc.bats \
build/99_cleanup.bats \
common.bash \
fixtures/empty-file \
fixtures/README \
make-auto.d/build.bats.in \
make-auto.d/build_custom.bats.in \
make-auto.d/builder_to_archive.bats.in \
make-auto.d/unpack.bats.in \
registry-config.yml \
run/build-rpms.bats \
run/equip.bats \
run/convert.bats \
run/run_escalated.bats \
run/run_isolation.bats \
run/run_join.bats \
run/run_misc.bats \
run/run_uidgid.bats \
run_first.bats \
sotest/files_inferrable.txt \
sotest/libsotest.c \
sotest/sotest.c

# Test files that should be executable.
testfiles_exec = \
Build.centos7xz \
Build.docker_pull \
Build.missing \
docs-sane \
doctest \
doctest-auto \
force-auto \
make-perms-test \
order-py

# Program and shared library used for testing shared library injection. It's
# built according to the rules below. In principle, we could use libtool for
# that, but I'm disinclined to add that in since it's one test program and
# does not require any libtool portability.
sobuilts = \
sotest/bin/sotest \
sotest/lib/libsotest.so.1.0 \
sotest/lib/libfabric/libsotest-fi.so \
sotest/libsotest.so \
sotest/libsotest.so.1 \
sotest/libsotest.so.1.0 \
sotest/sotest

CLEANFILES = $(sobuilts) \
	docs-sane \
	doctest build/30_doctest-auto.bats \
	force-auto force-auto.bats \
	make-perms-test order-py

if ENABLE_TEST
nobase_test_DATA = $(testfiles)
nobase_test_SCRIPTS = $(testfiles_exec)
nobase_nodist_test_SCRIPTS = $(sobuilts)
if ENABLE_IMAGE  # this means we have Python
nobase_test_DATA += force-auto.bats
force-auto.bats: force-auto
	./$< > $@
nobase_test_DATA += build/30_doctest-auto.bats
build/30_doctest-auto.bats: doctest-auto
	./$< > $@
endif
# See comment about symlinks in examples/Makefile.am.
all-local:
	ln -fTs /tmp fixtures/symlink-to-tmp
clean-local:
	rm -f fixtures/symlink-to-tmp
install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(testdir)/fixtures
	ln -fTs /tmp $(DESTDIR)$(testdir)/fixtures/symlink-to-tmp
uninstall-local:
	rm -f $(DESTDIR)$(testdir)/fixtures/symlink-to-tmp
	rmdir $(DESTDIR)$(testdir)/fixtures || true
endif
EXTRA_DIST = $(testfiles) \
	$(testfiles_exec) \
	docs-sane.py \
	doctest.py \
	force-auto.py \
	make-perms-test.py \
	order-py.py
EXTRA_SCRIPTS = $(sobuilts)

## Python scripts - need text processing
docs-sane doctest force-auto make-perms-test order-py: %: %.py
	rm -f $@
	cp $< $@
	chmod +rx,-w $@  # respects umask

sotest/sotest: sotest/sotest.c sotest/libsotest.so.1.0 sotest/libsotest.so sotest/libsotest.so.1
	$(CC) -o $@ $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -L./sotest -lsotest $^

sotest/libsotest.so.1.0: sotest/libsotest.c
	$(CC) -o $@ $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -shared -fPIC -Wl,-soname,libsotest.so.1 -lc $^

sotest/libsotest.so: sotest/libsotest.so.1.0
	ln -fTs ./libsotest.so.1.0 $@

sotest/libsotest.so.1: sotest/libsotest.so.1.0
	ln -fTs ./libsotest.so.1.0 $@

sotest/bin/sotest: sotest/sotest
	mkdir -p sotest/bin
	cp -a $^ $@

sotest/lib/libsotest.so.1.0: sotest/libsotest.so.1.0
	mkdir -p sotest/lib
	cp -a $^ $@

sotest/lib/libfabric/libsotest-fi.so: sotest/libsotest.so.1.0
	mkdir -p sotest/lib/libfabric
	cp -a $^ $@