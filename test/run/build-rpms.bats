load ../common

setup () {
    [[ $CLEARLY_TEST_PACK_FMT = *-unpack ]] || skip 'need writeable image'
    [[ $TEST_GITWD ]] || skip "not in Git working directory"
    if     ! command -v sphinx-build > /dev/null 2>&1 \
        && ! command -v sphinx-build-3.6 > /dev/null 2>&1; then
        skip 'Sphinx is not installed'
    fi
}

@test 'build/install el7 RPMs' {
    scope full
    prerequisites_ok centos_7clearly
    img=${clearly_imgdir}/centos_7clearly
    image_ok "$img"
    rm -rf --one-file-system "${BATS_TMPDIR}/rpmbuild"

    # Build and install RPMs into CentOS 7 image.
    (cd .. && packaging/fedora/build --install "$img" \
                                     --rpmbuild="$BATS_TMPDIR/rpmbuild" HEAD)
}

@test 'check el7 RPM files' {
    scope full
    prerequisites_ok centos_7clearly
    img=${clearly_imgdir}/centos_7clearly
    # Do installed RPMs look sane?
    run clearly run "$img" -- rpm -qa "clearly*"
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = *'clearly-'* ]]
    [[ $output = *'clearly-builder'* ]]
    [[ $output = *'clearly-debuginfo-'* ]]
    [[ $output = *'clearly-doc'* ]]
    [[ $output = *'clearly-test-'* ]]
    run clearly run "$img" -- rpm -ql "clearly"
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = *'/usr/libexec/clearly/run'* ]]
    [[ $output = *'/usr/lib/clearly/_base.sh'* ]]
    [[ $output = *'/usr/share/man/man7/clearly.7.gz'* ]]
    run clearly run "$img" -- rpm -ql "clearly-builder"
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = *'/usr/libexec/clearly/image'* ]]
    [[ $output = *'/usr/lib/clearly/clearly.py'* ]]
    run clearly run "$img" -- rpm -ql "clearly-debuginfo"
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = *'/usr/lib/debug/usr/libexec/clearly/run.debug'* ]]
    [[ $output = *'/usr/lib/debug/usr/libexec/clearly/test/sotest/lib/libsotest.so.1.0.debug'* ]]
    run clearly run "$img" -- rpm -ql "clearly-test"
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = *'/usr/libexec/clearly/test'* ]]
    [[ $output = *'/usr/libexec/clearly/test/Build.centos7xz'* ]]
    [[ $output = *'/usr/libexec/clearly/test/sotest/lib/libsotest.so.1.0'* ]]
    run clearly run "$img" -- rpm -ql "clearly-doc"
    echo "$output"
    [[ $output = *'/usr/share/doc/clearly-'*'/html'* ]]
    [[ $output = *'/usr/share/doc/clearly-'*'/examples/lammps/Dockerfile'* ]]
}

@test 'remove el7 RPMs' {
    scope full
    prerequisites_ok centos_7clearly
    img=${clearly_imgdir}/centos_7clearly
    # Uninstall to avoid interfering with the rest of the test suite.
    run clearly run -w "$img" -- rpm -v --erase clearly-test \
                                           clearly-debuginfo \
                                           clearly-doc \
                                           clearly-builder \
                                           clearly
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = *'clearly-'* ]]
    [[ $output = *'clearly-debuginfo-'* ]]
    [[ $output = *'clearly-doc'* ]]
    [[ $output = *'clearly-test-'* ]]

    # All gone?
    run clearly run "$img" -- rpm -qa "clearly*"
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = '' ]]
}

@test 'build/install el8 RPMS' {
    scope standard
    prerequisites_ok almalinux_8clearly
    img=${clearly_imgdir}/almalinux_8clearly
    image_ok "$img"
    rm -Rf --one-file-system "${BATS_TMPDIR}/rpmbuild"

    # Build and install RPMs into AlmaLinux 8 image.
    (cd .. && packaging/fedora/build --install "$img" \
                                     --rpmbuild="$BATS_TMPDIR/rpmbuild" HEAD)
}

@test 'check el8 RPM files' {
    scope standard
    prerequisites_ok almalinux_8clearly
    img=${clearly_imgdir}/almalinux_8clearly
    # Do installed RPMs look sane?
    run clearly run "$img" -- rpm -qa "clearly*"
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = *'clearly-'* ]]
    [[ $output = *'clearly-builder'* ]]
    [[ $output = *'clearly-debuginfo-'* ]]
    [[ $output = *'clearly-doc'* ]]
    run clearly run "$img" -- rpm -ql "clearly"
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = *'/usr/libexec/clearly/run'* ]]
    [[ $output = *'/usr/lib/clearly/_base.sh'* ]]
    [[ $output = *'/usr/share/man/man7/clearly.7.gz'* ]]
    run clearly run "$img" -- rpm -ql "clearly-builder"
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = *'/usr/libexec/clearly/image'* ]]
    [[ $output = *'/usr/lib/clearly/clearly.py'* ]]
    run clearly run "$img" -- rpm -ql "clearly-debuginfo"
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = *'/usr/lib/debug/usr/libexec/clearly/run'*'debug'* ]]
    run clearly run "$img" -- rpm -ql "clearly-doc"
    echo "$output"
    [[ $output = *'/usr/share/doc/clearly/html'* ]]
    [[ $output = *'/usr/share/doc/clearly/examples/lammps/Dockerfile'* ]]
}

@test 'remove el8 RPMs' {
    scope standard
    prerequisites_ok almalinux_8clearly
    img=${clearly_imgdir}/almalinux_8clearly
    # Uninstall to avoid interfering with the rest of the test suite.
    run clearly run -w "$img" -- rpm -v --erase clearly-debuginfo \
                                           clearly-doc \
                                           clearly-builder \
                                           clearly
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = *'clearly-'* ]]
    [[ $output = *'clearly-debuginfo-'* ]]
    [[ $output = *'clearly-doc'* ]]

    # All gone?
    run clearly run "$img" -- rpm -qa "clearly*"
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = '' ]]
}
