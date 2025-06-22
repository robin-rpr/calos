load ../common

@test 'clearly run refuses to run if setgid' {
    scope standard
    clearly_run_tmp=$BATS_TMPDIR/run.setgid
    gid=$(id -g)
    gid2=$(id -G | cut -d' ' -f2)
    echo "gids: ${gid} ${gid2}"
    [[ $gid != "$gid2" ]]
    cp -a "$clearly_runfile" "$clearly_run_tmp"
    ls -l "$clearly_run_tmp"
    chgrp "$gid2" "$clearly_run_tmp"
    chmod g+s "$clearly_run_tmp"
    ls -l "$clearly_run_tmp"
    [[ -g $clearly_run_tmp ]]
    run "$clearly_run_tmp" --version
    echo "$output"
    [[ $status -eq $CLEARLY_ERR_MISC ]]
    [[ $output = *': please report this bug ('* ]]
    rm "$clearly_run_tmp"
}

@test 'clearly run refuses to run if setuid' {
    scope standard
    [[ -n $clearly_have_sudo ]] || skip 'sudo not available'
    clearly_run_tmp=$BATS_TMPDIR/run.setuid
    cp -a "$clearly_runfile" "$clearly_run_tmp"
    ls -l "$clearly_run_tmp"
    sudo chown root "$clearly_run_tmp"
    sudo chmod u+s "$clearly_run_tmp"
    ls -l "$clearly_run_tmp"
    [[ -u $clearly_run_tmp ]]
    run "$clearly_run_tmp" --version
    echo "$output"
    [[ $status -eq $CLEARLY_ERR_MISC ]]
    [[ $output = *': please report this bug ('* ]]
    sudo rm "$clearly_run_tmp"
}

@test 'clearly run as root: --version and --test' {
    scope standard
    [[ -n $clearly_have_sudo ]] || skip 'sudo not available'
    sudo "$clearly_runfile" --version
    sudo "$clearly_runfile" --help
}

@test 'clearly run as root: run image' {
    scope standard
    # Running an image should work as root, but it doesn’t, and I'm not sure
    # why, so skip this test. This fails in the test suite with:
    #
    #   clearly run: couldn’t resolve image path: No such file or directory (run.c:139:2)
    #
    # but when run manually (with same arguments?) it fails differently with:
    #
    #   $ sudo clearly run $clearly_imgdir/chtest -- true
    #   clearly run: [...]/chtest: Permission denied (run.c:195:13)
    #
    skip 'issue #76'
    sudo "$clearly_runfile" "$clearly_timg" -- true
}

@test 'clearly run as root: root with non-zero gid refused' {
    scope standard
    [[ -n $clearly_have_sudo ]] || skip 'sudo not available'
    if ! (sudo -u root -g "$(id -gn)" true); then
        # Allowing sudo to user root but group non-root is an unusual
        # configuration. You need e.g. “%foo ALL=(ALL:ALL)” instead of the
        # more common “%foo ALL=(ALL)”. See issue #485.
        pedantic_fail 'sudo not configured for user root and group non-root'
    fi
    run sudo -u root -g "$(id -gn)" "$clearly_runfile" -v --version
    echo "$output"
    [[ $status -eq $CLEARLY_ERR_MISC ]]
    [[ $output = *'please report this bug ('* ]]
}

@test 'non-setuid fusermount3' {
    [[ $CLEARLY_TEST_PACK_FMT == squash-mount ]] || skip 'squash-mount format only'
    if [[ -u $(command -v fusermount3) ]]; then
        ls -lh "$(command -v fusermount3)"
        pedantic_fail 'fusermount3(1) is setuid'
    fi
    true  # other tests validate it actually works
}
