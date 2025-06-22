CLEARLY_TEST_TAG=$clearly_test_tag
load "${CLEARLYTEST_DIR}/common.bash"

setup () {
    prerequisites_ok multistage
}

@test "${clearly_tag}/hello" {
    run clearly run "$clearly_img" -- hello -g 'Hello, Clearly!'
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = 'Hello, Clearly!' ]]
}

@test "${clearly_tag}/man hello" {
    clearly run "$clearly_img" -- man hello > /dev/null
}

@test "${clearly_tag}/files seem OK" {
    [[ $CLEARLY_TEST_PACK_FMT = squash-mount ]] && skip 'need directory image'
    # hello executable itself.
    test -x "${clearly_img}/usr/local/bin/hello"
    # Present by default.
    test -d "${clearly_img}/usr/local/share/applications"
    test -d "${clearly_img}/usr/local/share/info"
    test -d "${clearly_img}/usr/local/share/man"
    # Copied from first stage.
    test -d "${clearly_img}/usr/local/share/locale"
    # Correct file count in directories.
    ls -lh "${clearly_img}/usr/local/bin"
    [[ $(find "${clearly_img}/usr/local/bin" -mindepth 1 -maxdepth 1 | wc -l) -eq 1 ]]
    ls -lh "${clearly_img}/usr/local/share"
    [[ $(find "${clearly_img}/usr/local/share" -mindepth 1 -maxdepth 1 | wc -l) -eq 4 ]]
}

@test "${clearly_tag}/no first-stage stuff present" {
    # Can’t run GCC.
    run clearly run "$clearly_img" -- gcc --version
    echo "$output"
    [[ $status -eq $CLEARLY_ERR_CMD ]]
    [[ $output = *'gcc: No such file or directory'* ]]

    # No GCC or Make.
    ls -lh "${clearly_img}/usr/bin/gcc" || true
    [[ ! -f "${clearly_img}/usr/bin/gcc" ]]
    ls -lh "${clearly_img}/usr/bin/make" || true
    [[ ! -f "${clearly_img}/usr/bin/make" ]]
}
