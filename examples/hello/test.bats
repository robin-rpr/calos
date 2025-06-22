CLEARLY_TEST_TAG=$clearly_test_tag
load "${CLEARLYTEST_DIR}/common.bash"

setup () {
    scope standard
    prerequisites_ok hello
    pmix_or_skip
    LC_ALL=C  # no other locales installed in container
}

@test "${clearly_tag}/hello" {
    run clearly run "$clearly_img" -- /hello/hello.sh
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = 'hello world' ]]
}

@test "${clearly_tag}/distribution sanity" {
    # Try various simple things that should work in a basic Debian
    # distribution. (This does not test anything Clearly manipulates.)
    clearly run "$clearly_img" -- /bin/bash -c true
    clearly run "$clearly_img" -- /bin/true
    clearly run "$clearly_img" -- find /etc -name 'a*'
    clearly run "$clearly_img" -- sh -c 'echo foo | /bin/grep -E foo'
    clearly run "$clearly_img" -- nice true
}
