CLEARLY_TEST_TAG=$ch_test_tag
load "${CHTEST_DIR}/common.bash"

setup () {
    scope standard
    prerequisites_ok hello
    pmix_or_skip
    LC_ALL=C  # no other locales installed in container
}

@test "${ch_tag}/hello" {
    run clearly run "$ch_img" -- /hello/hello.sh
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = 'hello world' ]]
}

@test "${ch_tag}/distribution sanity" {
    # Try various simple things that should work in a basic Debian
    # distribution. (This does not test anything Clearly manipulates.)
    clearly run "$ch_img" -- /bin/bash -c true
    clearly run "$ch_img" -- /bin/true
    clearly run "$ch_img" -- find /etc -name 'a*'
    clearly run "$ch_img" -- sh -c 'echo foo | /bin/grep -E foo'
    clearly run "$ch_img" -- nice true
}
