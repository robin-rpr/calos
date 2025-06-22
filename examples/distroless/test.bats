CLEARLY_TEST_TAG=$clearly_test_tag
load "${CHTEST_DIR}/common.bash"

setup () {
    scope standard
    prerequisites_ok distroless
}

@test "${clearly_tag}/hello" {
    run clearly run "$clearly_img" -- /hello.py
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = 'Hello, World!' ]]
}
