CLEARLY_TEST_TAG=$clearly_test_tag
load "$CHTEST_DIR"/common.bash

setup () {
    prerequisites_ok seccomp
}

@test "${clearly_tag}/fifos only" {
    clearly run "$clearly_img" -- sh -c 'ls -lh /_*'
    # shellcheck disable=SC2016
    clearly run "$clearly_img" -- sh -c 'test $(ls /_* | wc -l) == 2'
    clearly run "$clearly_img" -- test -p /_mknod_fifo
    clearly run "$clearly_img" -- test -p /_mknodat_fifo
}
