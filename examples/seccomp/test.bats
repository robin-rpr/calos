CLEARLY_TEST_TAG=$ch_test_tag
load "$CHTEST_DIR"/common.bash

setup () {
    prerequisites_ok seccomp
}

@test "${ch_tag}/fifos only" {
    clearly run "$ch_img" -- sh -c 'ls -lh /_*'
    # shellcheck disable=SC2016
    clearly run "$ch_img" -- sh -c 'test $(ls /_* | wc -l) == 2'
    clearly run "$ch_img" -- test -p /_mknod_fifo
    clearly run "$ch_img" -- test -p /_mknodat_fifo
}
