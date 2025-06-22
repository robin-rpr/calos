CLEARLY_TEST_TAG=$clearly_test_tag
load "${CLEARLYTEST_DIR}/common.bash"

setup () {
    scope standard
    prerequisites_ok exhaustive
}

@test "${clearly_tag}/WORKDIR" {
    output_expected=$(cat <<'EOF'
/workdir:
abs2
file

/workdir/abs2:
file
rel1

/workdir/abs2/rel1:
file1
file2
rel2

/workdir/abs2/rel1/rel2:
file
EOF
)
    run clearly run "$clearly_img" -- ls -R /workdir
    echo "$output"
    [[ $status -eq 0 ]]
    diff -u <(echo "$output_expected") <(echo "$output")
}
