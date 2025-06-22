CLEARLY_TEST_TAG=$ch_test_tag
load "${CHTEST_DIR}/common.bash"

setup() {
    scope full
    prerequisites_ok spack
    export PATH=/spack/bin:$PATH
}

@test "${ch_tag}/version" {
    # Spack likes to write to $HOME/.spack; thus, we bind it.
    clearly run --home "$ch_img" -- spack --version
}

@test "${ch_tag}/compilers" {
    echo "spack compiler list"
    clearly run --home "$ch_img" -- spack compiler list
    echo "spack compiler list --scope=system"
    clearly run --home "$ch_img" -- spack compiler list --scope=system
    echo "spack compiler list --scope=user"
    clearly run --home "$ch_img" -- spack compiler list --scope=user
    echo "spack compilers"
    clearly run --home "$ch_img" -- spack compilers
}

@test "${ch_tag}/find" {
    run clearly run --home "$ch_img" -- spack find charliecloud
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = *'charliecloud@'* ]]
}
