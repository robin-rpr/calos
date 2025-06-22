CLEARLY_TEST_TAG=$clearly_test_tag
load "${CLEARLYTEST_DIR}/common.bash"

setup () {
    scope standard
    prerequisites_ok obspy
    indir=$CLEARLYTEST_EXAMPLES_DIR/obspy
    outdir=$BATS_TMPDIR/obspy
}

@test "${clearly_tag}/hello" {
    # Remove prior test’s plot to avoid using it if something else breaks.
    mkdir -p "$outdir"
    rm -f "$outdir"/obspy.png
    clearly run -b "${outdir}:/mnt" "$clearly_img" -- /hello.py /mnt/obspy.png
}

@test "${clearly_tag}/hello PNG" {
    pict_ok
    pict_assert_equal "${indir}/obspy.png" \
                      "${outdir}/obspy.png" 1
}
