#!/usr/bin/env bash
# Runs one test binary many times at once, to bring out races that a single
# `cargo test` almost never hits, and tallies the outcome.
#
#   scripts/stress.sh [-p package] [-n runs] [-j parallel] [-t seconds] <test> [filter]
#
#   <test>      the integration test target (`interop` for tests/interop.rs),
#               or `lib` for the package's unit tests
#   [filter]    a test name filter, as `cargo test` takes it
#   -p package  default iec104-tokio
#   -n runs     how many runs in all (default 100)
#   -j parallel how many run at once (default: the number of CPUs)
#   -t seconds  the time-out of one run (default 300)
#
# Every run writes its output, with `--nocapture` and `RUST_LOG` (default
# `info`), to its own file in target/stress/<package>-<test>-<time>/, so a
# failure's log belongs to that run alone. At the end: how many runs passed,
# failed or did not finish, the distinct panic locations, the logs of the
# first failures, and, where `nstat` exists, the kernel's TCP counters over
# the whole stress (a reconnect storm shows as TIME_WAIT overflows and SYN
# retransmissions). Exits 1 if any run did not pass.
#
# Count concurrent tests, not processes: a binary whose tests run in
# parallel runs several at once per copy. Pick -j so that about three times
# the CPUs' worth of tests run at once; far beyond that, every test only
# times out. Copies of one binary must not share files: a test that writes
# files keeps them in a directory of its own process.
set -euo pipefail

package=iec104-tokio
runs=100
jobs=$(nproc 2>/dev/null || echo 4)
seconds=300
usage() {
    sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2
    exit 2
}
while getopts "p:n:j:t:h" opt; do
    case $opt in
    p) package=$OPTARG ;;
    n) runs=$OPTARG ;;
    j) jobs=$OPTARG ;;
    t) seconds=$OPTARG ;;
    *) usage ;;
    esac
done
shift $((OPTIND - 1))
[[ $# -ge 1 && $# -le 2 ]] || usage
target=$1
filter=${2:-}

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

if [[ $target == lib ]]; then
    selector=(--lib)
else
    selector=(--test "$target")
fi
echo "building $package ${selector[*]}"
bin=$(cargo test -p "$package" "${selector[@]}" --no-run 2>&1 \
    | sed -n 's/.*Executable .*(\(.*\))$/\1/p' | tail -1)
[[ -n $bin && -x $bin ]] || { echo "no test binary for $package ${selector[*]}" >&2; exit 1; }

logs="$root/target/stress/$package-$target-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$logs"
echo "running $bin${filter:+ $filter}: $runs runs, $jobs at a time, logs in $logs"

counters=false
if command -v nstat >/dev/null; then
    nstat -n >/dev/null 2>&1 && counters=true
fi

export BIN=$bin LOGS=$logs SECONDS_PER_RUN=$seconds FILTER=$filter
export RUST_LOG=${RUST_LOG:-info}
# A run that fails or times out makes xargs exit non-zero; the tally below
# is the verdict.
seq 1 "$runs" | xargs -P "$jobs" -I{} sh -c \
    'timeout "$SECONDS_PER_RUN" "$BIN" $FILTER --nocapture > "$LOGS/$1.log" 2>&1' _ {} || true

# grep finds nothing in some of these: not an error here.
count() { { grep -l "$1" "$logs"/*.log || true; } | wc -l; }
passed=$(count '^test result: ok')
failed=$(count '^test result: FAILED')
unfinished=$((runs - passed - failed))
echo
echo "passed $passed, failed $failed, did not finish $unfinished (of $runs)"
if ((passed > 0)) && [[ $(count '^test result: ok\. [1-9]') -eq 0 ]]; then
    echo "warning: no run ran a test; does the filter match one?"
fi
if ((failed + unfinished > 0)); then
    echo
    echo "panics:"
    { grep -h 'panicked at' "$logs"/*.log || true; } | sed -E 's/ \([0-9]+\)//' | sort | uniq -c | sort -rn \
        | { grep . || echo "  none: the runs that did not pass were cut off by the time-out (-t)"; }
    echo
    echo "first logs that did not pass:"
    { grep -L '^test result: ok' "$logs"/*.log || true; } | head -5 | sed 's/^/  /'
fi
if $counters; then
    echo
    echo "kernel TCP counters during the stress:"
    { nstat 2>/dev/null || true; } \
        | { grep -E 'TcpActiveOpens|TimeWaitOverflow|TCPSynRetrans|TCPRetransFail|ListenDrops|ListenOverflows' || echo "none of note"; } \
        | sed 's/^/  /'
fi
((failed + unfinished == 0))
