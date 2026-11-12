#!/bin/bash
# Checks carrel-fnd against concurrent builds, a second daemon and a daemon crash.
# Run as root on a function host with Docker image fnlab-py2 present.
# usage: resilience.sh <carrel-fnd> <carrel-fn-init> <firecracker> <jailer>
set -u
FND=$1; INIT=$2; FC=$3; JAILER=$4
ROOT=/var/lib/carrel-fn
RUN="-firecracker $FC -jailer $JAILER"
BUILD="$FND build -image fnlab-py2 -port 80 -init $INIT $RUN"
fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }
vms() { pgrep -c -x firecracker; }

LOG=$(mktemp -d)
pkill -x carrel-fnd; pkill -x firecracker; sleep 1
rm -rf $ROOT/py $ROOT/job $ROOT/.jail
for ns in $(ip netns list | awk '/^cfn/ {print $1}'); do ip netns del "$ns"; done   # left by earlier runs

# Two functions build at once in different slots; a second build of one function is refused.
$BUILD -name py -idle 3 > $LOG/build-py.log 2>&1 & first=$!
$BUILD -name job -mode fresh > $LOG/build-job.log 2>&1 & second=$!
sleep 0.5
$BUILD -name py -idle 3 > $LOG/build-py2.log 2>&1
check "a second build of the same function is refused" "$(grep -c 'is being built' $LOG/build-py2.log)" 1
wait $first; check "build of py beside another build" $? 0
wait $second; check "build of job beside another build" $? 0
check "both functions have a version" "$(ls -d $ROOT/py/v/* $ROOT/job/v/* 2>/dev/null | wc -l)" 2
check "no jail or build cgroup is left" "$(ls $ROOT/.jail/firecracker 2>/dev/null | wc -l)$(ls /sys/fs/cgroup/carrel-fn | grep -c cfnb)" 00

# One router per directory.
$FND serve -slots 8 $RUN > $LOG/fnd.log 2>&1 & daemon=$!
sleep 2
timeout 10 $FND serve -slots 8 $RUN > $LOG/fnd-second.log 2>&1
check "a second serve on the same directory is refused" "$(grep -c 'another carrel-fnd serve' $LOG/fnd-second.log)" 1

# A daemon that is killed leaves its Firecracker running; the next daemon ends it.
check "request before the crash" "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Carrel-Function: py' http://127.0.0.1:8090/)" 200
kill -9 $daemon; wait $daemon 2>/dev/null; sleep 0.5
check "the crash leaves an orphan microVM" "$(vms)" 1
orphan=$(pgrep -o -x firecracker)
$FND serve -slots 8 $RUN > $LOG/fnd.log 2>&1 & daemon=$!
sleep 2
check "the next daemon ends the orphan" "$(vms)$(test -d /proc/$orphan && echo alive)" 0
check "no cgroup of the old instance is left" "$(ls /sys/fs/cgroup/carrel-fn | grep -c '^cfn')" 0
check "request after the restart" "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Carrel-Function: py' http://127.0.0.1:8090/)" 200

# A clean stop ends every instance.
kill -TERM $daemon; wait $daemon
check "a clean stop leaves no microVM" "$(vms)" 0
check "a clean stop leaves no network namespace" "$(ip netns list | grep -c '^cfn')" 0
[ $fail = 0 ] && echo "RESULT all pass" || echo "RESULT FAILED"
