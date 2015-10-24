#!/bin/bash
set -e

TESTROOT=/testroot/busybox
rm -rf ${TESTROOT}
mkdir -p ${TESTROOT}
tar -xf  rootfs.tar.gz -C ${TESTROOT}

cp cmd/runtimetest/runtimetest ${TESTROOT}

pushd $TESTROOT > /dev/null
ocitools generate --args /runtimetest
popd
