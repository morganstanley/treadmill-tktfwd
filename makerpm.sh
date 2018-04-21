#!/bin/sh

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

RPMDIR=~/rpms/

while getopts "d:" OPT; do
    case "${OPT}" in
        d)
            RPMDIR=${OPTARG}
            ;;
    esac
done
shift $((OPTIND-1))

mkdir -p $RPMDIR/SPEC
m4 -D VERSION=1.0 -D TOPDIR=$RPMDIR $DIR/treadmill-tktfwd.spec > $RPMDIR/SPEC/treadmill-tktfwd.spec

for SDIR in SOURCES BUILD RPMS SRPMS; do
    mkdir -vp $RPMDIR/$SDIR
done

./autogen.sh

BUILDDIR=$(mktemp -d)
cd $BUILDDIR
$DIR/configure && make && make dist
cp treadmill-tktfwd-*.tar.gz $RPMDIR/SOURCES
cd $DIR
rm -rf $BUILDDIR

rpmbuild --buildroot=$RPMDIR/BUILDROOT -ba $RPMDIR/SPEC/treadmill-tktfwd.spec
