#!/bin/bash

version=$1
rev=$2

if [ -z "$version" ]
then
    echo "Usage: $0 <version> [rev]"
    exit 1
fi

if [ -z "$rev" ]
then
    rev=1
fi

BUILD_DIR=/tmp/build-samba4-$$
CWD=`pwd`

SAMBA_SRC="samba4_$version.orig.tar.gz"

if ! [ -f $SAMBA_SRC ]
then
    ./build-orig.sh $version
    if [ $? -ne 0 ]; then
        exit 1
    fi
fi

mkdir $BUILD_DIR
ln -sf $CWD/$SAMBA_SRC $BUILD_DIR/$SAMBA_SRC

pushd $BUILD_DIR
tar xzf $CWD/$SAMBA_SRC
cd samba4_$version
cp -r $CWD/debian .
dch -b -v "$version-zentyal$rev" -D 'precise' --force-distribution 'New upstream release'
cp debian/changelog $CWD/debian/

ppa-build.sh
popd

mv $BUILD_DIR/samba4_*.{debian.tar.gz,dsc,changes} .
rm -rf $BUILD_DIR
