#!/bin/sh
# download and cross compile all dependencies of binmap
CROSS=${1:-arm-linux-gnueabi-}
PREFIX=${2:-$HOME/local-arm}
CC=${CROCC}gcc
CXX=${CROCC}g++
which $CC 2>&1 1>/dev/null || { echo "C compiler '$CC' not found in PATH" 1>&2 ; exit 1 }
which $CXX 2>&1 1>/dev/null || { echo "C compiler '$CC' not found in PATH" 1>&2 ; exit 1 }

if [ -n "${CROSS}" ]
    OS=`uname | tr [:upper:] [:lower:]`
    ARCH=`uname -p`
then
    echo "using cross compilation tool chain '$CROSS'"
    OS=`echo $CROSS | cut -d - -f 2`
    ARCH=`echo $CROSS | cut -d - -f 1`
else
    echo "using native compilation tool chain"
fi
echo "installation is done in '$PREFIX'"

read "press space to proceeed" > /dev/null


ELFUTILS_URL=https://fedorahosted.org/releases/e/l/elfutils/elfutils-0.148.tar.bz2
ZLIB_URL=http://zlib.net/zlib-1.2.8.tar.gz
OPENSSL_URL=http://www.openssl.org/source/openssl-1.0.1e.tar.gz
BOOST_URL=http://downloads.sourceforge.net/project/boost/boost/1.55.0/boost_1_55_0.tar.bz2

ELFUTILS_ARCHIVE=`basename $ELFUTILS_URL`
ELFUTILS_DIR=${ELFUTILS_ARCHIVE%.tar.bz2}
[ -f $ELFUTILS_ARCHIVE ] || wget $ELFUTILS_URL
[ -d $ELFUTILS_DIR ] || tar xjf $ELFUTILS_ARCHIVE
cd ${ELFUTILS_DIR}
mkdir _build
cd _build
../configure --prefix=$PREFIX --host=${CROSS} CC=${CC}
cd libelf
make -j AR=${CROSS}-ar
make install
cd ../../..

ZLIB_ARCHIVE=`basename $ZLIB_URL`
ZLIB_DIR=${ZLIB_ARCHIVE%.tar.gz}
[ -f $ZLIB_ARCHIVE ] || wget $ZLIB_URL
[ -d $ZLIB_DIR ] || tar xzf $ZLIB_ARCHIVE
cd $ZLIB_DIR
CC=$CC ./configure --prefix=$PREFIX
make
make install
cd ..

OPENSSL_ARCHIVE=`basename $OPENSSL_URL`
OPENSSL_DIR=${OPENSSL_ARCHIVE%.tar.gz}
case $ARCH in
    arm) SSL_ARCH=armv4 ;;
    *) echo "architecture '$ARCH' not supported by OpenSSL?" 1>&2 && exit 1;;
esac
[ -f ${OPENSSL_ARCHIVE} ] || wget ${OPENSSL_URL}
[ -d ${OPENSSL_DIR} ] || tar xzf ${OPENSSL_ARCHIVE}
cd ${OPENSSL_DIR}
CC=$CC AR="${CROSS}ar" RANLIB="${CROSS}ranlib" LD="${CROSS}gcc" ./Configure no-threads no-shared no-asm no-dso no-sctp no-krb5 --prefix=$PREFIX  $OS-$SSL_ARCH
make -j1
make install_sw -j1
cd ../..

BOOST_ARCHIVE=`basename $BOOST_URL`
BOOST_DIR=${BOOST_ARCHIVE%.tar.bz2}
[ -f $BOOST_ARCHIVE ] || wget $BOOST_URL
[ -d $BOOST_DIR ] || tar xjf $BOOST_ARCHIVE
cd $BOOST_DIR
./bootstrap.sh
sed -i -e "s/using gcc/using gcc : $ARCH : $CXX/" project-config.jam
./b2 toolset=gcc-$ARCH target-os=$OS --with-program_options --with-serialization --with-system --with-log --with-graph --with-filesystem link=static runtime-link=static threading=single --prefix=$PREFIX
