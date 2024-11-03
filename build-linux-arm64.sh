#!/bin/bash

# Default for cortex-a53 optimized builds
clear
export feature="simd+crypto+crc"
export CC=gcc
export CXX=g++
export CFLAGS="-Ofast -fuse-linker-plugin -ftree-loop-if-convert -march=armv8-a+$feature -mcpu=cortex-a53+$feature -mtune=cortex-a53"
export CXXFLAGS="$CFLAGS"
export CPPFLAGS="$CFLAGS -I. -I/usr/local/devs/include"
export LDFLAGS="-L/usr/local/devs/lib -static"
export LIBS="-lcurl -lcrypto -lssl"
make clean
make distclean
rm configure
autoreconf -i
./configure --with-crypto --with-curl CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS" CPPFLAGS="$CPPFLAGS" LIBS="$LIBS" LDFLAGS="$LDFLAGS"
make -j4
