#!/bin/bash
set -x
cd deps/wslay
export OLD_PKG_CONFIG_PATH=$PKG_CONFIG_PATH
export PKG_CONFIG_PATH="$PWD/../../include/lib/pkgconfig:$PKG_CONFIG_PATH"
make distclean
./configure --prefix="$PWD/../../include_server" \
	CFLAGS="-O3 -march=haswell -flto -fno-strict-aliasing"
make -j$(nproc)
make install
export PKG_CONFIG_PATH="$PWD/../../include_server/lib/pkgconfig:$OLD_PKG_CONFIG_PATH"
cd ../h2o
rm -rf build
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_C_FLAGS="-march=haswell -flto" \
	-DCMAKE_SHARED_LINKER_FLAGS="-flto" \
	-DCMAKE_INSTALL_PREFIX="$PWD/../../../include_server" \
	-DDISABLE_LIBUV=ON \
	..
make libh2o-evloop -j$(nproc)
make install
