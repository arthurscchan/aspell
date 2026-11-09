#!/bin/bash -eu

# This script is called by the oss-fuzz main project when compiling the fuzz
# targets. This script is regression tested by travisoss.sh.

# Save off the current folder as the build root.
export BUILD_ROOT=$PWD
export ASPELL_PREFIX=$OUT/deps
export DICT_DIR=$OUT/dict

if [[ ! -d ${DICT_DIR} ]]
then
    mkdir -p ${DICT_DIR}
fi

export CFLAGS="$CFLAGS -g"
export CXXFLAGS="$CXXFLAGS -g"

echo "CC: $CC"
echo "CXX: $CXX"
echo "LIB_FUZZING_ENGINE: $LIB_FUZZING_ENGINE"
echo "CFLAGS: $CFLAGS"
echo "CXXFLAGS: $CXXFLAGS"
echo "OUT: $OUT"

export MAKEFLAGS+="-j$(nproc)"

# Install dependencies
apt-get -y install \
    automake \
    autopoint \
    bzip2 \
    gettext \
    libtool \
    texinfo \
    wget

# Compile and install libaspell.
pushd $SRC/aspell
export LIBS="-lpthread"
./autogen
./configure \
    --enable-static \
    --disable-shared \
    --disable-pspell-compatibility \
    --prefix=$ASPELL_PREFIX \
    --enable-pkgdatadir=$DICT_DIR \
    --enable-pkglibdir=$DICT_DIR

make V=1
make install
popd

# Compile the fuzzer.
autoreconf -i
./configure --with-aspell=$ASPELL_PREFIX
make V=1

# Copy the fuzzer and corpora to the output directory.
cp -v aspell_fuzzer $OUT/
zip $OUT/aspell_fuzzer_seed_corpus.zip aspell_fuzzer_corpus/*
# Structured config-focused seeds for the incumbent target (corpus pair
# aspell-corpus-dict-options): generated deterministically at build time.
python3 generate_seeds.py aspell_fuzzer_corpus_config
zip $OUT/aspell_fuzzer_config_corpus.zip aspell_fuzzer_corpus_config/*
cp -v aspell_fuzzer.dict aspell_fuzzer.options $OUT/

# Install some dictionaries!
export PATH=$ASPELL_PREFIX/bin:$PATH

install_language() {
    LANG=$1
    DICT=$2
    pushd /tmp
    wget -O- https://ftp.gnu.org/gnu/aspell/dict/${LANG}/$DICT.tar.bz2 | tar xfj -
    pushd $DICT
    ./configure
    make install
    popd
    popd
}

install_language en aspell6-en-2016.11.20-0
install_language pt_BR aspell6-pt_BR-20131030-12-0

# Verify that one corpus input runs.
echo "Running a single corpus input"
FUZZ_VERBOSE=yes $OUT/aspell_fuzzer aspell_fuzzer_corpus/en_us_input_utf8
