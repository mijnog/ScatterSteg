set -e
P=${PREFIX:-$HOME/bench/prefix}; mkdir -p $P src && cd src
[ -f libmcrypt-2.5.8.tar.gz ] || curl -sL https://sourceforge.net/projects/mcrypt/files/Libmcrypt/2.5.8/libmcrypt-2.5.8.tar.gz/download -o libmcrypt-2.5.8.tar.gz
[ -f mhash-0.9.9.9.tar.gz ] || curl -sL https://sourceforge.net/projects/mhash/files/mhash/0.9.9.9/mhash-0.9.9.9.tar.gz/download -o mhash-0.9.9.9.tar.gz
[ -f steghide-0.5.1.tar.gz ] || curl -sL https://sourceforge.net/projects/steghide/files/steghide/0.5.1/steghide-0.5.1.tar.gz/download -o steghide-0.5.1.tar.gz
tar xzf libmcrypt-2.5.8.tar.gz; (cd libmcrypt-2.5.8 && CFLAGS="-O2 -std=gnu89 -w" ./configure --prefix=$P --disable-shared >/dev/null && make -j8 >/dev/null && make install >/dev/null)
tar xzf mhash-0.9.9.9.tar.gz; (cd mhash-0.9.9.9 && CFLAGS="-O2 -std=gnu89 -w" ./configure --prefix=$P --disable-shared >/dev/null && make -j8 >/dev/null && make install >/dev/null)
tar xzf steghide-0.5.1.tar.gz; cd steghide-0.5.1
A=${AUR_DIR:?directory with the AUR steghide patches}
patch -p1 < $A/buildsystem.patch; patch -p1 -i $A/include-climits.patch; patch -Np1 -i $A/add-hardening.patch; patch -Np1 -i $A/fix-spelling.patch; patch -Np1 -i $A/consolidated-gcc-patches.patch; patch -Np1 -i $A/correct-german.patch
touch NEWS AUTHORS ChangeLog
CXXFLAGS="-O2 -std=gnu++14 -w -I$P/include" CPPFLAGS="-I$P/include" LDFLAGS="-L$P/lib" ./configure --prefix=$P --disable-nls >/dev/null
make -j8 2>&1 | tail -5; make install 2>&1 | tail -2
echo BUILD_DONE
