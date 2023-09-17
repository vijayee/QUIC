OPENSSLLIBPATH =/usr/local/lib64
OPENSSLINCPATH =/usr/include/openssl
MSQUICLIBPATH =/home/victor/Workspace/src/github.com/vijayee/msquic/build/bin/Release
MSQUICINCPATH =/home/victor/Workspace/src/github.com/vijayee/msquic/src/inc
PONYINCPATH =/home/victor/.local/share/ponyup/ponyc-release-0.51.3-x86_64-linux-gnu/include
PONYLIBPATH=/home/victor/.local/share/ponyup/ponyc-release-0.51.3-x86_64-linux-gnu/lib/x86-64
ALTLIBPATH=/home/victor/Workspace/src/github.com/vijayee/ponyc/src/libponyrt/sched
DEBUGPONYC=/home/victor/Workspace/src/github.com/vijayee/ponyc/build/debug/ponyc
THREADSANITIZERPONY=/home/victor/Workspace/src/github.com/vijayee/ponyc/build/release-thread_sanitizer/ponyc
build:
	mkdir -p build
	mkdir -p build/lib
	mkdir -p build/test
libponyquic: build
	clang -g -v -fPIC -O3 -o build/lib/quic.o -c QUIC/c/quic.c -L$(MSQUICLIBPATH) -I$(PONYINCPATH) -I$(MSINCQUICPATH) -lponyrt -lmsquic #-I$(OPENSSLINCPATH)
	#cd build/lib && ar -x  $(MSQUICLIBPATH)/libmsquic.a # && ar -x  $(OPENSSLPATH)/libcrypto.a
	ar rcs build/lib/libponyquic.a build/lib/*.o
	rm build/lib/*.o
libponyquicAS: build
	clang -g -fsanitize=address -v -fPIC -O3 -o build/lib/quic.o -c QUIC/c/quic.c -L$(MSQUICLIBPATH) -I$(PONYINCPATH) -I$(MSINCQUICPATH) -lponyrt -lmsquic #-I$(OPENSSLINCPATH)
	#cd build/lib && ar -x  $(MSQUICLIBPATH)/libmsquic.a # && ar -x  $(OPENSSLPATH)/libcrypto.a
	ar rcs build/lib/libponyquic.a build/lib/*.o
	rm build/lib/*.o
libponyquicTS: build
	clang -g -fsanitize=thread -v -fPIC -O3 -o build/lib/quic.o -c QUIC/c/quic.c -L$(MSQUICLIBPATH) -I$(PONYINCPATH) -I$(MSINCQUICPATH) -lponyrt -lmsquic #-I$(OPENSSLINCPATH)
	#cd build/lib && ar -x  $(MSQUICLIBPATH)/libmsquic.a # && ar -x  $(OPENSSLPATH)/libcrypto.a
	ar rcs build/lib/libponyquic.a build/lib/*.o
	rm build/lib/*.o
install: libponyquic
	mkdir -p /usr/local/lib/NeatCrypto
	cp build/lib/libponyquic.a /usr/local/lib/QUIC
testlib:libponyquic
		clang -v -o build/test/testlib QUIC/test/test.c -I$(ALTLIBPATH) -lponyrt  #-IQUIC/c -Lbuild/lib -L$(MSQUICLIBPATH) -I$(PONYINCPATH) -I$(MSINCQUICPATH) -lponyrt -lmsquic -lponyquic #-I$(OPENSSLINCPATH)
		./build/test/testlib
test: libponyquic
	#corral fetch
	corral run -- ponyc  QUIC/test -o build/test --verbose =4 --debug -p build/lib -p $(MSQUICLIBPATH) -p $(OPENSSLLIBPATH)
	./build/test/test

test/network/server: libponyquic
	#corral fetch
	corral run -- ponyc  QUIC/test/network/server -o build/test --verbose =4 --debug -p build/lib -p $(MSQUICLIBPATH) -p $(OPENSSLLIBPATH)
	./build/test/server
test/network/client: libponyquic
	#corral fetch
	corral run -- ponyc  QUIC/test/network/client -o build/test --verbose =4 --debug -p build/lib -p $(MSQUICLIBPATH) -p $(OPENSSLLIBPATH)
	./build/test/client
test/network/client/debug: libponyquic
	#corral fetch
	corral run -- $(DEBUGPONYC)  QUIC/test/network/client -o build/test --verbose =4 --debug -p build/lib -p $(MSQUICLIBPATH) -p $(OPENSSLLIBPATH)
	lldb ./build/test/client
test/network/client/valgrind: libponyquic
	#corral fetch
	corral run -- $(DEBUGPONYC)  QUIC/test/network/client -o build/test --verbose =4 --debug -p build/lib -p $(MSQUICLIBPATH) -p $(OPENSSLLIBPATH)
	valgrind --leak-check=yes ./build/test/client
test/network/client/threadsanitizer: libponyquicTS
	#corral fetch
	corral run -- $(THREADSANITIZERPONY)  QUIC/test/network/client -o build/test --verbose =4 --debug -p build/lib -p $(MSQUICLIBPATH) -p $(OPENSSLLIBPATH)
	./build/test/client
test/network/client/addresssanitizer: libponyquicAS
	#corral fetch
	corral run -- $(DEBUGPONYC)  QUIC/test/network/client -o build/test --verbose =4 --debug -p build/lib -p $(MSQUICLIBPATH) -p $(OPENSSLLIBPATH)
	./build/test/client
test/network/server/debug: libponyquic
	#corral fetch
	corral run -- $(DEBUGPONYC)  QUIC/test/network/server -o build/test --verbose =4 --debug -p build/lib -p $(MSQUICLIBPATH) -p $(OPENSSLLIBPATH)
	lldb ./build/test/server
clean:
	rm -rf build
