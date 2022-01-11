binaries=app/etshell app/etcoverage app/etharden app/etobjdump\
  app/etorder app/etprofile app/etsandbox app/ettwocode app/etelf
libs=src/libegalito.so src/libaddon.so \
  app/libcet.so app/libcoverage.so  app/libsandbox.so
deps=dep/capstone/libcapstone.so.? \
  dep/distorm3/make/linux/libdistorm3.so
static_libs=src/libegalito.a

.PHONY: all relocate clean

all: relocate

relocate: relocate-lib relocate-bin relocate-dep
relocate-bin:
	install -m0755 -D -t ./build/bin ${binaries}

relocate-lib:
	install -m0644 -D -t ./build/lib ${libs}

relocate-dep: 
	install -m0644 -D -t ./build/lib ${deps}

relocate-static: 
	install -m0644 -D -t ./build/static ${static_libs}

clean:
	rm -r ./build
