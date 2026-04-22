include env.mk

binaries=app/etshell app/etcoverage app/etharden app/etobjdump\
  app/etorder app/etprofile app/etsandbox app/ettwocode app/etelf\
  app/etgtirb
libs=src/libegalito.so src/libaddon.so \
  app/libcet.so app/libcoverage.so  app/libsandbox.so
deps= dep/distorm3/make/linux/libdistorm3.so
static_libs=src/libegalito.a

headers=analysis archive break chunk conductor debug\
  disasm dwarf elf generate gtirb instr load log operation\
  pass runtime snippet transform util
header_files := $(foreach dir,$(headers),$(wildcard src/$(dir)/*.h))
header_files += src/config/config.h src/config.h src/types.h
new_headers := $(foreach f,$(header_files),build/include/$(f))
PKGCFGDIR := build/pkgconfig
PKGCFGFILE := ${PKGCFGDIR}/egalito.pc
.PHONY: all relocate clean

all: relocate

relocate: relocate-lib relocate-bin relocate-dep relocate-dev
relocate-bin: ${binaries}
	install -m0755 -D -t ./build/bin $^

relocate-lib: ${libs}
relocate-dep: ${deps}

relocate-lib relocate-dep:
	install -m0644 -D -t ./build/lib $^

relocate-dev: ${new_headers} $(PKGCFGFILE)
	@echo "Copying header files"
	
build/include/%.h: %.h
	@mkdir -p build/include
	@cp --parents $< build/include

${PKGCFGFILE}: egalito.pc.in | ${PKGCFGDIR}
	cat $< | sed 's/-CFLAGS/$(filter -D%,$(CFLAGS))/g' > $@

${PKGCFGDIR}:
	mkdir -p $@
	
relocate-static: 
	install -m0644 -D -t ./build/static ${static_libs}

clean:
	rm -r ./build
