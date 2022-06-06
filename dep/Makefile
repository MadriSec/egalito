# Makefile for dependencies

include ../env.mk

.PHONY: all rtld ifunc keystone distorm3 clean realclean
all: rtld ifunc keystone distorm3
	-@touch built
clean:
	-$(call short-make,rtld,clean)
	-$(call short-make,ifunc,clean)
	-@rm -f built
realclean:
	-$(call short-make,rtld,clean)
	-$(call short-make,ifunc,clean)
	-$(call short-make,distorm3/make/linux,clean)
	-@rm -rf keystone/build
	-@rm -f built

ifeq ($(USE_LOADER),1)
rtld:
	$(call short-make,rtld)
else
rtld:
endif
ifunc:
	$(call short-make,ifunc)
distorm3:
	$(call short-make,distorm3/make/linux) CC='gcc -Wno-missing-braces'

ifeq ($(CROSS_ANALYZE),1)
CROSS2 =
else
CROSS2 = $(CROSS)
endif

ifeq ($(USE_KEYSTONE),1)
keystone:
	-@cd keystone \
		&& mkdir build \
		&& cd build \
		&& ../make-share.sh \
		&& ../make-lib.sh
else
keystone:
endif

gtirb:
	@cd gtirb \
	  && mkdir build \
	  && cd build \
	  && cmake .. -DGTIRB_BUILD_SHARED_LIBS=OFF \
	  && cmake --build .
