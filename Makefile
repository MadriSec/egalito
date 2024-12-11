# Root Makefile for egalito
# To change settings, see env.mk

ifdef USE_CONFIG
    include $(USE_CONFIG)
    export
endif

MAKEFLAGS += -j $(shell nproc)

# Run the GTIRB installation script first
.PHONY: all src test app clean realclean get-gtirb

all: dep src test app
	@true

dep: get-gtirb dep/built

get-gtirb:
	@echo "Running get-gtirb.sh..."
	./test/script/get-gtirb.sh

dep/built: dep/Makefile
	$(call short-make,dep)

src: dep config
	$(call short-make,src)

config:
	$(call short-make,src/config)

test: src
	$(call short-make,test)
	$(call short-make,test/example)
	$(call short-make,test/binary all symlinks)

app: src test
	$(call short-make,app)

clean realclean:
	$(call short-make,app,clean)
	$(call short-make,src,clean)
	$(call short-make,test,$@)
	$(call short-make,test/example,clean)
	$(call short-make,test/binary,clean)
	$(call short-make,dep,$@)

