# Makefile for egalito test code

include ../env.mk

DIRS = framework unit script codegen
CLEAN_DIRS = framework unit
.PHONY: all $(DIRS) clean realclean
all: unit

unit: framework

$(DIRS):
	$(MAKE) -C $@

clean:
	$(foreach DIR,$(CLEAN_DIRS),$(MAKE) -C $(DIR) clean;)

realclean:
	$(MAKE) -C framework realclean
	$(MAKE) -C unit clean
