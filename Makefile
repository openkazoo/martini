ROOT = ../..
PROJECT = martini

all: compile

COMPILE_MOAR = make-c_src
CLEAN_MOAR = clean-c_src

make-c_src:
	@$(MAKE) -C c_src

clean-c_src:
	@$(MAKE) -C c_src clean

include $(ROOT)/make/kz.mk
