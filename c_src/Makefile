# Get Erlang include paths
ERL_INCLUDE_DIR = `erl -noshell -eval 'io:format("~s/usr/include", [[code:root_dir()]]).' -s erlang halt`
ERL_ERTS_INCLUDE_DIR = `erl -eval 'io:format("~s", [code:lib_dir(erts, include)])' -s init stop -noshell`
ERL_INTERFACE_INCLUDE_DIR = `erl -eval 'io:format("~s", [code:lib_dir(erl_interface, include)])' -s init stop -noshell`

# Erlang library path
ERL_INTERFACE_LIB_DIR = `erl -eval 'io:format("~s", [code:lib_dir(erl_interface, lib)])' -s init stop -noshell`

CFLAGS = -fPIC -I$(ERL_INCLUDE_DIR) -I$(ERL_ERTS_INCLUDE_DIR) -I$(ERL_INTERFACE_INCLUDE_DIR) -I. -I../priv
LDFLAGS = -L$(ERL_INTERFACE_LIB_DIR) -lei

all: martini

libsecsipid:
	@echo "Building libsecsipid"
	@cd secsipidx/csecsipid && \
		go build -ldflags="-extldflags=-Wl" -o ../../../priv/libsecsipid.a -buildmode=c-archive csecsipid.go

martini: libsecsipid
	@echo "Building martini"
	cc $(CFLAGS) -c martini.c -o ../priv/martini.o
	cc -shared -o ../priv/martini.so ../priv/martini.o ../priv/libsecsipid.a $(LDFLAGS)

clean:
	rm -f ../priv/*.a ../priv/*.o ../priv/*.so ../priv/*.h
