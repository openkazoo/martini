compile:
	rebar3 compile

format:
	rebar3 fmt

clean:
	rebar3 clean

test:
	rebar3 eunit

test-cover:
	rebar3 cover

ct:
	rebar3 ct