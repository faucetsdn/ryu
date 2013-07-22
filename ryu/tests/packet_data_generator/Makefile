
generate:
	rebar get-deps
	rebar compile
	erl -pa ebin deps/*/ebin -s x x -s init stop
