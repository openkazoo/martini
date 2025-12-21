%%%-----------------------------------------------------------------------------
%%% @copyright Copyright (C) 2025 Dialwave, Inc.
%%% @doc
%%%
%%% This software is distributable under the BSD license. See the terms of the
%%% BSD license in the documentation provided with this software.
%%%
%%% @end
%%%-----------------------------------------------------------------------------
-module(martini_app).

-behaviour(application).

-export([start/2, stop/1]).

-spec start(application:start_type(), any()) -> {'ok', pid()}.
start(_StartType, _StartArgs) ->
    {'ok', self()}.

-spec stop(any()) -> 'ok'.
stop(_State) ->
    'ok'.
