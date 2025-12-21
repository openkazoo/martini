%%%-----------------------------------------------------------------------------
%%% @copyright Copyright (C) 2025 Dialwave, Inc.
%%% @doc
%%%
%%% This software is distributable under the BSD license. See the terms of the
%%% BSD license in the documentation provided with this software.
%%%
%%% @end
%%%-----------------------------------------------------------------------------
-module(martini_error).

-export([
    get_reason/1
]).

-spec get_reason(any()) -> kz_term:ne_binary().
get_reason(Error) ->
    case Error of
        'ok' -> <<"ok">>;
        'invalid_private_key' -> <<"invalid_private_key">>;
        'invalid_public_key' -> <<"invalid_public_key">>;
        'invalid_identity_header' -> <<"invalid_identity_header">>;
        'invalid_jws' -> <<"invalid_jws">>;
        'invalid_header' -> <<"invalid_header">>;
        'invalid_payload' -> <<"invalid_payload">>;
        'token_expired' -> <<"token_expired">>;
        'signature_invalid' -> <<"signature_invalid">>;
        'x5u_missing' -> <<"x5u_missing">>;
        'x5u_mismatch' -> <<"x5u_mismatch">>;
        'http_error' -> <<"http_error">>;
        'http_status_error' -> <<"http_status_error">>;
        _ -> <<"unknown_error">>
    end.
