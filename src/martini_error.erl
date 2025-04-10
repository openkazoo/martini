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
        %%
        %%
        %% SecSIPIdX: OK
        0 ->
            <<"ok">>;
        %%
        %%
        %% SecSIPIdX: Generic errors
        -1 ->
            <<"error">>;
        %%
        %%
        %% SecSIPIdX: Public certificate and private key errors
        -101 ->
            <<"cert_invalid">>;
        -102 ->
            <<"cert_invalid_format">>;
        -103 ->
            <<"cert_expired">>;
        -104 ->
            <<"cert_before_validity">>;
        -105 ->
            <<"cert_processing">>;
        -106 ->
            <<"cert_no_ca_file">>;
        -107 ->
            <<"cert_read_ca_file">>;
        -108 ->
            <<"cert_no_ca_intermediate">>;
        -109 ->
            <<"cert_read_ca_intermediate">>;
        -110 ->
            <<"cert_no_crl_file">>;
        -111 ->
            <<"cert_read_crl_file">>;
        -112 ->
            <<"cert_revoked">>;
        -114 ->
            <<"cert_invalid_ec">>;
        -151 ->
            <<"prvkey_invalid">>;
        -152 ->
            <<"prvkey_invalid_format_or_ec">>;
        %%
        %%
        %% SecSIPIdX: Identity JSON header, payload and signature errors:
        -201 ->
            <<"json_header_parse">>;
        -202 ->
            <<"json_header_alg">>;
        -203 ->
            <<"json_header_ppt">>;
        -204 ->
            <<"json_header_typ">>;
        -205 ->
            <<"json_header_x5u">>;
        -231 ->
            <<"json_payload_parse">>;
        -232 ->
            <<"json_payload_iat_expired">>;
        -251 ->
            <<"json_signature_invalid">>;
        -252 ->
            <<"json_signature_hashing">>;
        -253 ->
            <<"json_signature_size">>;
        -254 ->
            <<"json_signature_failure">>;
        -255 ->
            <<"json_signature_no_b64">>;
        %%
        %%
        %% SecSIPIdX: Identity SIP header errors
        -301 ->
            <<"sip_header_parse">>;
        -302 ->
            <<"sip_header_alg">>;
        -303 ->
            <<"sip_header_ppt">>;
        -304 ->
            <<"sip_header_empty">>;
        -305 ->
            <<"sip_header_info">>;
        %%
        %%
        %% SecSIPIdX: HTTP and file operations errors
        -401 ->
            <<"http_invalid_url">>;
        -402 ->
            <<"http_get">>;
        -403 ->
            <<"http_status_Error">>;
        -404 ->
            <<"http_read_body">>;
        -451 ->
            <<"file_read">>;
        %%
        %%
        %% Catch errors that fall in a SecSIPIdX range but are otherwise not known
        Error when Error >= -199, Error =< -100 ->
            <<"cert_error">>;
        Error when Error >= -299, Error =< -200 ->
            <<"json_error">>;
        Error when Error >= -399, Error =< -300 ->
            <<"sip_error">>;
        Error when Error >= -499, Error =< -400 ->
            <<"http_or_file_error">>;
        %%
        %%
        %% Catch errors from martini
        'martini_null_output' ->
            <<"martini_null_output">>;
        'martini_malloc_fail' ->
            <<"martini_malloc_fail">>;
        %%
        %%
        %% Catch everything else
        Error ->
            <<"unknown_error">>
    end.
