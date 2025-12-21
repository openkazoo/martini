%%%-----------------------------------------------------------------------------
%%% @copyright Copyright (C) 2025 Dialwave, Inc.
%%% @doc
%%%
%%% This software is distributable under the BSD license. See the terms of the
%%% BSD license in the documentation provided with this software.
%%%
%%% @end
%%%-----------------------------------------------------------------------------
-module(martini).

-include("martini.hrl").
-include_lib("public_key/include/public_key.hrl").

%%==============================================================================
%% API Functions
%%==============================================================================

-export([
    normalize_tn/1,
    maybe_add_identity_header/1,
    get_identity/3,
    get_identity/5,
    check_full_identity/1,
    check_full_identity/2,
    check_full_identity_pubkey/2,
    check_full_identity_pubkey/3
]).

%%------------------------------------------------------------------------------
%% @doc Normalize the TN
%% @param TN - the TN to normalize
%% @return the normalized TN
%% @end
%%
%% Implementations MUST drop any "+"s, internal dashes, parentheses,
%% or other non-numeric characters, except for the "#" or "*" keys
%% used in some special service numbers (typically, these will appear
%% only in the To header field value).  This MUST result in an ASCII
%% string limited to "#", "*", and digits without whitespace or
%% visual separators.
%%------------------------------------------------------------------------------
-spec normalize_tn(kz_term:ne_binary()) ->
    kz_term:ne_binary().
normalize_tn(TN) ->
    re:replace(TN, <<"[^0-9#*]">>, <<>>, ['global', {'return', 'binary'}]).

%%------------------------------------------------------------------------------
%% @doc Determine if an identity header should be added
%% @param JObj - the offnet JSON object to add the identity header to
%% @return the offnet JSON object with the identity header added
%% @end
%%------------------------------------------------------------------------------
-spec maybe_add_identity_header(kz_json:object()) ->
    kz_json:object().
maybe_add_identity_header(JObj) ->
    case ?ENABLED of
        'true' ->
            %% Get origination number
            OrigTN = kz_json:get_value(<<"Outbound-Caller-ID-Number">>, JObj, <<>>),

            %% Get destination number
            DestTN = stepswitch_util:get_outbound_destination(JObj),

            %% Attempt to generate an identity header
            case get_identity(OrigTN, DestTN, <<"A">>) of
                {'error', Code} ->
                    Reason = martini_error:get_reason(Code),
                    lager:error("Failed to generate identity header: (~p) ~p", [Code, Reason]),
                    JObj;
                {'ok', IdentityHeader} ->
                    lager:debug("Identity: ~p", [IdentityHeader]),

                    %% Create a nested structure
                    NewObj = kz_json:from_list([
                        {<<"Custom-SIP-Headers">>,
                            kz_json:from_list([
                                {<<"Identity">>, IdentityHeader}
                            ])}
                    ]),

                    %% Use merge_recursive to merge the header into the original object
                    %% This will create Custom-SIP-Headers if it doesn't exist or merge
                    %% with the existing headers, overwriting an existing Identity header
                    %% but preserving others
                    kz_json:merge_recursive(JObj, NewObj)
            end;
        _ ->
            JObj
    end.

%%------------------------------------------------------------------------------
%% @doc Generate the identity header
%% @param OrigTN - calling number
%% @param DestTN - called number
%% @param AttestVal - attestation level
%% @return {'ok', Identity} | {'error', Reason}
%% @end
%%------------------------------------------------------------------------------
-spec get_identity(
    kz_term:ne_binary(), kz_term:ne_binary(), kz_term:ne_binary()
) ->
    {'ok', kz_term:ne_binary()} | {'error', any()}.
get_identity(OrigTN, DestTN, AttestVal) ->
    get_identity(OrigTN, DestTN, AttestVal, ?PUBLIC_KEY_URL, ?PRIVATE_KEY_PEM).

%%==============================================================================
%% Internal functions
%%==============================================================================

%%------------------------------------------------------------------------------
%% @doc Calls the NIF to generate the identity header
%% @param OrigTN - calling number
%% @param DestTN - called number
%% @param AttestVal - attestation level
%% @param X5uVal - location of public certificate
%% @param PrvkeyData - content of private key to be used to generate the signature
%% @return {'ok', Identity} | {'error', Reason}
%% @end
%%------------------------------------------------------------------------------
-spec get_identity(
    kz_term:ne_binary(),
    kz_term:ne_binary(),
    kz_term:ne_binary(),
    kz_term:ne_binary(),
    kz_term:ne_binary()
) ->
    {'ok', kz_term:ne_binary()} | {'error', any()}.
get_identity(OrigTN, DestTN, AttestVal, X5uVal, PrvkeyPemBin) ->
    NormalizedOrigTN = normalize_tn(OrigTN),
    NormalizedDestTN = normalize_tn(DestTN),
    try
        Iat = erlang:system_time(second),
        HeaderJObj = kz_json:from_list([
            {<<"alg">>, <<"ES256">>},
            {<<"ppt">>, <<"shaken">>},
            {<<"typ">>, <<"passport">>},
            {<<"x5u">>, X5uVal}
        ]),
        PayloadJObj = kz_json:from_list([
            {<<"attest">>, AttestVal},
            {<<"dest">>, kz_json:from_list([{<<"tn">>, [NormalizedDestTN]}])},
            {<<"iat">>, Iat},
            {<<"orig">>, kz_json:from_list([{<<"tn">>, NormalizedOrigTN}])},
            {<<"origid">>, uuid_v4_bin()}
        ]),
        HeaderJson = iolist_to_binary(kz_json:encode(HeaderJObj)),
        PayloadJson = iolist_to_binary(kz_json:encode(PayloadJObj)),
        SigningInput = <<
            (kz_base64url:encode(HeaderJson))/binary,
            ".",
            (kz_base64url:encode(PayloadJson))/binary
        >>,
        PrvKey = decode_private_key(PrvkeyPemBin),
        SigDer = public_key:sign(SigningInput, sha256, PrvKey),
        SigRaw = ecdsa_der_to_raw_64(SigDer),
        Token = <<
            SigningInput/binary,
            ".",
            (kz_base64url:encode(SigRaw))/binary
        >>,
        Identity = <<
            Token/binary,
            ";info=<",
            X5uVal/binary,
            ">;alg=ES256;ppt=shaken"
        >>,
        {'ok', Identity}
    catch
        _:_ ->
            {'error', invalid_private_key}
    end.

%%------------------------------------------------------------------------------
%% Verification
%%------------------------------------------------------------------------------
-spec check_full_identity(kz_term:ne_binary()) ->
    {'ok', map()} | {'error', any()}.
check_full_identity(IdentityHeaderVal) ->
    check_full_identity(IdentityHeaderVal, #{}).

-spec check_full_identity(kz_term:ne_binary(), map()) ->
    {'ok', map()} | {'error', any()}.
check_full_identity(IdentityHeaderVal, Opts) when is_binary(IdentityHeaderVal), is_map(Opts) ->
    Expire = maps:get(expire_seconds, Opts, ?IDENTITY_EXPIRE_SECONDS),
    TimeoutMs = maps:get(http_timeout_ms, Opts, ?X5U_HTTP_TIMEOUT_MS),
    case parse_identity_header(IdentityHeaderVal) of
        {'error', Reason} ->
            {'error', Reason};
        {'ok', #{token := Token, info := Info} = Parsed} ->
            case fetch_x5u(Info, TimeoutMs) of
                {'ok', Pem} ->
                    check_full_identity_pubkey(Token, Parsed, Expire, Pem);
                {'error', _} ->
                    {'error', http_error}
            end
    end.

-spec check_full_identity_pubkey(kz_term:ne_binary(), kz_term:ne_binary()) ->
    {'ok', map()} | {'error', any()}.
check_full_identity_pubkey(IdentityHeaderVal, PubKeyPemBin) ->
    Expire = ?IDENTITY_EXPIRE_SECONDS,
    check_full_identity_pubkey(IdentityHeaderVal, PubKeyPemBin, Expire).

-spec check_full_identity_pubkey(kz_term:ne_binary(), kz_term:ne_binary(), non_neg_integer()) ->
    {'ok', map()} | {'error', any()}.
check_full_identity_pubkey(IdentityHeaderVal, PubKeyPemBin, Expire) ->
    case parse_identity_header(IdentityHeaderVal) of
        {'error', Reason} ->
            {'error', Reason};
        {'ok', #{token := Token} = Parsed} ->
            check_full_identity_pubkey(Token, Parsed, Expire, PubKeyPemBin)
    end.

check_full_identity_pubkey(TokenBin, Parsed, ExpireSeconds, PubKeyPemBin) ->
    case parse_jws(TokenBin) of
        {'error', Reason} ->
            {'error', Reason};
        {'ok', #{
            header := HeaderMap,
            payload := PayloadMap,
            signing_input := SigningInput,
            sig_raw := SigRaw
        }} ->
            case verify_attributes(HeaderMap, Parsed) of
                ok ->
                    case verify_payload(PayloadMap, ExpireSeconds) of
                        ok ->
                            case decode_public_key(PubKeyPemBin) of
                                {'ok', PubKey} ->
                                    SigDer = ecdsa_raw_64_to_der(SigRaw),
                                    case public_key:verify(SigningInput, sha256, SigDer, PubKey) of
                                        true -> {'ok', PayloadMap};
                                        false -> {'error', signature_invalid}
                                    end;
                                {'error', _} ->
                                    {'error', invalid_public_key}
                            end;
                        {'error', Reason2} ->
                            {'error', Reason2}
                    end;
                {'error', Reason3} ->
                    {'error', Reason3}
            end
    end.

%%------------------------------------------------------------------------------
%% Parsing helpers
%%------------------------------------------------------------------------------
parse_identity_header(IdentityHeaderVal) ->
    NoWS = remove_whitespace(IdentityHeaderVal),
    Parts = binary:split(NoWS, <<";">>, [global]),
    case Parts of
        [] ->
            {'error', invalid_identity_header};
        [Token | Params] ->
            case parse_identity_params(Params, #{token => Token}) of
                {'ok', Map1} ->
                    case maps:get(info, Map1, undefined) of
                        undefined -> {'error', x5u_missing};
                        _ -> {'ok', Map1}
                    end;
                Error ->
                    Error
            end
    end.

parse_identity_params([], Acc) ->
    {'ok', Acc};
parse_identity_params([P | Rest], Acc) ->
    case binary:split(P, <<"=">>, [global]) of
        [<<"alg">>, <<"ES256">>] ->
            parse_identity_params(Rest, Acc#{alg => <<"ES256">>});
        [<<"ppt">>, <<"shaken">>] ->
            parse_identity_params(Rest, Acc#{ppt => <<"shaken">>});
        [<<"ppt">>, <<"\"shaken\"">>] ->
            parse_identity_params(Rest, Acc#{ppt => <<"shaken">>});
        [<<"info">>, Info] ->
            parse_identity_params(Rest, Acc#{info => strip_angle_brackets(Info)});
        _ ->
            parse_identity_params(Rest, Acc)
    end.

parse_jws(TokenBin) ->
    Segs = binary:split(TokenBin, <<".">>, [global]),
    case Segs of
        [H64, P64, S64] ->
            try
                HeaderJson = kz_base64url:decode(H64),
                PayloadJson = kz_base64url:decode(P64),
                SigRaw = kz_base64url:decode(S64),
                HeaderMap = kz_json:to_map(kz_json:decode(HeaderJson)),
                PayloadMap = kz_json:to_map(kz_json:decode(PayloadJson)),
                {'ok', #{
                    header => HeaderMap,
                    payload => PayloadMap,
                    signing_input => <<H64/binary, ".", P64/binary>>,
                    sig_raw => SigRaw
                }}
            catch
                _:_ ->
                    {'error', invalid_jws}
            end;
        _ ->
            {'error', invalid_jws}
    end.

verify_attributes(HeaderMap, Parsed) ->
    %% Ensure header is consistent with Identity params
    Info = maps:get(info, Parsed),
    case maps:get(<<"x5u">>, HeaderMap, Info) of
        Info -> ok;
        _ -> {'error', x5u_mismatch}
    end.

verify_payload(PayloadMap, ExpireSeconds) ->
    case maps:get(<<"iat">>, PayloadMap, 0) of
        0 ->
            {'error', invalid_payload};
        Iat when is_integer(Iat) ->
            Now = erlang:system_time(second),
            case Now =< Iat + ExpireSeconds of
                true -> ok;
                false -> {'error', token_expired}
            end;
        _ ->
            {'error', invalid_payload}
    end.

%%------------------------------------------------------------------------------
%% @doc Fetch and cache the X.509 certificate
%% @param Url - the URL of the X.509 certificate
%% @param TimeoutMs - the timeout in milliseconds
%% @return {'ok', Pem} | {'error', Reason}
%% @end
%%------------------------------------------------------------------------------
fetch_x5u(Url, TimeoutMs) ->
    ensure_x5u_cache(),
    case ets:lookup('martini_x5u_cache', Url) of
        [{_Key, ExpireAt, Pem}] ->
            Now = erlang:system_time(second),
            case Now =< ExpireAt of
                'true' ->
                    {'ok', Pem};
                'false' ->
                    ets:delete('martini_x5u_cache', Url),
                    fetch_x5u_http(Url, TimeoutMs)
            end;
        [] ->
            fetch_x5u_http(Url, TimeoutMs)
    end.

fetch_x5u_http(Url, TimeoutMs) ->
    case kz_http:get(Url, [], [{'timeout', TimeoutMs}, {'connect_timeout', TimeoutMs}]) of
        {'ok', Code, _Hdrs, Body} when Code >= 200, Code < 300 ->
            Ttl = ?X5U_CACHE_TTL_SECONDS,
            ExpireAt = erlang:system_time(second) + Ttl,
            ets:insert('martini_x5u_cache', {Url, ExpireAt, Body}),
            {'ok', Body};
        {'ok', _Code, _Hdrs, _Body} ->
            {'error', 'http_status_error'};
        _ ->
            {'error', 'http_error'}
    end.

ensure_x5u_cache() ->
    case ets:info('martini_x5u_cache') of
        undefined ->
            _ = ets:new('martini_x5u_cache', ['named_table', 'public', 'set']),
            'ok';
        _ ->
            'ok'
    end.

%%------------------------------------------------------------------------------
%% Crypto / key parsing helpers
%%------------------------------------------------------------------------------
decode_private_key(PemBin) ->
    case public_key:pem_decode(PemBin) of
        [] ->
            error('invalid_private_key');
        Entries ->
            decode_first_private_key(Entries)
    end.

decode_first_private_key([Entry | Rest]) ->
    try public_key:pem_entry_decode(Entry) of
        Key -> Key
    catch
        _:_ -> decode_first_private_key(Rest)
    end;
decode_first_private_key([]) ->
    error('invalid_private_key').

decode_public_key(PemBin) ->
    case public_key:pem_decode(PemBin) of
        [] ->
            {'error', 'invalid_public_key'};
        Entries ->
            decode_public_key_entries(Entries)
    end.

decode_public_key_entries([{'Certificate', Der, _} | _]) ->
    Cert = public_key:pkix_decode_cert(Der, otp),
    PubKeyInfo = Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subjectPublicKeyInfo,
    Key = PubKeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey,
    Alg = PubKeyInfo#'OTPSubjectPublicKeyInfo'.algorithm,
    Params =
        case Alg of
            #'PublicKeyAlgorithm'{parameters = P} -> P;
            _ -> asn1_NOVALUE
        end,
    case Params of
        'asn1_NOVALUE' -> {'ok', Key};
        _ -> {'ok', {Key, Params}}
    end;
decode_public_key_entries([Entry | Rest]) ->
    try public_key:pem_entry_decode(Entry) of
        Key -> {'ok', Key}
    catch
        _:_ -> decode_public_key_entries(Rest)
    end;
decode_public_key_entries([]) ->
    {'error', 'invalid_public_key'}.

ecdsa_der_to_raw_64(SigDer) ->
    Decoded = public_key:der_decode('ECDSA-Sig-Value', SigDer),
    {R, S} =
        case Decoded of
            {'ECDSA-Sig-Value', R0, S0} -> {R0, S0};
            {R0, S0} -> {R0, S0};
            Other -> error({bad_ecdsa_sig, Other})
        end,
    <<
        (left_pad_32(binary:encode_unsigned(R)))/binary,
        (left_pad_32(binary:encode_unsigned(S)))/binary
    >>.

ecdsa_raw_64_to_der(<<Rbin:32/binary, Sbin:32/binary>>) ->
    R = binary:decode_unsigned(Rbin),
    S = binary:decode_unsigned(Sbin),
    try
        %% Prefer record form (OTP) if available via public_key.hrl include.
        public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r = R, s = S})
    catch
        _:_ ->
            %% Fallbacks for older/newer ASN.1 representations
            try public_key:der_encode('ECDSA-Sig-Value', {'ECDSA-Sig-Value', R, S}) of
                Bin -> Bin
            catch
                _:_ -> public_key:der_encode('ECDSA-Sig-Value', {R, S})
            end
    end;
ecdsa_raw_64_to_der(Other) ->
    error({'bad_ecdsa_sig', Other}).

left_pad_32(Bin) when is_binary(Bin) ->
    Sz = byte_size(Bin),
    case Sz of
        32 ->
            Bin;
        N when N < 32 ->
            Pad = binary:copy(<<0>>, 32 - N),
            <<Pad/binary, Bin/binary>>;
        _ ->
            error('bad_ecdsa_sig_size')
    end.

%%------------------------------------------------------------------------------
%% Misc helpers
%%------------------------------------------------------------------------------
remove_whitespace(Bin) ->
    re:replace(Bin, <<"\\s+">>, <<>>, [global, {return, binary}]).

strip_angle_brackets(<<$<, Rest/binary>>) ->
    case byte_size(Rest) of
        0 ->
            Rest;
        N ->
            case binary:last(Rest) of
                $> -> binary:part(Rest, 0, N - 1);
                _ -> Rest
            end
    end;
strip_angle_brackets(Bin) ->
    Bin.

uuid_v4_bin() ->
    <<B1:8, B2:8, B3:8, B4:8, B5:8, B6:8, B7:8, B8:8, B9:8, B10:8, B11:8, B12:8, B13:8, B14:8,
        B15:8,
        B16:8>> =
        crypto:strong_rand_bytes(16),
    %% Set version 4 (0100) in byte 7 (high nibble), variant 10xx in byte 9 (high bits).
    V7 = (B7 band 16#0F) bor 16#40,
    V9 = (B9 band 16#3F) bor 16#80,
    iolist_to_binary(
        io_lib:format(
            "~2.16.0b~2.16.0b~2.16.0b~2.16.0b-~2.16.0b~2.16.0b-~2.16.0b~2.16.0b-~2.16.0b~2.16.0b-~2.16.0b~2.16.0b~2.16.0b~2.16.0b~2.16.0b~2.16.0b",
            [B1, B2, B3, B4, B5, B6, V7, B8, V9, B10, B11, B12, B13, B14, B15, B16]
        )
    ).
