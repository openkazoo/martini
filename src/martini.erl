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

-on_load(load_nif/0).

-define(NIF_LOAD_INFO, 101).

-define(nif_stub, nif_stub_error(?LINE)).

%%==============================================================================
%% API Functions
%%==============================================================================

-export([
    load_nif/0,
    normalize_tn/1,
    maybe_add_identity_header/1,
    get_identity/4
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
            DestTN = kz_json:get_value(<<"To-DID">>, JObj, <<>>),

            %% Get call ID
            OrigID = kz_json:get_value(<<"Call-ID">>, JObj, <<>>),

            %% Attempt to generate an identity header
            case get_identity(OrigTN, DestTN, <<"A">>, OrigID) of
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
%% @param OrigID - unique ID for tracking purposes, if empty string a UUID is generated
%% @param X5uVal - location of public certificate
%% @param PrvkeyData - content of private key to be used to generate the signature
%% @return {ok, Identity} | {error, Reason}
%% @end
%%------------------------------------------------------------------------------
-spec get_identity(
    kz_term:ne_binary(), kz_term:ne_binary(), kz_term:ne_binary(), kz_term:ne_binary()
) ->
    {ok, kz_term:ne_binary()} | {error, any()}.
get_identity(OrigTN, DestTN, AttestVal, OrigID) ->
    NormalizedOrigTN = normalize_tn(OrigTN),
    NormalizedDestTN = normalize_tn(DestTN),
    lager:debug("OrigTN: ~p; DestTN: ~p; AttestVal: ~p; OrigID: ~p", [
        NormalizedOrigTN, NormalizedDestTN, AttestVal, OrigID
    ]),
    get_identity_nif(
        NormalizedOrigTN, NormalizedDestTN, AttestVal, OrigID, ?PUBLIC_KEY_URL, ?PRIVATE_KEY_PEM
    ).

%%==============================================================================
%% Internal functions
%%==============================================================================

%%------------------------------------------------------------------------------
%% @doc Calls the NIF to generate the identity header
%% @returns 'ok' | {'error', {atom(), string()}}
%% @end
%% @end
%%------------------------------------------------------------------------------
-spec get_identity_nif(
    kz_term:ne_binary(),
    kz_term:ne_binary(),
    kz_term:ne_binary(),
    kz_term:ne_binary(),
    kz_term:ne_binary(),
    kz_term:ne_binary()
) ->
    {ok, kz_term:ne_binary()} | {error, any()}.
get_identity_nif(_, _, _, _, _, _) -> ?nif_stub.

%%------------------------------------------------------------------------------
%% @doc Generate a NIF stub error
%% @param Line - the line number of the caller
%% @returns no_return()
%% @end
%%------------------------------------------------------------------------------
-spec nif_stub_error(integer()) -> no_return().
nif_stub_error(Line) ->
    erlang:nif_error({'nif_not_loaded', 'module', ?MODULE, 'line', Line}).

%%------------------------------------------------------------------------------
%% @doc Load the NIF module
%% @returns 'ok' | {'error', {atom(), string()}}
%% @end
%%------------------------------------------------------------------------------
-spec load_nif() -> 'ok' | {'error', {atom(), string()}}.
load_nif() ->
    PrivDir =
        case code:priv_dir(?MODULE) of
            {'error', _} ->
                EbinDir = filename:dirname(code:which(?MODULE)),
                AppPath = filename:dirname(EbinDir),
                filename:join(AppPath, "priv");
            Path ->
                Path
        end,
    lager:debug("Loading NIF for ~p ~p from ~p", [
        ?MODULE, ?APP_VERSION, filename:join(PrivDir, ?MODULE)
    ]),
    erlang:load_nif(filename:join(PrivDir, ?MODULE), ?NIF_LOAD_INFO).
