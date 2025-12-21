-module(martini_stir_shaken_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

sign_and_verify_with_pubkey_test() ->
    {PrvPem, PubPem} = gen_ec_keypair_pem(),
    X5u = <<"https://example.invalid/cert.pem">>,
    {ok, Identity} = martini:get_identity(<<"+1 (212) 555-0100">>, <<"12125550199">>, <<"A">>, X5u, PrvPem),
    {ok, Payload} = martini:check_full_identity_pubkey(Identity, PubPem),
    ?assertEqual(<<"A">>, maps:get(<<"attest">>, Payload)),
    ?assert(maps:is_key(<<"origid">>, Payload)).

expired_token_test() ->
    {PrvPem, PubPem} = gen_ec_keypair_pem(),
    X5u = <<"https://example.invalid/cert.pem">>,
    {ok, Identity} = martini:get_identity(<<"12125550100">>, <<"12125550199">>, <<"A">>, X5u, PrvPem),
    %% Force immediate expiry using pubkey verification
    {error, token_expired} = martini:check_full_identity_pubkey(Identity, PubPem, 0).

gen_ec_keypair_pem() ->
    %% Generate EC keypair and return {PrivPem, PubPemAsCertLike}
    %% We encode public key as a PEM SubjectPublicKeyInfo entry so martini can parse it.
    Curve = {namedCurve, {1, 2, 840, 10045, 3, 1, 7}}, %% prime256v1 / P-256
    PrvKey = public_key:generate_key(Curve),
    PrvPem = public_key:pem_encode([public_key:pem_entry_encode('ECPrivateKey', PrvKey)]),
    %% Derive public key point + curve parameters from the EC private key
    Params = PrvKey#'ECPrivateKey'.parameters,
    PubPoint = {'ECPoint', PrvKey#'ECPrivateKey'.publicKey},
    PubPem = public_key:pem_encode([
        public_key:pem_entry_encode('SubjectPublicKeyInfo', {PubPoint, Params})
    ]),
    {PrvPem, PubPem}.
