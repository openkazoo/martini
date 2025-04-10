# martini

This is an experimental implementation of STIR/SHAKEN in Kazoo using [SecSIPIdX](https://github.com/asipto/secsipidx) as a [NIF](https://www.erlang.org/doc/system/nif.html) to process identity headers.

## Progress / Todo

- Testing is needed, especially regarding:
    - Anonymous calls (i.e., privacy settings in Kazoo)
    - International calls
    - Emergency services (911/933)
    - Special services (411/811/899/etc)
- Check number database to properly determine attestation level
- Add support for inbound call verification
- Add support for resellers (check account DB for private key)

## Known Issues

- There is a [known bug in FreeSWITCH](https://github.com/signalwire/freeswitch/commit/9cc7c2d58146a4797fe391a7380a2aeef3f53130) that creates duplicate `Identity` headers.

## Prerequisites

- Certificates from an approved STI-CA
- Somewhere to host your public key
- Go (required to build SecSIPIdX)

## Installation

### Clone Repo

```sh
git clone https://github.com/openkazoo/martini
git submodule update --init
```

### Patch Stepswitch

In `stepswitch_outbound.erl`, update `handle_req`:

```erlang
-spec handle_req(kz_json:object(), kz_term:proplist()) -> any().
handle_req(OffnetJObj, _Props) ->
    'true' = kapi_offnet_resource:req_v(OffnetJObj),
    OffnetReq = kapi_offnet_resource:jobj_to_req(OffnetJObj),
    _ = kapi_offnet_resource:put_callid(OffnetReq),
    NewOffnetReq = martini:maybe_add_identity_header(OffnetJObj),
    case kapi_offnet_resource:resource_type(NewOffnetReq) of
        ?RESOURCE_TYPE_AUDIO -> handle_audio_req(NewOffnetReq);
        ?RESOURCE_TYPE_ORIGINATE -> handle_originate_req(NewOffnetReq)
    end.
```

### Build

- Build and install Kazoo as usual

## Configuration

The `martini` config is stored in CouchDB under `system_config/martini`:

```json
"default": {
  "enabled": true,
  "public_key_url": "https://domain.com/public_key.pem",
  "private_key_pem": "-----BEGIN EC PRIVATE KEY-----\n{YOUR_PRIVATE_KEY}\n-----END EC PRIVATE KEY-----"
}
```

- Modify the config
    - Ensure `public_key_url` is accessible to the public
    - Ensure `private_key_pem` has newlines, as appropriate
- Run `sup kazoo_data_maintenance flush_docs`
