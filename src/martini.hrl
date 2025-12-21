%%%-----------------------------------------------------------------------------
%%% @copyright Copyright (C) 2025 Dialwave, Inc.
%%% @doc
%%%
%%% This software is distributable under the BSD license. See the terms of the
%%% BSD license in the documentation provided with this software.
%%%
%%% @end
%%%-----------------------------------------------------------------------------
-ifndef(MARTINI_HRL).

-define(APP_NAME, <<"martini">>).
-define(APP_VERSION, <<"2.0.0">>).
-define(CONFIG_CAT, <<"martini">>).

-define(ENABLED,
    kapps_config:get_boolean(?CONFIG_CAT, <<"enabled">>, 'false')
).

-define(PUBLIC_KEY_URL,
    kapps_config:get_binary(
        ?CONFIG_CAT, <<"public_key_url">>, <<"https://domain.com/public_key.pem">>
    )
).

-define(PRIVATE_KEY_PEM,
    kapps_config:get_binary(
        ?CONFIG_CAT,
        <<"private_key_pem">>,
        <<"-----BEGIN EC PRIVATE KEY-----\n{YOUR_PRIVATE_KEY}\n-----END EC PRIVATE KEY-----">>
    )
).

-define(IDENTITY_EXPIRE_SECONDS,
    kapps_config:get_integer(?CONFIG_CAT, <<"identity_expire_seconds">>, 60)
).

-define(X5U_HTTP_TIMEOUT_MS,
    kapps_config:get_integer(?CONFIG_CAT, <<"x5u_http_timeout_ms">>, 5000)
).

-define(X5U_CACHE_TTL_SECONDS,
    kapps_config:get_integer(?CONFIG_CAT, <<"x5u_cache_ttl_seconds">>, 3600)
).

-define(MARTINI_HRL, 'true').
-endif.
