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
-define(APP_VERSION, <<"1.0.2">>).
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

-define(MARTINI_HRL, 'true').
-endif.
