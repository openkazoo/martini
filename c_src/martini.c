/*
%%%-----------------------------------------------------------------------------
%%% @copyright Copyright (C) 2025 Dialwave, Inc.
%%% @doc
%%%
%%% This software is distributable under the BSD license. See the terms of the
%%% BSD license in the documentation provided with this software.
%%%
%%% @end
%%%-----------------------------------------------------------------------------
*/

#include "secsipidx/csecsipid/libsecsipid.h"
#include <erl_nif.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define NIF_LOAD_INFO (102)

static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_null_output;
static ERL_NIF_TERM atom_malloc_fail;

/*
 * Validate and convert an Erlang binary to a null-terminated C string
 * @param env ErlNifEnv pointer for the calling process.
 * @param term ERL_NIF_TERM to identify the NIF library.
 * @param str_ptr pointer to the C string to store the converted binary.
 * @param status pointer to the status of the conversion.
 */
static bool validate_and_convert_binary(ErlNifEnv *env, ERL_NIF_TERM term, char **str_ptr, ERL_NIF_TERM *status)
{
    ErlNifBinary bin;

    if (!enif_inspect_binary(env, term, &bin)) {
        // badarg will override any other result
        *status = enif_make_badarg(env);
        return false;
    }

    *str_ptr = malloc(bin.size + 1);
    if (!*str_ptr) {
        *status = atom_malloc_fail;
        return false;
    }

    memcpy(*str_ptr, bin.data, bin.size);
    (*str_ptr)[bin.size] = '\0';

    return true;
}

// Forward declarations
static ERL_NIF_TERM get_identity_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

/*
 * Generate an identity header
 * @param env ErlNifEnv pointer for the calling process.
 * @param argc number of arguments.
 * @param argv array of arguments.
 */
static ERL_NIF_TERM get_identity_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    char *origTN = NULL, *destTN = NULL, *attestVal = NULL, *x5uVal = NULL, *prvkeyData = NULL, *outPtr = NULL;
    ERL_NIF_TERM result = atom_ok;

    // Check arguments
    if (argc != 5) {
        return enif_make_badarg(env);
    }

    // Validate and convert the binaries to C strings
    if (!validate_and_convert_binary(env, argv[0], &origTN, &result) ||
        !validate_and_convert_binary(env, argv[1], &destTN, &result) ||
        !validate_and_convert_binary(env, argv[2], &attestVal, &result) ||
        !validate_and_convert_binary(env, argv[3], &x5uVal, &result) ||
        !validate_and_convert_binary(env, argv[4], &prvkeyData, &result)) {
        // Check if there was an error
        if (!enif_is_identical(result, atom_ok)) {
            // If there was an error, return the error atom and the error code
            result = enif_make_tuple2(env, atom_error, result);

            goto cleanup;
        }
    }

    // Call the C function
    int ret = SecSIPIDGetIdentityPrvKey(origTN, destTN, attestVal, "", x5uVal, prvkeyData, &outPtr);

    // Handle the result
    if (ret < 0) {
        // Some sort of error happened
        result = enif_make_tuple2(env, atom_error, enif_make_int(env, ret));
    } else if (!outPtr) {
        // SecSIPIDGetIdentity suceeded but outPtr is NULL?
        result = enif_make_tuple2(env, atom_error, atom_null_output);
    } else {
        ErlNifBinary identity_bin;
        size_t identity_len = strlen(outPtr);

        // Allocate an Erlang managed binary buffer
        if (!enif_alloc_binary(identity_len, &identity_bin)) {
            // Allocation failed, return malloc_fail error
            result = enif_make_tuple2(env, atom_error, atom_malloc_fail);
        } else {
            // Copy C string data into the Erlang binary buffer
            memcpy(identity_bin.data, outPtr, identity_len);

            // Create the Erlang binary term (takes ownership of identity_bin memory)
            ERL_NIF_TERM identity_term = enif_make_binary(env, &identity_bin);

            // Construct success tuple {ok, Binary}
            result = enif_make_tuple2(env, atom_ok, identity_term);
        }
    }

cleanup:
    // Free allocated memory only if allocation succeeded
    if (origTN) {
        free(origTN);
    }
    if (destTN) {
        free(destTN);
    }
    if (attestVal) {
        free(attestVal);
    }
    if (x5uVal) {
        free(x5uVal);
    }
    if (prvkeyData) {
        free(prvkeyData);
    }
    if (outPtr) {
        // Free the output pointer allocated by SecSIPIDGetIdentity
        free(outPtr);
    }

    return result;
}

/**
 * Check the load info.
 * @param env ErlNifEnv pointer for the calling process.
 * @param load_info ERL_NIF_TERM to identify the NIF library.
 */
static int check_load_info(ErlNifEnv *env, ERL_NIF_TERM load_info)
{
    int i;
    return enif_get_int(env, load_info, &i) && (i == NIF_LOAD_INFO);
}

/**
 * Load the NIF module.
 * @param env ErlNifEnv pointer for the calling process.
 * @param priv_data pointing the private data for the NIF library to keep between the NIF calls.
 * @param load_info ERL_NIF_TERM to identify the NIF library.
 */
static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    atom_ok = enif_make_atom(env, "ok");
    atom_error = enif_make_atom(env, "error");
    atom_null_output = enif_make_atom(env, "martini_null_output");
    atom_malloc_fail = enif_make_atom(env, "martini_malloc_fail");

    return 0;
}

/**
 * Reload the NIF module.
 * @param env ErlNifEnv pointer for the calling process.
 * @param priv_data pointing the private data for the NIF library to keep between the NIF calls.
 * @param load_info ERL_NIF_TERM to identify the NIF library.
 */
static int reload(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    // Not supported
    if (*priv_data != NULL) {
        return -1;
    }

    // Check version
    if (!check_load_info(env, load_info)) {
        return -1;
    }

    return 0;
}

/**
 * Upgrade the NIF module.
 * @param env ErlNifEnv pointer for the calling process.
 * @param priv_data pointing the private data for the NIF library to keep between the NIF calls.
 * @param old_priv_data pointing the private data given from the last calls of load() or reload().
 * @param load_info ERL_NIF_TERM to identify the NIF library.
 */
static int upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

/**
 * Unload the NIF module.
 * @param env ErlNifEnv pointer for the calling process.
 * @param priv_data pointing the private data for the NIF library to keep between the NIF calls.
 */
static void unload(ErlNifEnv *env, void *priv_data)
{
    // nop
}

// NIF function registration
static ErlNifFunc nif_funcs[] = {
    {"get_identity_nif", 5, get_identity_nif, 0}
};

// NIF initialization function
ERL_NIF_INIT(martini, nif_funcs, load, NULL, upgrade, unload);
