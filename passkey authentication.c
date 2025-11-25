#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fido.h>

int main() {
    int r;

    // Initialize libfido2
    if (fido_init(0) != FIDO_OK) {
        fprintf(stderr, "Failed to initialize libfido2\n");
        return 1;
    }

    // -----------------------------
    // Loaded/stored user data
    // -----------------------------
    const unsigned char credential_id[] = {
        /* Replace with actual credential ID bytes */
        0x00
    };
    size_t credential_id_len = sizeof(credential_id);

    const unsigned char user_public_key[] = {
        /* Replace with actual COSE-encoded public key */
        0x00
    };

    // -----------------------------
    // Authentication response from browser
    // -----------------------------
    const unsigned char client_data_json[] = {
        /* navigator.credentials.get().response.clientDataJSON */
        0x00
    };
    size_t client_data_json_len = sizeof(client_data_json);

    const unsigned char authenticator_data[] = {
        /* navigator.credentials.get().response.authenticatorData */
        0x00
    };
    size_t authenticator_data_len = sizeof(authenticator_data);

    const unsigned char signature[] = {
        /* navigator.credentials.get().response.signature */
        0x00
    };
    size_t signature_len = sizeof(signature);

    // Challenge from your server (SHA256 of clientDataJSON.challenge)
    const unsigned char challenge_hash[32] = {
        /* SHA256("your original challenge") */
        0x00
    };

    // -----------------------------
    // Create assertion object
    // -----------------------------
    fido_assert_t *assert = fido_assert_new();
    if (!assert) {
        fprintf(stderr, "Failed to create assertion object\n");
        return 1;
    }

    // Set relying party ID (your domain)
    if ((r = fido_assert_set_rp(assert, "example.com")) != FIDO_OK) {
        fprintf(stderr, "set_rp: %s\n", fido_strerr(r));
        return 1;
    }

    // Set hashed challenge
    if ((r = fido_assert_set_clientdata_hash(assert,
            challenge_hash, sizeof(challenge_hash))) != FIDO_OK) {
        fprintf(stderr, "set_clientdata_hash: %s\n", fido_strerr(r));
        return 1;
    }

    // Allow a single credential ID
    if ((r = fido_assert_allow_cred(assert,
            credential_id, credential_id_len)) != FIDO_OK) {
        fprintf(stderr, "allow_cred: %s\n", fido_strerr(r));
        return 1;
    }

    // -----------------------------
    // Verify assertion signature
    // -----------------------------
    r = fido_assert_verify(assert, 0,
                           user_public_key,
                           authenticator_data,
                           authenticator_data_len,
                           client_data_json,
                           client_data_json_len,
                           signature,
                           signature_len);

    if (r == FIDO_OK) {
        printf("Passkey verification SUCCESS\n");
    } else {
        printf("Passkey verification FAILED: %s\n", fido_strerr(r));
    }

    fido_assert_free(&assert);
    return 0;
}
