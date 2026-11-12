# Real hardware attestation chains

Test data for `tools/test/test_attest.py`: certificate chains (PEM, leaf first) that real phones'
secure hardware produced. Nothing here was made for this project and no byte was edited. The
challenge each phone was given is in the test, copied from `attestationChallenge` in the metadata
Google publishes beside each chain (not kept here: its boot-key hashes look like secrets to scanners).

Source: https://github.com/android/keyattestation, `testdata/`, fetched 2026-11-12, Apache-2.0
(the same licence as this repository). Mapping:

| file | upstream path | what it is |
|---|---|---|
| `tegu-strongbox-ec-root2026` | `tegu/sdk36/SB_EC_2026_ROOT` | StrongBox, ends at the ECDSA P-384 root |
| `caiman-strongbox-rkp` | `caiman/sdk36/SB_EC_RKP` | StrongBox, remotely provisioned, 2019 RSA root |
| `akita-tee-root2019` | `akita/sdk34/TEE_EC_NONE` | TEE, 2019 RSA root |
| `blueline-tee-root2016` | `blueline/sdk28/TEE_EC_NONE` | TEE, the 2016 RSA root (expired 2026-05-24) |
| `walleye-tee-ca-false` | `walleye/sdk27/TEE_EC_NONE` | TEE, 2016 root; the attestation-key certificate says CA:FALSE |
