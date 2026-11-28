# Mutation checks for vault/VaultCrypto.kt

Each guard was broken on purpose, the vault tests run on fresh XML (results deleted before each
run), the named tests went red, and the source was restored and re-run green (19/19). Every mutant
compiled (no `e:` lines). Run with
`./gradlew testDebugUnitTest --offline --tests 'com.ritwick.sudostamp.vault.*'`.

| # | Mutant (in VaultCrypto.kt) | Red tests |
|---|---|---|
| a | delete `if (!macEqual(want, e.mac)) throw VaultRefused("MAC mismatch")` in `decrypt` | `VaultCryptoTest.every single flipped bit in iv, ct or mac is refused`, `VaultCryptoTest.the MAC is checked before anything is decrypted`, `VaultCryptoTest.an item key is re-wrapped under the org key and the item's fields still open`, `VaultCryptoTest.wipe zeroes the key material`, `VaultEncStringFuzzTest.one flipped bit in iv, ct or mac is refused` |
| b | `macEqual(a, b) = true` instead of `MessageDigest.isEqual(a, b)` | the same five as (a) |
| c | delete the `iterations < MIN_ITERATIONS` refusal in `masterKey` | `VaultCryptoTest.iterations outside 600000 to 2000000 are refused before any work` |
| d | `'2', '0' -> {` in `EncString.parse` (type 0 parsed as type 2) | `VaultCryptoTest.EncString types other than 2 and 4 are refused, type 0 included`, `VaultEncStringFuzzTest.parser agrees with an independent reference and only ever refuses` |

Extra guards, same procedure:

| # | Mutant | Red tests |
|---|---|---|
| e | delete the canonical-base64 check in `unb64` | `VaultCryptoTest.non-canonical base64 is refused`, `VaultEncStringFuzzTest.parser agrees with an independent reference and only ever refuses` |
| f | drop `k.modulus.bitLength() != 2048` in `decryptPrivateKey` | `VaultCryptoTest.keys of the wrong size or kind are refused` |
| g | delete the iv length check in `EncString.parse` | `VaultCryptoTest.type 2 with the wrong shape is refused`, `VaultEncStringFuzzTest.parser agrees with an independent reference and only ever refuses` |
| h | delete the `iterations > MAX_ITERATIONS` refusal | `VaultCryptoTest.iterations outside 600000 to 2000000 are refused before any work` |
| i | OAEP-SHA-256 instead of SHA-1 in `unwrapOrgKey` | 6 VaultCryptoTest cases, e.g. `user key, private key, org key and item fields decrypt as pyca encrypted them`, `keys of the wrong size or kind are refused` |

(a) and (b) are caught by the same tests: both let a forged MAC through, and only the result
(opened, or refused by the padding instead of the MAC) is observable. Timing of the comparison
itself is not measured by any test. `MessageDigest.isEqual` in OpenJDK's library (which Android's
libcore is from API 24) takes time that depends only on the lengths.
