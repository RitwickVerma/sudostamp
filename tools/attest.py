#!/usr/bin/env python3
"""Check a SudoStamp key's hardware attestation. Imported by tools/pair.py (which runs as root
with `python3 -I`), so: Python standard library only, and the system `openssl` command for the
signatures -- present on every supported distribution.

The phone makes a key for this computer in its Keystore and, when the key is made with a
challenge, the secure hardware (TEE or StrongBox) signs a certificate chain that says where the
key lives. The chain ends at a Google hardware attestation root, which is EMBEDDED below and
pinned by SHA-256, so this proves the key sits in certified hardware without trusting the phone's
word, or the app's, or the network's. What is checked, in this order:

  1. the chain parses, and its last certificate is one of the pinned Google roots;
  2. openssl verifies each certificate's signature with the key of the next one up, to that root;
  3. the KeyDescription extension (1.3.6.1.4.1.11129.2.1.17) is in the leaf and nowhere else
     (Google: only the first occurrence can be trusted; a chain extended below the real leaf
     would carry a second one), and says the key is in hardware, not Software;
  4. its challenge is the one this pairing's transcript gives (a chain from another pairing, e.g.
     a real phone's replayed by something else, carries a different one);
  5. the leaf's public key IS the SSH key that is about to be pinned (same EC point);
  6. optionally, no certificate of the chain is on Google's revocation list (needs the network).

A chain that does not reach a pinned root (an emulator, an old phone, a custom ROM), or whose
signatures do not verify, proves nothing and says so: it is never mistaken for a hardware key,
and costs the person nothing unless they asked for --require-attestation. A chain that DOES verify
to a pinned root but fails 3 to 6 is a genuine statement of the hardware about a different key, a
different pairing or a software key: that is refused. Certificate validity dates are not checked:
the 2016 root expired in May 2026 and phones sold under it still attest under it, and the dates
of a hardware-signed certificate say nothing about where the key is.
"""
import base64
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import urllib.request

KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_P256 = "1.2.840.10045.3.1.7"
STATUS_URL = "https://android.googleapis.com/attestation/status"

LEVELS = {0: "Software", 1: "TEE", 2: "StrongBox"}
MAX_CERTS = 8

# Google's hardware attestation roots, from
#   https://developer.android.com/privacy-and-security/security-key-attestation  (Root certificates)
#   https://android.googleapis.com/attestation/root                              (the same two, JSON)
# fetched 2026-11-12; the two current ones match that JSON byte for byte. The first two are the
# trust anchors Google tells verifiers to use (RSA, and the ECDSA P-384 root that signs chains
# from 2026-02-01). The other three are listed on that page as "Previously Issued Root
# Certificates" and are what phones made 2016 to 2021 still chain to; the 2016 one expired on
# 2026-05-24 (see the note on dates above). Each is pinned by the SHA-256 of its DER, and the
# table is checked against its own pins when this file loads (a corrupted copy fails at once).
_ROOTS_SRC = [
    ("Google RSA root, 2022 (valid to 2042)",
     "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc",
     """
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
"""),
    ("Google ECDSA P-384 root, signs from 2026-02-01 (valid to 2035)",
     "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0",
     """
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
"""),
    ("previous RSA root, 2016 (expired 2026-05-24)",
     "c1984a3ef45c1e2a918551de10603c86f7051b2249c4891cae3230eabd0c97d5",
     """
MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYy
ODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYD
VR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAO
BgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lk
Lmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQAD
ggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfB
Pb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00m
qC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rY
DBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPm
QUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4u
JU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyD
CdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79Iy
ZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxD
qwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23Uaic
MDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1
wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk
"""),
    ("previous RSA root, 2019 (valid to 2034)",
     "1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc",
     """
MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAz
NzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnu
XKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83U
h6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cno
L/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5/cTiVKN2M1G2ok
QBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vA
D32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAI
mMAfY8U9/iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoBIuUFsVXJMTz+Jucth+IqoW
Fua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91
oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09o
jm6xNIrw2OocrDKsudk/okr/AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUB
ZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCH
ex0SdDrx+tWUDqG8At2JHA==
"""),
    ("previous RSA root, 2021 (valid to 2036)",
     "ab6641178a36e179aa0c1cdddf9a16eb45fa20943e2b8cd7c7c05c26cf8b487a",
     """
MIIFHDCCAwSgAwIBAgIJAMNrfES5rhgxMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjExMTE3MjMxMDQyWhcNMzYxMTEzMjMx
MDQyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBTNNZe5cuf8oiq+jV0itTG
zWVhSTjOBEk2FQvh11J3o3lna0o7rd8RFHnN00q4hi6TapFhh4qaw/iG6Xg+xOan
63niLWIC5GOPFgPeYXM9+nBb3zZzC8ABypYuCusWCmt6Tn3+Pjbz3MTVhRGXuT/T
QH4KGFY4PhvzAyXwdjTOCXID+aHud4RLcSySr0Fq/L+R8TWalvM1wJJPhyRjqRCJ
erGtfBagiALzvhnmY7U1qFcS0NCnKjoO7oFedKdWlZz0YAfu3aGCJd4KHT0MsGiL
Zez9WP81xYSrKMNEsDK+zK5fVzw6jA7cxmpXcARTnmAuGUeI7VVDhDzKeVOctf3a
0qQLwC+d0+xrETZ4r2fRGNw2YEs2W8Qj6oDcfPvq9JySe7pJ6wcHnl5EZ0lwc4xH
7Y4Dx9RA1JlfooLMw3tOdJZH0enxPXaydfAD3YifeZpFaUzicHeLzVJLt9dvGB0b
HQLE4+EqKFgOZv2EoP686DQqbVS1u+9k0p2xbMA105TBIk7npraa8VM0fnrRKi7w
lZKwdH+aNAyhbXRW9xsnODJ+g8eF452zvbiKKngEKirK5LGieoXBX7tZ9D1GNBH2
Ob3bKOwwIWdEFle/YF/h6zWgdeoaNGDqVBrLr2+0DtWoiB1aDEjLWl9FmyIUyUm7
mD/vFDkzF+wm7cyWpQpCVQ==
"""),
]


def _load_roots():
    roots = {}
    for name, pin, b64 in _ROOTS_SRC:
        der = base64.b64decode("".join(b64.split()))
        if hashlib.sha256(der).hexdigest() != pin:
            raise ImportError("embedded root %r does not match its pin" % name)
        roots[pin] = (name, der)
    return roots


ROOTS = _load_roots()


# ------------------------------------------------------------------ DER (just enough)

class Asn1Error(ValueError):
    pass


def tlv(buf, o, end=None):
    """One DER element at `o`: (tag, start, content_start, content_end). Definite lengths only;
    every length is checked against `end`, so a lying length cannot read past its parent."""
    end = len(buf) if end is None else end
    if o + 2 > end:
        raise Asn1Error("truncated")
    tag = buf[o]
    if tag & 0x1F == 0x1F:
        raise Asn1Error("high tag number")          # not in anything read here
    n, c = buf[o + 1], o + 2
    if n & 0x80:
        k = n & 0x7F
        if not 1 <= k <= 4 or c + k > end:
            raise Asn1Error("bad length")
        n, c = int.from_bytes(buf[c:c + k], "big"), c + k
    if c + n > end:
        raise Asn1Error("truncated")
    return tag, o, c, c + n


def kids(buf, node):
    """The elements inside a constructed one."""
    _, _, c, e = node
    out, o = [], c
    while o < e:
        n = tlv(buf, o, e)
        out.append(n)
        o = n[3]
    return out


def content(buf, node):
    return buf[node[2]:node[3]]


def oid(buf, node):
    if node[0] != 0x06:
        raise Asn1Error("not an OID")
    b = content(buf, node)
    if not b:
        raise Asn1Error("empty OID")
    parts, v = [b[0] // 40, b[0] % 40], 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(v)
            v = 0
    return ".".join(map(str, parts))


def small_int(buf, node):
    if node[0] not in (0x02, 0x0A):
        raise Asn1Error("not an INTEGER")
    return int.from_bytes(content(buf, node), "big", signed=True)


class Cert:
    """The parts of an X.509 certificate this check reads. Signatures are openssl's business."""

    def __init__(self, der):
        self.der = der
        top = tlv(der, 0)
        if top[0] != 0x30 or top[3] != len(der):
            raise Asn1Error("not one certificate")
        outer = kids(der, top)
        if len(outer) != 3 or outer[2][0] != 0x03:
            raise Asn1Error("not a certificate")
        tbs = outer[0]
        self.tbs = der[tbs[1]:tbs[3]]
        self.sig_alg = oid(der, kids(der, outer[1])[0])
        self.signature = content(der, outer[2])[1:]          # past the unused-bits byte
        f = kids(der, tbs)
        i = 1 if f[0][0] == 0xA0 else 0              # [0] version
        if len(f) < i + 6:
            raise Asn1Error("short TBSCertificate")
        self.serial = int.from_bytes(content(der, f[i]), "big")
        self.tbs_sig_alg = oid(der, kids(der, f[i + 1])[0])
        self.issuer = der[f[i + 2][1]:f[i + 2][3]]
        self.subject = der[f[i + 4][1]:f[i + 4][3]]
        self.spki = f[i + 5]
        self.spki_der = der[f[i + 5][1]:f[i + 5][3]]
        self.exts = {}                               # OID -> [OCTET STRING contents]
        for n in f[i + 6:]:
            if n[0] != 0xA3:
                continue
            for ext in kids(der, kids(der, n)[0]):
                e = kids(der, ext)
                self.exts.setdefault(oid(der, e[0]), []).append(content(der, e[-1]))

    def fingerprint(self):
        return hashlib.sha256(self.der).hexdigest()

    def self_signed(self):
        return self.issuer == self.subject

    def ec_point(self):
        """The 65-byte uncompressed P-256 point of the subject key, or None for any other key."""
        alg, bits = kids(self.der, self.spki)[:2]
        a = kids(self.der, alg)
        if oid(self.der, a[0]) != OID_EC_PUBLIC_KEY or len(a) < 2 or oid(self.der, a[1]) != OID_P256:
            return None
        b = content(self.der, bits)
        return b[1:] if len(b) == 66 and b[0] == 0 and b[1] == 4 else None


def key_description(ext):
    """The first eight fields of the KeyDescription (the same in every attestation version)."""
    root = tlv(ext, 0)
    f = kids(ext, root)
    if root[0] != 0x30 or root[3] != len(ext) or len(f) < 8:
        raise Asn1Error("not a KeyDescription")
    if f[4][0] != 0x04:
        raise Asn1Error("no challenge")
    return {
        "version": small_int(ext, f[0]),
        "attestation_level": small_int(ext, f[1]),
        "keymaster_level": small_int(ext, f[3]),
        "challenge": content(ext, f[4]),
    }


# ------------------------------------------------------------------ the verdict

class Result:
    """verdict: 'attested' (level is 'StrongBox' or 'TEE'), 'unverified' (nothing can be said:
    reason), or 'refused' (a genuine hardware chain that disagrees with this pairing: reason)."""

    def __init__(self, verdict, level=None, reason=""):
        self.verdict, self.level, self.reason = verdict, level, reason

    def line(self):
        if self.verdict == "attested":
            return "Key attested: %s" % self.level
        return "Key NOT hardware-attested (%s)" % self.reason

    def __repr__(self):
        return "Result(%r, %r, %r)" % (self.verdict, self.level, self.reason)


def unverified(reason):
    return Result("unverified", None, reason)


def refused(reason):
    return Result("refused", None, reason)


def openssl_path():
    return shutil.which("openssl")


# Signature algorithms a Google chain uses -> the digest openssl is told to apply.
SIG_DIGESTS = {
    "1.2.840.10045.4.3.2": "sha256", "1.2.840.10045.4.3.3": "sha384", "1.2.840.10045.4.3.4": "sha512",
    "1.2.840.113549.1.1.11": "sha256", "1.2.840.113549.1.1.12": "sha384", "1.2.840.113549.1.1.13": "sha512",
}


def verify_signatures(certs, openssl, tmp):
    """None if every certificate of `certs` (leaf first, the last being a pinned root) is signed
    by the next one up, checked by `openssl dgst -verify`; else why not.

    Each link is checked on its own, NOT with `openssl verify`: that also enforces CA flags, and
    the attestation-key certificate of real Pixel 2 chains says CA:FALSE while signing the leaf,
    so a path validation rejects phones that attest correctly. Here the trust comes from the
    pinned root and from every link being signed by the next key; what a certificate claims about
    itself is not consulted. The hash is chosen from the signed algorithm identifier and must
    agree with the outer one."""
    def pem(label, der):
        b = base64.b64encode(der).decode()
        return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(b[i:i + 64] for i in range(0, len(b), 64)), label)
    d = tempfile.mkdtemp(prefix="attest.", dir=tmp)
    try:
        for child, issuer in zip(certs, certs[1:]):
            if child.issuer != issuer.subject:
                return "the chain is not in order (a certificate's issuer is not the next one)"
            digest = SIG_DIGESTS.get(child.sig_alg)
            if digest is None or child.sig_alg != child.tbs_sig_alg:
                return "a certificate uses a signature algorithm this check does not accept"
            files = {"key.pem": pem("PUBLIC KEY", issuer.spki_der), "sig.bin": child.signature, "tbs.bin": child.tbs}
            for name, data in files.items():
                with open("%s/%s" % (d, name), "wb" if isinstance(data, bytes) else "w") as f:
                    f.write(data)
            try:
                p = subprocess.run([openssl, "dgst", "-" + digest, "-verify", d + "/key.pem", "-signature",
                                    d + "/sig.bin", d + "/tbs.bin"], capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.TimeoutExpired) as e:
                return "openssl could not run: %s" % e
            out = (p.stdout + p.stderr).strip()
            if p.returncode != 0 or "Verified OK" not in out:
                if "Verification failure" in out or "Verification Failure" in out:
                    return "the signatures do not verify"
                return "openssl failed: %s" % " ".join(out.split())[:120]
        return None
    finally:
        shutil.rmtree(d, ignore_errors=True)


def fetch_status(url=STATUS_URL, timeout=10):
    """Google's revocation list: {serial (lowercase hex, no leading zeros): entry}."""
    with urllib.request.urlopen(url, timeout=timeout) as r:
        data = r.read(8 * 1024 * 1024)
    return json.loads(data.decode("utf-8"))["entries"]


def check(chain, expected_challenge, ssh_blob, roots=None, openssl="", tmp="/tmp",
          check_revocation=False, status=fetch_status):
    """Judge `chain` (DER certificates, leaf first, as the phone sent them) for a pairing whose
    challenge must be `expected_challenge` and whose key is the SSH blob `ssh_blob`.
    `roots`, `openssl` and `status` are parameters so tests can supply their own; production
    leaves them alone."""
    roots = ROOTS if roots is None else roots
    openssl = openssl_path() if openssl == "" else openssl
    try:
        if not chain:
            return unverified("the phone sent no certificates")
        if len(chain) > MAX_CERTS:
            return unverified("the chain is implausibly long")
        certs = [Cert(d) for d in chain]
    except Asn1Error as e:
        return unverified("the certificate chain is unreadable: %s" % e)

    # 1. Google's root, by pin. Only then is anything in the chain worth reading.
    top = certs[-1]
    if top.fingerprint() not in roots:
        return unverified("the chain does not end at a Google hardware attestation root: an emulator, "
                          "or a phone without hardware attestation")
    # 2. Every signature up to it.
    if not openssl:
        return unverified("attestation not checked: openssl missing")
    why = verify_signatures(certs, openssl, tmp)
    if why:
        return unverified(why)

    # From here on the chain is Google's, so what it says is trusted. 3: where the key lives.
    try:
        found = [i for i, c in enumerate(certs) if KEY_DESCRIPTION_OID in c.exts]
        if found != [0] or len(certs[0].exts[KEY_DESCRIPTION_OID]) != 1:
            return refused("the attestation extension is not in the leaf only")
        kd = key_description(certs[0].exts[KEY_DESCRIPTION_OID][0])
        point = certs[0].ec_point()
    except Asn1Error as e:
        return refused("the attestation extension is unreadable: %s" % e)
    level = min(kd["attestation_level"], kd["keymaster_level"])
    if level not in LEVELS:
        return refused("unknown security level %d" % level)
    if level == 0:
        return refused("the hardware says this key is in software")
    # 4. This pairing, not another.
    if kd["challenge"] != expected_challenge:
        return refused("the attestation is for another pairing (wrong challenge)")
    # 5. The key that is about to be pinned.
    if point is None or ssh_blob[-65:] != point or len(ssh_blob) < 65:
        return refused("the attested key is not the key the phone gave for pairing")
    # 6. Revocation, on request.
    if check_revocation:
        try:
            entries = status()
        except Exception as e:                       # offline, blocked, malformed: all one answer
            return Result("unverified", LEVELS[level], "revocation status unknown: %s" % type(e).__name__)
        for c in certs:
            hit = entries.get("%x" % c.serial)
            if hit:
                return refused("a certificate in the chain is %s by Google" % str(hit.get("status", "revoked")).lower())
    return Result("attested", LEVELS[level])
