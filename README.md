# FHSE (FIDO2 Hmac-Secret Encryption)
## About
TL;DR => Encrypt files using password and 1+ FIDO2 security keys. The process
is quantum-safe and guarantees 256-bit security (due to FIDO2 spec).

This C library (with C++ bindings) provides hardware backed (FIDO2) security
for encryption keys in addition to a traditional password. The user typically
enters a password to unlock the FIDO2 details, and then uses a FIDO2 key (from
a set of N keys) to generate a "hmac-secret" that unlocks the "root" secret
(whose security-level is determined by the "seed" but never more than 256
bits). The process only uses quantum-safe primitives, and does _not_ require
storage on the FIDO2 key (it does not use a "discoverable" key slot). The
security level of the process (that encrypts the "root" secret) is guaranteed
~256-bits, as the FIDO2 spec provides 256-bits of "hmac-secret" material from
an internal device/hardware private key mixed with a 256-bit FHSE provided salt
(that gets encrypted with password).

The primary drawback is that a metadata blob must be stored along-side the
data to unlock the "root" secret. This issue, and lost/damaged FIDO2 keys, is
mitigated by providing recovery from a "seed". The seed process is left to the
client and is capped at the 256-bit security level; an empty seed can be
provided to indicate the generation of a randomized 256-bit "root" secret,
which means nothing is recoverable if the FHSE data, password or FIDO2 keys are
lost.

The primary use-case is Monero software wallets, where the wallet provides a
single seed to the user for recovery. The raw wallet seed is given to a
cryptographic-KDF, and whose output is provided to FHSE as its seed. If the
user loses their FHSE file, FIDO2 keys, OR password, the original "root" secret
can be recovered from the Monero wallet seed. The advantage is that the user can
safely store wallet metadata files "in the cloud" with guaranteed 256-bit
quantum safe security. The user can also omit the FHSE file from the backup;
if the cloud provider steals a FIDO2 key, they still need the FIDO2 salt which
is encrypted with password and whose encrypted value is never stored in the
cloud. The Monero wallet "keys" file is also encrypted with guaranteed 256-bit
security, and does not need to be backed up since it can be recovered from
wallet seed.

> Hardware wallets (Ledger and Trezor) support FIDO2 standard, but do not allow
> recovery from seed as there is no way to get secret material without a FIDO2
> handle. In other words, the "seed" given to FHSE must be random bytes when
> using a Hardware wallet. This requires backup of the FHSE file, negating
> some of the security of the cloud-backup case. Trezor wallet owners can
> mitigate this by generating a seed from an email address (see
> [macer](https://github.com/cifro-codes/macer)).

> Using FIDO2 to lock wallets provides a more clandestine approach to
> security - Ledger/Trezor are known cryptocurrency wallets whereas a Yubico
> device is cheaper and draws less attention.

