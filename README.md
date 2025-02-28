# Generate age keys from passphrase

This utility (age-passgen) generates secret and public keys (into stdout) from your entered passphrase or piped stdin
Strong password highly recomended

## Password selection
To keep entropy at at the same level of $\geq 2^{256}$ bits, as in private key of curve25519 (which is used in age encryption), you should use long password.
Exact amount of required characters can be calculated by formula: $\lceil 256 / log_2(Nchars) \rceil$


## TODO
[X] piped/terminal output as raw/verbose
[X] handle broken pipe signal since program will so much depend on pipes
[ ] option to read hex number that will be used instead of hash of password (usefull if user already has sha 256 hash of smth or want to use something else as input instead)
