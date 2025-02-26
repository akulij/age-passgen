# Generate age keys from passphrase

## Description
This utility (age-gen-passphrase) generates secret and public keys (into stdout) from your entered passphrase or piped stdin
Strong password highly recomended

## Password selection
To keep entropy at at the same level of $\geq 2^{256}$ bits, as in private key of curve25519 (which is used in age encryption), you should use long password.
Exact amount of required characters can be calculated by formula: $\lceil 256 / log_2(Nchars) \rceil$


## TODO
[ ] output identities instead of keys (to be closer in user experience to age-keygen)
[ ] piped/terminal output as raw/verbose
[ ] handle broken pipe signal since program will so much depend on pipes
