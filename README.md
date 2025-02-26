# Generate age keys from passphrase

## Description
This utility (age-gen-passphrase) generates secret and public keys (into stdout) from your entered passphrase or piped stdin
Strong password highly recomended

## Password selection
To keep entropy at at the same level of $\geq 2^{256}$ bits, you should use long password.
Exact amount of required characters can be calculated by formula: $\lceil 256 / log_2(Nchars) \rceil$
