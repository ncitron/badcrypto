## badcrypto
This repository serves to document my learning of cryptography. Each Rust modules implements a different cryptographic protocol. Each module will have it's own readme describing the protocol and any interesting learnings I bumped into along the way.

## warning
Do not use this in production. It is called badcrypto for a reason. Some of these protocols may be implemented incorrectly. Even when I do implement them correctly, there may be side channel attacks. I have made no effort to ensure that these algorithms are constant-time, which means some of them may be susceptible to timing attacks. If you use this, you will get wrecked. I won't even feel bad, the repo is literally called badcrypto. Just to reiterate, don't use this. Don't roll your own crypto. Don't let me roll your crypto for you. 

## contents
[ElGamal](./src/elgamal)
