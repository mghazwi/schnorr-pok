# Schnorr's proof of knowledge

### This code is for academic purposes ONLY. DO NOT USE IT IN PRACTICE.

This code is an adapted version of Schnorr's proof of knowledge used in [here](https://github.com/docknetwork/crypto/tree/main)

Schnorr protocol to prove knowledge of 1 or more discrete logs in zero knowledge.
Refer [this](https://crypto.stanford.edu/cs355/19sp/lec5.pdf) for more details of Schnorr protocol.

We outline the steps here for your convenience, and to make this documentation more succinct.
Prover wants to prove knowledge of `x` in `y = g * x` (`y` and `g` are public knowledge)
Step 1: Prover generates randomness `r`, and sends `t = g * r` to Verifier
Step 2: Verifier generates random challenge `c` and send to Prover
Step 3: Prover produces `s = r + x*c`, and sends s to Verifier
Step 4: Verifier checks that `g * s = (y * c) + t`

For proving knowledge of multiple messages like `x_1` and `x_2` in `y = g_1*x_1 + g_2*x_2`:
Step 1: Prover generates randomness `r_1` and `r_2`, and sends `t = g_1*r_1 + g_2*r_2` to Verifier
Step 2: Verifier generates random challenge `c` and send to Prover
Step 3: Prover produces `s_1 = r_1 + x_1*c` and `s_2 = r_2 + x_2*c`, and sends `s_1` and `s_2` to Verifier
Step 4: Verifier checks that `g_1*s_1 + g_2*s_2 = y*c + t`
