# Oblivious SRP Library
*Author: Yamya Reiki*

Oblivious SRP is an enhanced Secure Remote Password protocol that provides stronger protection against dictionary attacks by utilizing username-rate-limited Oblivious Pseudo-Random Functions (OPRF) and supporting multi-server setups.

## Installation & Usage

To use the `oblivious-srp` library, follow these steps:

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/oblivious-srp.git
   cd oblivious-srp
   ```

2. **Install dependencies:**

   ```bash
   npm install
   ```

3. **Run the tutorial suite:**

   ```bash
   npm run tutorial
   ```

   You can check out the [./tutorial/example.cjs](./tutorial/example.cjs) for detailed examples of library usage.

## Registration Phase

| **Step**                              | **Client**                                    | **Server**                           |
|---------------------------------------|-----------------------------------------------|--------------------------------------|
| 1.                                    | Generate random salt (`s`)                    |                                      |
| 2.                                    | Compute private verifier:                     |                                      |
|                                        | `v' = g^sk % N`                               |                                      |
|                                        | where `sk = H(s, username, pw)`               |                                      |
| 3.                                    | Blind the verifier:                           |                                      |
|                                        | `blind(v')` → Send to server                  |                                      |
| 4.                                    |                                               | Evaluate OPRF on `blind(v')`         |
| 5.                                    | Finalize OPRF result:                         |                                      |
|                                        | `OPRF(v') → v1'`                              |                                     |
| 6.                                    | Compute `x` from `v'` and `v1'`:              |                                      |
|                                       | `x = H(v', v1')`                            |                                      |
| 7.                                    | Compute public verifier:                      |                                      |
|                                        | `v = g^x % N`                                 |                                      |
|                                        | Send `v`, `username`, and `s` to server       | Store `v`, `username`, and `s`       |

## Login Phase

| **Step**                              | **Client**                                    | **Server**                           |
|---------------------------------------|-----------------------------------------------|--------------------------------------|
| 1.                                    | Generate ephemeral values:                    |                                      |
|                                        | `a`, `A = g^a % N`                            |                                      |
|                                        | Send `A` and `username` to server             |                                      |
| 2.                                    |                                               | Generate `b` and `B = kv + g^b % N` |
|                                        |                                               | Send `B` and `s` to client           |
| 3.                                    | Recompute private verifier:                   |                                      |
|                                        | `v' = g^sk % N`                               |                                      |
|                                        | where `sk = H(s, username, pw)`               |                                      |
| 4.                                    | Blind the verifier:                           |                                      |
|                                        | `blind(v')` → Send to server                  |                                      |
| 5.                                    |                                               | Evaluate OPRF on `blind(v')`         |
| 6.                                    | Finalize OPRF result:                         |                                      |
|                                        | `OPRF(v') → v1'`                              |                                      |
| 7.                                    | Compute `x` from `v'` and `v1'`:              |                                      |
|                                        | `x = H(v', v1')`                            |                                      |
| 8.                                    | Compute session key:                          | Compute session key:                |
|                                        | `u = H(A, B)`                               | `u = H(A, B)`                      |
|                                        | `S = (B - k * g^x)^(a + u * x) % N`           | `S = (A * v^u)^b % N`                |
| 9.                                    | Derive session key `Kc = H(S)`                | Derive session key `K = H(S)`        |
| 10.                                   | Derive client session proof `Mc`:             | Verify client proof `Mc`:            |
|                                        | `Mc = H(H(N) XOR H(g), H(I), s, A, B, Kc)`    | `Ms = H(H(N) XOR H(g), H(I), s, A, B, K)` |
|                                        |                                               | If `Ms === Mc`, derive server proof: |
|                                        |                                               | `P = H(A, Mc, K)`                    |
| 11.                                   | Verify server session proof `P`:             |                                      |
|                                        | `Pc = H(A, Mc, Kc)`                           |                                      |
|                                        | If `Pc === P`, session established            |                                      |

## Comparison of Oblivious SRP and Traditional SRP

### Traditional SRP

- The password is transformed into a verifier `v = g^sk mod N`, where `sk = H(salt, username, password)`.
- The server stores the verifier along with the username and salt.
- During authentication, the user proves knowledge of the password through zero knowledge proof.
- A malicious server can access `v`, `s`, and the username, making dictionary attacks possible.
- The malicious server can compute `sk_guess = H(salt, username, password_guess)` and `v_guess = g^sk_guess mod N` for each of its password guesses and if the guessed `v_guess = v`, then server knows the correct password. 

### Oblivious SRP

- Does **not** store the verifier (`g^sk mod N`) directly.
- The verifier is split into a private verifier (`v'`) and a public verifier (`v`). 
- The public verifier is derived from the OPRF evaluation of the private verifier, and OPRF is rate-limited.
- Multi-server support makes offline attacks harder by requiring multiple malicious servers to collaborate.
- The public verifier (`v`) is calculated as `v = g^H(v' || v1' || ... || vn')` where `v1' ... vn'` are OPRF evaluation responses of n-th SRP server.
- If the SRP server is malicious, it can access public verifier `v`, salt `s` and the username. To mount a dictionary attack, it will require to compute `sk_guess = H(salt, username, password_guess)`, `v_guess' = g^sk_guess mod N` and then acquire the real-time OPRF responses `vn'` from each of the SRP servers to compute `v_guess = g^H(v_guess' || v1' || ... || vn')`. Only if `v_guess = v`, does the server gets to know the correct password.
- Since, the OPRF evaluation is rate-limited by username, it requires a total compromise or that all the SRP servers be collaboratively malicious, to break the password.
  
#### Enhanced Security

- Requires attackers to compromise multiple servers to execute dictionary attacks, as OPRF responses are rate-limited.

---

### Summary

- **Traditional SRP**: Vulnerable to dictionary attacks due to direct storage of verifiers.
- **Oblivious SRP**: Provides stronger protection by blinding the verifier and adding multi-server support.

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](./LICENSE) file for details.

---
