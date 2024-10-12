# Oblivious SRP Library
*Author: Yamya Reiki*

Oblivious SRP is an enhanced Secure Remote Password protocol that provides stronger protection against dictionary attacks by utilizing username-rate-limited Oblivious Pseudo-Random Functions (OPRF) and supporting multi-server setups.

## Installation & Usage

To use the `oblivious-srp` library, follow these steps:

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/oblivious-srp.git
   cd oblivious-srp

2. **Run the following command to install all required dependencies:**

    ```bash
    npm install

3. **After installing dependencies, you can run the tutorial suite using the default npm script:**

    ```bash
    npm run tutorial

- You can check-out the [./tutorial/example.cjs] for detailed examples of library usage.

## Registration Phase
-------------------------------------------------------------------------
|                 Client               |           Server               |
-------------------------------------------------------------------------
| 1. Generate random salt (s)          |                                |
|                                      |                                |
| 2. Compute private verifier:         |                                |
|    v' = g^sk % N                     |                                |
|    where sk = H(s, username, pw)     |                                |
|                                      |                                |
| 3. Blind verifier:                   |                                |
|    blind(v') ----------------------> |                                |
|                                      | 4. Evaluate blinded request:   |
|                                      |    Evaluate OPRF on blind(v')  |
|              <---------------------- |                                |
| 5. Finalize OPRF result:             |                                |
|    OPRF(v') -> v1'                   |                                |
|                                      |                                |
| 6. Compute x from v' & v1':          |                                |
|    x = H(v' || v1')                  |                                |
|                                      |                                |
| 7. Compute public verifier:          |                                |
|    v = g^x % N                       |                                |
|    Send v, username, s ------------> | 8. Store v, username, s        |
-------------------------------------------------------------------------

## Login Phase

-------------------------------------------------------------------------
|                 Client               |           Server               |
-------------------------------------------------------------------------
| 1. Generate ephemeral values:        |                                |
|    a, A = g^a % N                    |                                |
|    Send A, username ---------------->|                                |
|                                      | 2. Generate ephemeral b:       |
|                                      |    B = kv + g^b % N            |
|              <---------------------- |    Send B, s                   |
|                                      |                                |
| 3. Recompute private verifier:       |                                |
|    v' = g^sk % N                     |                                |
|    where sk = H(s, username, pw)     |                                |
|                                      |                                |
| 4. Blind verifier:                   |                                |
|    blind(v') ----------------------> |                                |
|                                      | 5. Evaluate blinded request:   |
|                                      |    Evaluate OPRF on blind(v')  |
|              <---------------------- |                                |
| 6. Finalize OPRF result:             |                                |
|    OPRF(v') -> v1'                   |                                |
|                                      |                                |
| 7. Compute x from v' & v1':          |                                |
|    x = H(v' || v1')                  |                                |
|                                      |                                |
| 8. Compute session key:              | 8. Compute session key:        |
|    u = H(A || B)                     |    u = H(A || B)               |
|    S = (B - k * g^x)^(a + u * x) % N |    S = (A * v^u)^b % N         |
|                                      |                                |
| 9. Derive session key:               | 9. Derive session key:         |
|    Kc = H(S)                         |    K = H(S)                    |
|                                      |                                |
| 10. Derive client session proof:     | 10. Verify client proof:       |
|     Mc = H(H(N) XOR H(g), H(I),      |     Ms = H(H(N) XOR H(g),      |
|     s, A, B, Kc)                     |     H(I), s, A, B, K)          |
|                                      |     If Ms === Mc               |
|                                      |        Derive server proof:    |
|                                      |        P = H(A, Mc, K)         |
|                        P  <--------- |                                |
|                                      |                                |
| 11. Verify server session proof:     |                                |
|     Pc = H(A, Mc, Kc)                |                                |
|     If Pc === P                      |                                |
|        Session Established           |                                |
-------------------------------------------------------------------------

## Comparison of Oblivious SRP and Traditional SRP

### Traditional SRP:
- The user's password is transformed into a verifier (`v`) using the formula `v = g^sk mod N`, where `sk = H(salt, username, password)`.
- The server stores the verifier (`v`) along with the username and salt in its database.
- During authentication, the server sends a challenge, and the user proves knowledge of the password through zero knowledge proof.
- If the server is malicious, it can access `v`, `s`, and the username, allowing for dictionary attacks.
- The malicious server can compute `sk_guess = H(salt, username, password_guess)` and `v_guess = g^sk_guess mod N` for each of its password guesses and if the guessed `v_guess = v`, then server knows the correct password. 

#### Vulnerabilities:
- Storing the public verifier directly allows attackers to perform brute-force attacks on the password if they gain access to the server database.

---

### Oblivious SRP:
- The protocol does **not** store the verifier (`g^sk mod N`) directly. Instead, it splits the verifier into a private verifier (`v'`) and a public verifier (`v`). The server sees a **blinded version** of the private verifier (`v'`) through a rate-limited **Oblivious Pseudo-Random Function (OPRF)** and only stores the public verifier (`v`). The public verifier (`v`) is calculated as `v = g^H(v' || v1' || ... || vn')` where `v1' ... vn'` are OPRF evaluation responses of n-th SRP server. 
- If the SRP server is malicious, it can access public verifier `v`, salt `s` and the username. To mount a dictionary attack, it will require to compute `sk_guess = H(salt, username, password_guess)`, `v_guess' = g^sk_guess mod N` and then acquire the real-time OPRF responses `vn'` from each of the SRP servers to compute `v_guess = g^H(v_guess' || v1' || ... || vn')`. Only if `v_guess = v`, does the server gets to know the correct password. 
- Since, the OPRF evaluation is rate-limited by username, it requires all the SRP servers to be collaboratively malicious to break the password.      

#### Enhanced Security:
- Oblivious SRP can be extended to a **multi-server model**, requiring attackers to obtain valid rate-limited OPRF evaluation results from **all servers** to successfully guess the password.
- This makes it significantly harder for attackers to execute offline attacks, as they need to compromise several servers and compute consistent results.

---

### Summary:
- **Traditional SRP** is vulnerable due to the direct storage of the verifier. It is prone to dictionary attacks and online repeated requests for guessing the true password.
- **Oblivious SRP** enhances security by **obscuring sensitive information** and preventing dictionary attacks, especially with the option to extend the protocol to a multi-server setup.

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](./LICENSE) file for details.

