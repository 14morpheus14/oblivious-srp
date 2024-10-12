/*
 * Oblivious SRP Library
 *
 * Copyright (c) 2024 Yamya Reiki <reiki.yamya14@gmail.com>
 *
 * This file is part of the Oblivious SRP library.
 *
 * Oblivious SRP is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is licensed under the GPLv3, which means that you can use,
 * modify, and distribute it freely, but you cannot incorporate it into
 * proprietary software. Any derivative work must also be licensed
 * under the same terms, ensuring that it remains free for all users.
 *
 * Oblivious SRP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * In no event and under no legal theory, whether in tort (including negligence),
 * contract, or otherwise, unless required by applicable law (such as deliberate
 * and grossly negligent acts) or agreed to in writing, shall any contributor be
 * liable to you for damages, including any direct, indirect, special, incidental,
 * or consequential damages of any character arising as a result of this software
 * or out of the use or inability to use the software (including but not limited to
 * damages for loss of goodwill, work stoppage, computer failure or malfunction, or
 * any and all other commercial damages or losses), even if such contributor has
 * been advised of the possibility of such damages.
 *
 * You should have received a copy of the GNU General Public License
 * along with Oblivious SRP. If not, see <https://www.gnu.org/licenses/>.
 */

'use strict';

// Import required modules
const TypeSRP = require('../util/type-srp.cjs'); // SRP Integer handling for large numbers
const params = require('../util/params.cjs'); // SRP parameters such as prime N, generator g, etc.
const OPRFClientHandler = require('./OPRFClient.cjs');

/**
 * SRPClient class to handle Secure Remote Password (SRP) operations.
 * This class provides methods to generate salts, derive private keys, derive private verifier, 
 * perform blind evaluation on private verifer, perform OPRF finalization on private verifier, 
 * derive verifier hash, derive public verifier, 
 * generate ephemerals and derive session keys for SRP authentication.
 */
class SRPClient {
  constructor() {
    this.oprfClient = new OPRFClientHandler(); // Create the OPRF Client Handler;
  }

  /**
   * Generate a random salt for the SRP protocol.
   * @returns {string} A random salt in hexadecimal format.
   */
  generateSalt() {
    return TypeSRP.randomInteger(params.hashOutputBytes).toHex();
  }

  /**
   * Derive a private key (sk) from a given salt, username, and password.
   * This is computed as: sk = H(salt, H(username:password)).
   * @param {string} salt - The user's salt.
   * @param {string} username - The user's username.
   * @param {string} password - The user's password.
   * @returns {string} The derived private key in hexadecimal format.
   */
  async derivePrivateKey(salt, username, password) {
    const { H } = params; // Hash function (H) from SRP params
    const s = TypeSRP.fromHex(salt); // Convert salt to TypeSRP
    const I = String(username); // Convert username to string
    const p = String(password); // Convert password to string
    return H(s, H(`${I}:${p}`)).toHex(); // Compute private key
  }

  /**
   * Derive the private verifier (v') from private key (sk).
   * This is computed as: v' = g^sk % N
   * @param {string} privateKey - The private key (sk) derived from username and password in hex.
   * @returns {Uint8Array} The private verifier in hexadecimal format  
   */
  derivePrivateVerifier(privateKey) {
    const {N, g} = params;
    const sk = TypeSRP.fromHex(privateKey);
    return g.modPow(sk, N).toUint8Array();
  }

  /**
   * Blind evaluate the OPRF private verifier (v') as private input.
   * @param {string} v_ - The private verifier (v') as private input to OPRF in hex.
   * @returns {Object} - Contains `finData` (the blind data) and `serializedEvalReq` (the serialized evaluation request to send to server).
   */
  async blindEvalOPRFInput(v_) {
    // Perform blind evaluation
    const { finData, serializedEvalReq } = await this.oprfClient.performBlindEvaluation(v_);
    return {finData, serializedEvalReq};
  }

  /**
   * Finalize the OPRF Output
   * @param {Uint8Array} responseData - The evaluation response from the server. 
   * @param {Object} blindData - Contains `blindData` (the blind data).
   * @returns {string} The hexadeximal output of OPRF function.
   */
  async finalizeOPRF(responseData, blindData) {
    // Deserialize the server's response
    const deserializedEvaluation = this.oprfClient.deserializeEvaluation(responseData);
    // Finalize and get the OPRF output
    const output = await this.oprfClient.finalizeEvaluation(blindData, deserializedEvaluation);
    // Convert the Uint8Array output to a hex string
    const hexOutput = Array.from(output).map(byte => byte.toString(16).padStart(2, '0')).join('');
    return hexOutput;
  }
  
  /**
   * Derive the verifierHash (x) from private verifier (v'), and OPRF outputs of SRPServers.
   * This is computed as: x = H(v'||v1'||v2'||...||vn').
   * 
   * @param {...(string)} args - Two or more arguments to hash (one private verifier (v') and multiple OPRF outputs) in hex.
   * @returns {string} The derived verifierHash in hexadecimal format.
   */
  async deriveVerifierHash(...args) {
    const { H } = params; // Import the hash function (argon2-based H) from params

    // Concatenate all the arguments into a single string
    const concatenatedInput = args.join('');

    // Convert the concatenated input to TypeSRP
    const inputInteger = TypeSRP.fromHex(concatenatedInput);

    // Hash the concatenated input using params.H and return the result in hex format
    return H(inputInteger).toHex();
  }

  /**
   * Derive the public verifier (v) from a verifierHash (x).
   * This is computed as: v = g^x % N.
   * @param {string} verifierHash - The verifierHash (x) = H(v'||v1'||v2'||...||vn') in hex.
   * @returns {string} The public verifier in hexadecimal format.
   */
  derivePublicVerifier(verifierHash) {
    const { N, g } = params; // SRP modulus (N) and generator (g)
    const x = TypeSRP.fromHex(verifierHash); // Convert verifierHash to TypeSRP
    return g.modPow(x, N).toHex(); // Compute verifier as g^x % N
  }

  /**
   * Generate the client's ephemeral values for SRP: 
   * Secret (a) and public (A), where A = g^a % N.
   * @returns {Object} Contains the secret and public ephemeral values in hexadecimal format.
   */
  generateEphemeral() {
    const { N, g } = params; // SRP modulus (N) and generator (g)
    let a = TypeSRP.randomInteger(params.hashOutputBytes); // Generate random secret 'a'
    const A = g.modPow(a, N); // Compute public ephemeral A = g^a % N
    return { secret: a.toHex(), public: A.toHex() }; // Return secret and public values in hex
  }

  /**
   * Derive the session key and proof based on the client's secret ephemeral, 
   * server's public ephemeral, salt, username, and private key.
   * @param {string} clientSecretEphemeral - The client's secret ephemeral (a) in hex.
   * @param {string} serverPublicEphemeral - The server's public ephemeral (B) in hex.
   * @param {string} salt - The user's salt in hex.
   * @param {string} username - The user's username.
   * @param {string} verifierHash - The user's verifierHash (x).
   * @returns {Object} Contains the session key (K) and proof (M) in hex.
   */
  async deriveSession(clientSecretEphemeral, serverPublicEphemeral, salt, username, verifierHash) {
    const { N, g, k, H } = params; // SRP parameters including modulus (N), generator (g), multiplier (k), and hash function (H)
    const a = TypeSRP.fromHex(clientSecretEphemeral); // Convert client's secret ephemeral (a) to TypeSRP
    const B = TypeSRP.fromHex(serverPublicEphemeral); // Convert server's public ephemeral (B) to TypeSRP
    const s = TypeSRP.fromHex(salt); // Convert salt to TypeSRP
    const I = String(username); // Convert username to string
    const x = TypeSRP.fromHex(verifierHash); // Convert private key to TypeSRP

    // Check if server's public ephemeral (B) is valid (B % N != 0)
    if (B.mod(N).equals(TypeSRP.ZERO)) {
      throw new Error('Server sent an invalid public ephemeral');
    }

    // Compute A = g^a % N
    const A = g.modPow(a, N);
    // Compute u = H(A, B)
    const u = H(A, B);

    // Compute shared secret S = (B - k * g^x)^(a + u * x) % N
    const S = B.add(N) // Step 1: Add N to ensure positivity
              .subtract(k.multiply(g.modPow(x, N)).mod(N)) // Step 2: Subtract k * g^x (mod N)
              .mod(N) // Step 3: Take result modulo N to ensure it's within [0, N-1]
              .modPow(a.add(u.multiply(x)), N); // Step 4: Perform modular exponentiation

    // Compute session key K = H(S)
    const K = H(S);
    // Compute proof M = H(H(N) XOR H(g), H(I), s, A, B, K)
    const M = H(H(N).xor(H(g)),H(I), s, A, B, K);

    // Return the session key and proof in hexadecimal format
    return { key: K.toHex(), proof: M.toHex() };
  }

  /**
   * Verify the server's session proof (M2) against the client's session.
   * @param {string} clientPublicEphemeral - The client's public ephemeral (A) in hex.
   * @param {Object} clientSession - The client's session, containing the proof (M) and session key (K).
   * @param {string} serverSessionProof - The server's session proof (M2) in hex.
   * @throws {Error} If the server's session proof is invalid.
   */
  verifySession(clientPublicEphemeral, clientSession, serverSessionProof) {
    const { H } = params; // Hash function (H) from SRP params
    const A = TypeSRP.fromHex(clientPublicEphemeral); // Convert client’s public ephemeral (A) to TypeSRP
    const M = TypeSRP.fromHex(clientSession.proof); // Convert client's session proof (M) to TypeSRP
    const K = TypeSRP.fromHex(clientSession.key); // Convert client's session key (K) to TypeSRP
    // Compute the expected server session proof: H(A, M, K)
    const expected = H(A, M, K);
    const actual = TypeSRP.fromHex(serverSessionProof); // Convert server's session proof (M2) to TypeSRP

    // Compare the server's provided session proof with the expected value
    if (!actual.equals(expected)) {
      throw new Error('Server provided session proof is invalid');
    }
  }
}

// Export the SRPClient class for use in other modules
module.exports = SRPClient;
