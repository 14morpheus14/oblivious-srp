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

// Import necessary modules and classes from the Cloudflare OPRF library
const { Evaluation, Oprf, OPRFClient: VoprfClient } = require('@cloudflare/voprf-ts');

class OPRFClientHandler {
    constructor() {
        this.suite = Oprf.Suite.P256_SHA256;
        this.client = new VoprfClient(this.suite);
    }
    /**
     * Encodes input to a Uint8Array.
     * 
     * @param {string|Uint8Array} input - The input to encode, can be a string (hex string or regular string) or Uint8Array.
     * @returns {Uint8Array} - The encoded input as Uint8Array.
     */
    encodeInput(input) {
        if (input instanceof Uint8Array) {
            return input;
        }
        
        // Check if the input is a valid hexadecimal string and convert it to Uint8Array
        const isHex = /^[0-9a-fA-F]+$/i.test(input);
        if (typeof input === 'string' && isHex) {
            return new Uint8Array(input.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        }

        // Otherwise, assume it's a regular string and encode it using TextEncoder
        return new TextEncoder().encode(input);
    }

    /**
     * Perform blind evaluation and return both the blinded data and evaluation request.
     * 
     * @param {string|Uint8Array} input - The input for which the blind evaluation will be performed.
     * @returns {Object} - Contains `finData` (the blind data) and `serializedEvalReq` (the serialized evaluation request).
     */
    async performBlindEvaluation(input) {
        const inputBytes = this.encodeInput(input);

        // Perform blind evaluation
        const [finData, evalReq] = await this.client.blind([inputBytes]);

        // Serialize the evaluation request
        const serializedEvalReq = evalReq.serialize();

        return { finData, serializedEvalReq };
    }

    /**
     * Deserialize the evaluation response received from the server.
     * 
     * @param {Uint8Array} responseData - The raw data received from the server.
     * @returns {Evaluation} - The deserialized evaluation object.
     */
    deserializeEvaluation(responseData) {
        return Evaluation.deserialize(this.suite, responseData);
    }

    /**
     * Finalize the OPRF process by combining the blind data with the deserialized evaluation.
     * 
     * @param {Uint8Array} finData - The blinded input data.
     * @param {Evaluation} deserializedEvaluation - The evaluation object received from the server.
     * @returns {Uint8Array} - The finalized output from the OPRF process.
     */
    async finalizeEvaluation(finData, deserializedEvaluation) {
        const [output] = await this.client.finalize(finData, deserializedEvaluation);
        return output;
    }
}

module.exports = OPRFClientHandler;
