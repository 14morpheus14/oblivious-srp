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
const { EvaluationRequest, Oprf, OPRFServer: VoprfServer } = require('@cloudflare/voprf-ts');

// Define the OPRFServerHandler class, which handles OPRF server operations
class OPRFServerHandler {
    /**
     * Constructor to initialize the OPRF server handler.
     * @param {Uint8Array} privateKey - The private key for the OPRF server.
     */
    constructor(privateKey) {
        // Define the cryptographic suite to be used, in this case P-256 curve with SHA-256 hash.
        this.suite = Oprf.Suite.P256_SHA256;

        // Initialize the OPRF server using the specified suite and the private key provided.
        this.server = new VoprfServer(this.suite, privateKey);
    }

    /**
     * Deserialize the client's evaluation request.
     * Converts a serialized evaluation request (Uint8Array) back into an `EvaluationRequest` object.
     * 
     * @param {Uint8Array} serializedEvalReq - The serialized evaluation request from the client.
     * @returns {EvaluationRequest} - The deserialized evaluation request object.
     */
    deserializeEvaluationRequest(serializedEvalReq) {
        // The `deserialize` method is used to convert the serialized request into an EvaluationRequest object
        // based on the cryptographic suite defined earlier (P256_SHA256 in this case).
        return EvaluationRequest.deserialize(this.suite, serializedEvalReq);
    }

    /**
     * Serialize the evaluation response to be sent back to the client.
     * Converts an evaluation response object into a format that can be sent (Uint8Array).
     * 
     * @param {Evaluation} evaluation - The evaluation object containing the result of the OPRF operation.
     * @returns {Uint8Array} - The serialized evaluation response, ready to send to the client.
     */
    serializeEvaluationResponse(evaluation) {
        // The `serialize` method is used to convert the evaluation result into a Uint8Array format
        // that can be easily transmitted over a network back to the client.
        return evaluation.serialize();
    }

    /**
     * Perform a blind evaluation of the client's request.
     * This evaluates the client's blinded input in a way that the server doesn't learn the input,
     * while still producing a valid response that the client can later unblind.
     * 
     * @param {EvaluationRequest} evalReq - The deserialized evaluation request from the client.
     * @returns {Evaluation} - The evaluation result that the server generates.
     */
    async performBlindEvaluate(evalReq) {
        // Use the OPRF server to perform a "blind evaluation" on the client's request.
        // The `blindEvaluate` function allows the server to evaluate the client's input without seeing the actual data.
        // The result is an `Evaluation` object.
        return await this.server.blindEvaluate(evalReq);
    }
}

// Export the OPRFServerHandler class for use in other modules.
// This allows the class to be instantiated and used to handle OPRF operations.
module.exports = OPRFServerHandler;
