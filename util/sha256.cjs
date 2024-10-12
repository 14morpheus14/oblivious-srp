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

// Import necessary modules
const crypto = require('crypto');
const TypeSRP = require('./type-srp.cjs');

// Define the Sha256 class
class Sha256 {
  constructor() {}

  // Method to handle sha256 hashing with variable arguments
  hash(...args) {
    const h = crypto.createHash('sha256');

    for (const arg of args) {
      if (arg instanceof TypeSRP) {
        h.update(Buffer.from(arg.toHex(), 'hex'));
      } else if (typeof arg === 'string') {
        h.update(arg);
      } else {
        throw new TypeError('Expected string or TypeSRP');
      }
    }

    return TypeSRP.fromHex(h.digest('hex'));
  }
}

// Default export the sha256 instance
module.exports = new Sha256().hash.bind(new Sha256());
