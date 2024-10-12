/* 
 * Oblivious SRP Library
 *
 * Copyright (c) 2024 Yamya Reiki <reiki.yamya14@gmail.com>
 *
 * This file is part of the Oblivious SRP Library.
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

const padStart = require('pad-start');
const randomHex = require('crypto-random-hex');
const { BigInteger } = require('jsbn');

const kBigInteger = Symbol('big-integer');
const kHexLength = Symbol('hex-length');

/**
 * Class representing an SRP (Secure Remote Password) type integer data with additional utility methods.
 */
class TypeSRP {
  /**
   * Constructs an TypeSRP.
   * 
   * @param {BigInteger} bigInteger - A `BigInteger` representing the numeric value.
   * @param {number} hexLength - The length of the integer in hexadecimal format.
   */
  constructor(bigInteger, hexLength) {
    this[kBigInteger] = bigInteger;
    this[kHexLength] = hexLength;
  }

  /**
   * Adds another TypeSRP to the current value.
   * 
   * @param {TypeSRP} val - The TypeSRP to add.
   * @returns {TypeSRP} - A new TypeSRP representing the sum.
   */
  add(val) {
    return new TypeSRP(this[kBigInteger].add(val[kBigInteger]), null);
  }

  /**
   * Checks if the current TypeSRP is equal to another.
   * 
   * @param {TypeSRP} val - The TypeSRP to compare.
   * @returns {boolean} - True if equal, otherwise false.
   */
  equals(val) {
    return this[kBigInteger].equals(val[kBigInteger]);
  }

  /**
   * Multiplies the current TypeSRP by another.
   * 
   * @param {TypeSRP} val - The TypeSRP to multiply.
   * @returns {TypeSRP} - A new TypeSRP representing the product.
   */
  multiply(val) {
    return TypeSRP.fromBigInt(this.toBigInt() * val.toBigInt());
  }

  /**
   * Divides the current TypeSRP by another.
   * 
   * @param {TypeSRP} val - The TypeSRP divisor.
   * @returns {TypeSRP} - A new TypeSRP representing the quotient.
   */
  divide(val) {
    return new TypeSRP(this[kBigInteger].divide(val[kBigInteger]), this[kHexLength]);
  }

  /**
   * Performs modular exponentiation: (base^exponent) mod m.
   * 
   * @param {TypeSRP|BigInt} exponent - The exponent to raise the base to.
   * @param {TypeSRP|BigInt} m - The modulus.
   * @returns {TypeSRP} - The result of modular exponentiation.
   */
  modPow(exponent, m) {
    const expBigInt = exponent instanceof TypeSRP ? exponent.toBigInt() : BigInt(exponent);
    const modBigInt = m instanceof TypeSRP ? m.toBigInt() : BigInt(m);
  
    return TypeSRP.fromBigInt(this.modularExponentiation(this.toBigInt(), expBigInt, modBigInt));
  }

  /**
   * Computes the current TypeSRP modulo m.
   * 
   * @param {TypeSRP} m - The modulus.
   * @returns {TypeSRP} - A new TypeSRP representing the result of the mod operation.
   */
  mod(m) {
    return new TypeSRP(this[kBigInteger].mod(m[kBigInteger]), m[kHexLength]);
  }

  /**
   * Subtracts another TypeSRP from the current one.
   * 
   * @param {TypeSRP} val - The TypeSRP to subtract.
   * @returns {TypeSRP} - A new TypeSRP representing the difference.
   */
  subtract(val) {
    return new TypeSRP(this[kBigInteger].subtract(val[kBigInteger]), this[kHexLength]);
  }

  /**
   * Performs a bitwise XOR operation with another TypeSRP.
   * 
   * @param {TypeSRP} val - The TypeSRP to XOR with.
   * @returns {TypeSRP} - A new TypeSRP resulting from the XOR operation.
   */
  xor(val) {
    return new TypeSRP(this[kBigInteger].xor(val[kBigInteger]), this[kHexLength]);
  }

  /**
   * Converts the TypeSRP to a decimal string representation.
   * 
   * @returns {string} - The decimal string representation of the TypeSRP.
   */
  toDecimal() {
    return this[kBigInteger].toString(10);
  }

  /**
   * Converts the TypeSRP to a BigInt.
   * 
   * @returns {BigInt} - The BigInt representation of the TypeSRP.
   */
  toBigInt() {
    return BigInt(this[kBigInteger].toString(10));
  }

  /**
   * Inspects the TypeSRP, providing a brief hexadecimal preview.
   * 
   * @returns {string} - A string representation of the TypeSRP for inspection.
   */
  inspect() {
    const hex = this[kBigInteger].toString(16);
    return `<TypeSRP ${hex.slice(0, 16)}${hex.length > 16 ? '...' : ''}>`;
  }

  /**
   * Converts the TypeSRP to a hexadecimal string representation with optional padding.
   * 
   * @returns {string} - The hexadecimal string representation of the TypeSRP.
   */
  toHex() {
    const hex = this[kBigInteger].toString(16);
    
    // If hex length is not specified, return the hex string without padding
    if (this[kHexLength] === null) {
      return hex;
    }

    // Otherwise, pad the hex string to the specified length
    return padStart(hex, this[kHexLength], '0');
  }

  /**
   * Gets the hex length of the TypeSRP.
   * 
   * @returns {number} - The hex length of the TypeSRP.
   */
  getHexLength() {
    return this[kHexLength];
  }

  /**
   * Checks if the current TypeSRP is greater than another.
   * 
   * @param {TypeSRP} val - The TypeSRP to compare.
   * @returns {boolean} - True if greater, otherwise false.
   */
  isGreaterThan(val) {
    return this[kBigInteger].compareTo(val[kBigInteger]) > 0;
  }

  /**
   * Checks if the current TypeSRP is less than another.
   * 
   * @param {TypeSRP} val - The TypeSRP to compare.
   * @returns {boolean} - True if less, otherwise false.
   */
  isLessThan(val) {
    return this[kBigInteger].compareTo(val[kBigInteger]) < 0;
  }

    /**
   * Computes the greatest common divisor (GCD) of two BigIntegers.
   * 
   * @param {BigInt} a - The first number.
   * @param {BigInt} b - The second number.
   * @returns {BigInt} - The GCD of a and b.
   */
  gcd(a, b) {
    while (b !== BigInt(0)) {
      [a, b] = [b, a % b];
    }
    return a;
  }

  /**
   * Computes the modular inverse of the current TypeSRP modulo m using Fermat's Little Theorem,
   * but only if the gcd of this and m is 1.
   * 
   * @param {TypeSRP} m - The modulus.
   * @returns {TypeSRP} - A new TypeSRP representing the modular inverse, or throws an error if no inverse exists.
   */
  modInverse(m) {
    const aBigInt = this.toBigInt();
    const mBigInt = m.toBigInt();

    // Check if gcd(a, m) is 1
    if (this.gcd(aBigInt, mBigInt) !== BigInt(1)) {
      throw new Error('Modular inverse does not exist: gcd(a, m) is not 1');
    }

    return TypeSRP.fromBigInt(this.modularExponentiation(aBigInt, mBigInt - BigInt(2), mBigInt));
  }


  /**
   * Efficient modular exponentiation by squaring.
   * 
   * @param {BigInt} base - The base of the exponentiation.
   * @param {BigInt} exp - The exponent.
   * @param {BigInt} mod - The modulus.
   * @returns {BigInt} - The result of (base^exp) mod mod.
   */
  modularExponentiation(base, exp, mod) {
    let result = BigInt(1);
    base = base % mod;

    while (exp > 0) {
      if (exp % BigInt(2) === 1n) {
        result = (result * base) % mod;
      }
      exp = exp / BigInt(2);
      base = (base * base) % mod;
    }

    return result;
  }

  toNumber() {
    const bigIntValue = this.toBigInt();
    
    // Check if the BigInt value fits within JavaScript's safe integer range
    if (bigIntValue <= Number.MAX_SAFE_INTEGER && bigIntValue >= Number.MIN_SAFE_INTEGER) {
      // Convert to JavaScript Number
      return Number(bigIntValue);
    } else {
      throw new Error('TypeSRP value is too large to be safely converted to a JavaScript Number');
    }
  }

  /**
  * Converts the TypeSRP to a Uint8Array.
  * 
  * @returns {Uint8Array} - The Uint8Array representation of the TypeSRP.
  */
  toUint8Array() {
    // Convert the BigInteger to a hexadecimal string
    let hex = this[kBigInteger].toString(16);

    // If the hex string has an odd length, pad it with a leading zero
    if (hex.length % 2 !== 0) {
      hex = '0' + hex;
    }

    // Create a Uint8Array from the hex string
    const byteArray = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      byteArray[i / 2] = parseInt(hex.substr(i, 2), 16);
    }

    return byteArray;
  }
}

// Static methods to create TypeSRP instances.

/**
 * Creates an TypeSRP from a hexadecimal string.
 * 
 * @param {string} input - The hexadecimal string input.
 * @returns {TypeSRP} - A new TypeSRP created from the hexadecimal input.
 */
TypeSRP.fromHex = function(input) {
  return new TypeSRP(new BigInteger(input, 16), input.length);
};

/**
 * Generates a random TypeSRP of a specified byte length.
 * 
 * @param {number} bytes - The number of bytes for the random integer.
 * @returns {TypeSRP} - A new TypeSRP representing the random value.
 */
TypeSRP.randomInteger = function(bytes) {
  return TypeSRP.fromHex(randomHex(bytes));
};

/** 
 * Static method to create TypeSRP from BigInt
 * */ 
TypeSRP.fromBigInt = function(bigInt) {
  // Convert BigInt to a BigInteger from the 'jsbn' library
  return new TypeSRP(new BigInteger(bigInt.toString()), null);
};

// Constants for zero and one TypeSRP instances.
TypeSRP.ZERO = new TypeSRP(new BigInteger('0'), null);
TypeSRP.ONE = new TypeSRP(new BigInteger('1'), null);

module.exports = TypeSRP;
