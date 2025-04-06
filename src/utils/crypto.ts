import * as ed25519 from '@noble/ed25519';
import { ethers } from 'ethers';
import { safeLogger } from './logger';
import * as crypto from 'crypto';

/**
 * Maximum allowed parameter sizes to prevent unreasonable memory usage
 */
export const MAX_PARAMETER_SIZES = {
  CREDENTIAL_SIZE: 10 * 1024, // 10KB max credential size
  ATTRIBUTE_ARRAY_LENGTH: 1024, // Maximum number of attributes
  ATTRIBUTE_NAME_LENGTH: 256, // Maximum attribute name length
  ATTRIBUTE_VALUE_SIZE: 1024, // Maximum size for attribute values
  CREDENTIAL_ID: 256, // Maximum length for credential IDs
  MAX_RESULTS: 100, // Maximum number of results to return in listings
  // Encryption constants
  SALT_LENGTH: 16,
  IV_LENGTH: 16,
  KEY_LENGTH: 32, // 256 bits
  CIPHER_ALGORITHM: 'aes-256-cbc' // AES-256 in CBC mode
};

/**
 * Safely hash a string using keccak256
 * Implements parameter validation and bounds checking
 */
export function safeKeccak256(data: string | Uint8Array): string {
  try {
    // Validate input
    if (!data) {
      safeLogger.warn('safeKeccak256 called with empty data');
      return ethers.constants.HashZero; // Return a safe default
    }

    // Check data length if it's a string
    if (typeof data === 'string' && data.length > MAX_PARAMETER_SIZES.CREDENTIAL_SIZE) {
      safeLogger.warn(`safeKeccak256 called with oversized data: ${data.length} bytes`);
      // Truncate to safe size rather than failing
      data = data.substring(0, MAX_PARAMETER_SIZES.CREDENTIAL_SIZE);
    }

    // Check data length if it's a Uint8Array
    if (data instanceof Uint8Array && data.length > MAX_PARAMETER_SIZES.CREDENTIAL_SIZE) {
      safeLogger.warn(`safeKeccak256 called with oversized Uint8Array: ${data.length} bytes`);
      // Truncate to safe size
      const safeSized = new Uint8Array(MAX_PARAMETER_SIZES.CREDENTIAL_SIZE);
      safeSized.set(data.slice(0, MAX_PARAMETER_SIZES.CREDENTIAL_SIZE));
      data = safeSized;
    }

    // Convert string to bytes if needed
    const dataBytes = typeof data === 'string' 
      ? ethers.utils.toUtf8Bytes(data) 
      : data;

    // Calculate hash
    return ethers.utils.keccak256(dataBytes);
  } catch (error) {
    safeLogger.error('Error in safeKeccak256', { error });
    return ethers.constants.HashZero; // Return a safe default on error
  }
}

/**
 * Safely verify an Ed25519 signature
 * Includes parameter validation and bounds checking
 */
export async function verifyEd25519Signature(
  message: string | Uint8Array,
  signature: string | Uint8Array,
  publicKey: string | Uint8Array
): Promise<boolean> {
  try {
    // Validate and sanitize inputs
    if (!message || !signature || !publicKey) {
      safeLogger.warn('verifyEd25519Signature called with missing parameters');
      return false;
    }

    // Convert and normalize all parameters to Uint8Array
    const messageBytes = typeof message === 'string'
      ? ethers.utils.toUtf8Bytes(message)
      : message;
    
    const signatureBytes = typeof signature === 'string'
      ? ethers.utils.arrayify(signature.startsWith('0x') ? signature : `0x${signature}`)
      : signature;
    
    const publicKeyBytes = typeof publicKey === 'string'
      ? ethers.utils.arrayify(publicKey.startsWith('0x') ? publicKey : `0x${publicKey}`)
      : publicKey;

    // Validate signature and public key sizes
    if (signatureBytes.length !== 64) {
      safeLogger.warn(`Invalid Ed25519 signature length: ${signatureBytes.length} bytes`);
      return false;
    }

    if (publicKeyBytes.length !== 32) {
      safeLogger.warn(`Invalid Ed25519 public key length: ${publicKeyBytes.length} bytes`);
      return false;
    }

    // Verify the signature
    return await ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
  } catch (error) {
    safeLogger.error('Error in verifyEd25519Signature', { error });
    return false; // Return a safe default on error
  }
}

/**
 * Safely validates an attribute array
 * Ensures it's within reasonable size limits
 */
export function validateAttributeArray(attributes: string[]): string[] {
  if (!Array.isArray(attributes)) {
    safeLogger.warn('validateAttributeArray called with non-array input');
    return [];
  }

  // Limit the number of attributes to prevent DoS
  if (attributes.length > MAX_PARAMETER_SIZES.ATTRIBUTE_ARRAY_LENGTH) {
    safeLogger.warn(`Attribute array exceeds maximum size: ${attributes.length}`);
    // Return a truncated array instead of throwing
    return attributes.slice(0, MAX_PARAMETER_SIZES.ATTRIBUTE_ARRAY_LENGTH);
  }

  // Validate individual attribute names
  return attributes.filter(attr => {
    if (typeof attr !== 'string') {
      safeLogger.warn(`Invalid attribute type: ${typeof attr}`);
      return false;
    }
    
    if (attr.length > MAX_PARAMETER_SIZES.ATTRIBUTE_NAME_LENGTH) {
      safeLogger.warn(`Attribute name too long: ${attr.length} chars`);
      return false;
    }
    
    return true;
  });
}

/**
 * Generate a deterministic bytes representation of a credential
 * with parameter validation and safety checks
 */
export function credentialToBytes(
  credential: any, 
  includeProof: boolean = false
): Uint8Array {
  try {
    if (!credential || typeof credential !== 'object') {
      safeLogger.warn('credentialToBytes called with invalid credential');
      return new Uint8Array();
    }

    // Create a copy with or without proof
    const credentialCopy = {...credential};
    if (!includeProof) {
      delete credentialCopy.proof;
    }

    // Convert to a deterministic string representation
    const credentialString = JSON.stringify(
      credentialCopy,
      // Sort keys for deterministic representation
      (_, value) => {
        if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
          // Add proper index signature to the result object
          return Object.keys(value).sort().reduce<{[key: string]: any}>((result, key) => {
            result[key] = value[key];
            return result;
          }, {});
        }
        return value;
      }
    );

    // Check string length for safety
    if (credentialString.length > MAX_PARAMETER_SIZES.CREDENTIAL_SIZE) {
      safeLogger.warn(`Credential string too large: ${credentialString.length} bytes`);
      // Return a truncated version instead of failing
      return ethers.utils.toUtf8Bytes(
        credentialString.substring(0, MAX_PARAMETER_SIZES.CREDENTIAL_SIZE)
      );
    }

    return ethers.utils.toUtf8Bytes(credentialString);
  } catch (error) {
    safeLogger.error('Error in credentialToBytes', { error });
    return new Uint8Array(); // Return empty array on error
  }
}

/**
 * Encrypt data with a password using AES-256-CBC
 * Implements secure parameter handling with proper validation and error handling
 * @param data String data to encrypt
 * @param password Password to derive encryption key from
 * @returns Encrypted data as a string (format: salt.iv.encrypted_data)
 */
export async function encryptWithPassword(data: string, password: string): Promise<string> {
  try {
    // Validate inputs with safe parameter handling
    if (!data) {
      safeLogger.warn('encryptWithPassword called with empty data');
      return '';
    }
    
    if (!password || typeof password !== 'string') {
      safeLogger.error('encryptWithPassword called with invalid password');
      return '';
    }
    
    // Apply bounds checking
    if (data.length > MAX_PARAMETER_SIZES.CREDENTIAL_SIZE) {
      safeLogger.warn(`Attempting to encrypt oversized data: ${data.length} bytes`);
      data = data.substring(0, MAX_PARAMETER_SIZES.CREDENTIAL_SIZE);
    }
    
    // Generate a random salt for key derivation
    const salt = crypto.randomBytes(MAX_PARAMETER_SIZES.SALT_LENGTH);
    
    // Generate a random initialization vector
    const iv = crypto.randomBytes(MAX_PARAMETER_SIZES.IV_LENGTH);
    
    // Derive key from password and salt using PBKDF2
    const key = crypto.pbkdf2Sync(
      password,
      salt,
      10000, // Number of iterations
      MAX_PARAMETER_SIZES.KEY_LENGTH,
      'sha256'
    );
    
    // Create cipher with key and IV
    const cipher = crypto.createCipheriv(
      MAX_PARAMETER_SIZES.CIPHER_ALGORITHM,
      key,
      iv
    );
    
    // Encrypt the data
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Return salt, IV, and encrypted data as a single string
    return `${salt.toString('hex')}.${iv.toString('hex')}.${encrypted}`;
  } catch (error) {
    safeLogger.error('Error in encryptWithPassword', { error });
    return '';
  }
}

/**
 * Decrypt data that was encrypted with encryptWithPassword
 * Implements secure parameter handling with proper validation and error handling
 * @param encryptedData Encrypted data string (format: salt.iv.encrypted_data)
 * @param password Password used for encryption
 * @returns Decrypted data as a string or empty string on error
 */
export async function decryptWithPassword(encryptedData: string, password: string): Promise<string> {
  try {
    // Validate inputs with safe parameter handling
    if (!encryptedData || typeof encryptedData !== 'string') {
      safeLogger.warn('decryptWithPassword called with invalid encrypted data');
      return '';
    }
    
    if (!password || typeof password !== 'string') {
      safeLogger.error('decryptWithPassword called with invalid password');
      return '';
    }
    
    // Split the encrypted data into its components
    const parts = encryptedData.split('.');
    if (parts.length !== 3) {
      safeLogger.warn('decryptWithPassword: Invalid encrypted data format');
      return '';
    }
    
    const [saltHex, ivHex, encrypted] = parts;
    
    // Convert hex strings back to buffers
    const salt = Buffer.from(saltHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    
    // Validate component lengths
    if (salt.length !== MAX_PARAMETER_SIZES.SALT_LENGTH || 
        iv.length !== MAX_PARAMETER_SIZES.IV_LENGTH) {
      safeLogger.warn('decryptWithPassword: Invalid salt or IV length');
      return '';
    }
    
    // Derive the same key from the password and salt
    const key = crypto.pbkdf2Sync(
      password,
      salt,
      10000, // Same number of iterations as encryption
      MAX_PARAMETER_SIZES.KEY_LENGTH,
      'sha256'
    );
    
    // Create decipher with key and IV
    const decipher = crypto.createDecipheriv(
      MAX_PARAMETER_SIZES.CIPHER_ALGORITHM,
      key,
      iv
    );
    
    // Decrypt the data
    try {
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (decryptError) {
      safeLogger.warn('decryptWithPassword: Decryption failed, possibly wrong password', {
        error: decryptError
      });
      return '';
    }
  } catch (error) {
    safeLogger.error('Error in decryptWithPassword', { error });
    return '';
  }
}
