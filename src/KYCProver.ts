import { ethers } from 'ethers';
import fs from 'fs';
import path from 'path';
import * as snarkjs from 'snarkjs';
import * as ffjavascript from 'ffjavascript';
import { KYCCredential, KYCProof, KYCProofInput, KYCProverConfig } from "./types";
import { safeLogger } from './utils/logger';
import { safeKeccak256, verifyEd25519Signature, validateAttributeArray, credentialToBytes, MAX_PARAMETER_SIZES } from './utils/crypto';

/**
 * Handles the generation and verification of KYC-related zero-knowledge proofs
 * Implements safe parameter handling with proper bounds checking
 */
export class KYCProver {
  private config: KYCProverConfig;

  constructor(config: KYCProverConfig) {
    this.config = config;
    this.validateConfig();
  }

  /**
   * Generates a zero-knowledge proof for a KYC credential
   * Only reveals the specified attributes while keeping others private
   * Implements safe parameter handling and proper error management
   */
  async generateProof(
    credential: KYCCredential,
    attributesToReveal: string[] = [],
    viewingKey: bigint
  ): Promise<KYCProof> {
    try {
      // Validate credential first
      const isCredentialValid = await this.verifyCredential(credential);
      if (!isCredentialValid) {
        safeLogger.warn('Attempted to generate proof for invalid credential', {
          credentialId: credential.id,
          issuer: credential.issuer
        });
        // Return empty proof structure instead of throwing
        return this.createEmptyProof();
      }

      // Validate attributesToReveal - apply bounds checking and validation
      const validatedAttributes = validateAttributeArray(attributesToReveal);
      
      // Create a witness input for the circuit
      const input = this.prepareCircuitInput(credential, validatedAttributes, viewingKey);
      
      // Check if the circuit files exist
      if (!this.ensureFilesExist([this.config.circuitPath, this.config.provingKeyPath])) {
        safeLogger.error('Required circuit files not found');
        return this.createEmptyProof();
      }
      
      // Generate actual proof using snarkjs with real circuit and inputs
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        this.config.circuitPath,
        this.config.provingKeyPath
      );
      
      // Extract revealed attributes to include in the proof output
      const revealedAttributes: {[key: string]: any} = {};
      validatedAttributes.forEach(attr => {
        if (credential.attributes[attr] !== undefined) {
          // Apply size bounds check on attribute values
          const value = credential.attributes[attr];
          if (typeof value === 'string' && value.length > MAX_PARAMETER_SIZES.ATTRIBUTE_VALUE_SIZE) {
            // Truncate oversized values
            revealedAttributes[attr] = value.substring(0, MAX_PARAMETER_SIZES.ATTRIBUTE_VALUE_SIZE);
            safeLogger.warn(`Truncated oversized attribute value: ${attr}`);
          } else {
            revealedAttributes[attr] = value;
          }
        }
      });

      safeLogger.info('Generated ZK proof successfully', {
        credentialId: credential.id,
        numRevealedAttributes: Object.keys(revealedAttributes).length
      });

      return {
        proof,
        publicSignals,
        revealedAttributes
      };
    } catch (error) {
      safeLogger.error('Error generating KYC proof', { error });
      // Return empty proof instead of throwing, for safe parameter handling
      return this.createEmptyProof();
    }
  }

  /**
   * Creates an empty proof structure for error cases
   * Following the safe parameter handling practice of returning empty/default values
   */
  private createEmptyProof(): KYCProof {
    return {
      proof: {},
      publicSignals: [],
      revealedAttributes: {}
    };
  }

  /**
   * Verifies a KYC credential by checking the issuer's signature
   * Without generating a zero-knowledge proof
   * Implements safe parameter handling with proper validation
   */
  async verifyCredential(credential: KYCCredential): Promise<boolean> {
    try {
      // Parameter validation
      if (!credential || typeof credential !== 'object') {
        safeLogger.warn('Invalid credential format');
        return false;
      }

      // Get the issuer's public key with proper bounds checking
      const issuerPublicKey = this.config.issuerPublicKeys[credential.issuer];
      if (!issuerPublicKey) {
        safeLogger.warn(`Unknown issuer: ${credential.issuer}`);
        return false;
      }

      // Check if the credential has expired
      if (credential.expiresAt && new Date(credential.expiresAt) < new Date()) {
        safeLogger.warn("Credential has expired");
        return false;
      }

      // Verify the proof on the credential using our real crypto utilities
      const message = this.hashCredentialForVerification(credential);
      
      // Use the appropriate signature verification algorithm based on proof type
      const isSignatureValid = await this.verifyIssuerSignature(
        message,
        credential.proof.proofValue,
        issuerPublicKey,
        credential.proof.type
      );

      if (!isSignatureValid) {
        safeLogger.warn('Invalid credential signature', {
          credentialId: credential.id,
          issuer: credential.issuer
        });
      }

      return isSignatureValid;
    } catch (error) {
      safeLogger.error("Error verifying credential", { error });
      return false; // Safe return value for error case
    }
  }

  /**
   * Verifies a zero-knowledge proof for KYC credential
   * Using real Groth16 verification
   */
  async verifyProof(proof: any, publicSignals: any): Promise<boolean> {
    try {
      // Parameter validation with bounds checking
      if (!proof || !publicSignals) {
        safeLogger.warn('Missing proof or publicSignals in verifyProof');
        return false;
      }

      // Ensure the verification key file exists
      if (!this.ensureFilesExist([this.config.verificationKeyPath])) {
        safeLogger.error('Verification key file not found');
        return false;
      }
      
      // Load verification key with proper error handling
      let verificationKey: any;
      try {
        const verificationKeyContent = fs.readFileSync(this.config.verificationKeyPath, "utf-8");
        if (verificationKeyContent.length > MAX_PARAMETER_SIZES.CREDENTIAL_SIZE) {
          safeLogger.warn(`Verification key file too large: ${verificationKeyContent.length} bytes`);
          return false;
        }
        verificationKey = JSON.parse(verificationKeyContent);
      } catch (readError) {
        safeLogger.error('Error reading verification key file', { error: readError });
        return false;
      }
      
      // Verify the proof using the real snarkjs implementation
      const isValid = await snarkjs.groth16.verify(
        verificationKey,
        publicSignals,
        proof
      );
      
      safeLogger.debug('ZK proof verification result', { isValid });
      return isValid;
    } catch (error) {
      safeLogger.error("Error verifying KYC proof", { error });
      return false; // Safe error handling
    }
  }

  /**
   * Creates a hash of credential data for verification
   * Using safe parameter handling and real cryptography
   */
  private hashCredentialForVerification(credential: KYCCredential): string {
    try {
      // Create a deterministic representation of the credential without the proof
      const { proof, ...credentialWithoutProof } = credential;
      
      // Use our safe credentialToBytes utility to create a deterministic binary representation
      const credentialBytes = credentialToBytes(credentialWithoutProof);
      
      // Use our safeKeccak256 utility which includes parameter validation
      return safeKeccak256(credentialBytes);
    } catch (error) {
      safeLogger.error('Error hashing credential for verification', { error });
      return ethers.constants.HashZero; // Return a safe default on error
    }
  }

  /**
   * Verifies the issuer's signature on a credential using real cryptography
   * Implements safe parameter handling and multiple signature types
   */
  private async verifyIssuerSignature(
    message: string,
    signature: string,
    publicKey: string,
    proofType: string
  ): Promise<boolean> {
    try {
      // Parameter validation
      if (!message || !signature || !publicKey || !proofType) {
        safeLogger.warn('Missing parameters for signature verification');
        return false;
      }
      
      // For Ed25519Signature2020 - use our real implementation
      if (proofType === "Ed25519Signature2020") {
        safeLogger.debug("Verifying Ed25519 signature");
        return await verifyEd25519Signature(message, signature, publicKey);
      }
      
      // For EcdsaSecp256k1Signature2019
      if (proofType === "EcdsaSecp256k1Signature2019") {
        safeLogger.debug("Verifying ECDSA signature");
        
        // Convert message to a hash if it's not already one
        const messageHash = message.startsWith('0x') ? message : safeKeccak256(message);
        
        try {
          // Use ethers.js to recover the signing address and compare with public key
          const messageBytes = ethers.utils.arrayify(messageHash);
          const recoveredAddress = ethers.utils.recoverAddress(messageBytes, signature);
          
          // Compare the recovered address with the expected public key
          // Convert both to checksummed addresses for comparison
          const expectedAddress = ethers.utils.getAddress(publicKey);
          const actualAddress = ethers.utils.getAddress(recoveredAddress);
          
          return expectedAddress === actualAddress;
        } catch (cryptoError) {
          safeLogger.error('Error in ECDSA verification', { error: cryptoError });
          return false;
        }
      }
      
      safeLogger.warn(`Unsupported proof type: ${proofType}`);
      return false; // Unknown proof type
    } catch (error) {
      safeLogger.error('Error verifying signature', { error });
      return false; // Safe error handling
    }
  }

  /**
   * Prepares the input for the zk-SNARK circuit
   */
  private prepareCircuitInput(
    credential: KYCCredential,
    attributesToReveal: string[],
    viewingKey: bigint
  ): KYCProofInput {
    // Create input object for the circuit
    return {
      credential,
      revealedAttributes: attributesToReveal,
      viewingKey
    };
  }

  /**
   * Validates the configuration for the KYC prover
   */
  private validateConfig(): void {
    // Check if at least one issuer public key is provided
    if (!this.config.issuerPublicKeys || 
        Object.keys(this.config.issuerPublicKeys).length === 0) {
      throw new Error("No issuer public keys configured");
    }
  }

  /**
   * Ensures all required files exist
   * Returns true if all files exist, false otherwise
   */
  private ensureFilesExist(filePaths: string[]): boolean {
    try {
      for (const filePath of filePaths) {
        if (!fs.existsSync(filePath)) {
          safeLogger.error(`Required file not found: ${filePath}`);
          return false;
        }
      }
      return true;
    } catch (error) {
      safeLogger.error('Error checking file existence', { error });
      return false;
    }
  }
}
