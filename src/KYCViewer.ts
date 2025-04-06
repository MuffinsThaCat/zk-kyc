// Import our type definitions
import { ethers } from 'ethers';
import { NocturneViewer, ViewingKey, CanonAddress, StealthAddress } from "./nocturne-types";
import { KYCCredential, VerificationStatus } from "./types";
// Use explicit path to resolve issue with module resolution
import { KYCProver } from "./KYCProver.js";
// Import our secure utilities
import { safeLogger } from './utils/logger';
import { validateAttributeArray, MAX_PARAMETER_SIZES } from './utils/crypto';
// Import the new secure credential storage
import { CredentialStorage } from './storage/CredentialStorage';

/**
 * Implementation of a KYC-enabled viewer that implements the NocturneViewer interface
 * while adding KYC verification capabilities
 */
export class KYCViewer implements NocturneViewer {
  // NocturneViewer interface properties
  public vk: ViewingKey; 
  public vkNonce: bigint;
  
  // KYC-specific properties
  private kycCredential: KYCCredential | null = null; // Current active credential
  private credentialStorage: CredentialStorage; // Secure storage for multiple credentials
  public kycProver: KYCProver;
  private verificationStatus: VerificationStatus = VerificationStatus.UNVERIFIED;
  private activeCredentialId: string | null = null; // Track which credential is currently active
  
  // Keep track of canonical address for performance
  private _canonicalAddress: CanonAddress | null = null;

  constructor(vk: ViewingKey, vkNonce: bigint, kycProver: KYCProver) {
    this.vk = vk;
    this.vkNonce = vkNonce;
    this.kycProver = kycProver;
    this.kycCredential = null;
    this.activeCredentialId = null;
    this.verificationStatus = VerificationStatus.UNVERIFIED;
    
    // Initialize the credential storage with viewing key
    // Convert the ViewingKey to a string for secure credential storage
    // ViewingKey extends BigInt, so we need to convert it properly
    const viewingKeyString = vk.toString(16); // Convert BigInt to hex string
    
    // Ensure the hex string is at least 32 chars (16 bytes) for security
    // This follows our safe parameter handling principles
    const secureViewingKey = viewingKeyString.padStart(32, '0');
    
    // Add prefix for better identification in logs (filtered to avoid leaking the actual key)
    this.credentialStorage = new CredentialStorage(`secure_vk_${secureViewingKey.substring(0, 4)}...`);
    
    safeLogger.info('Initialized KYCViewer with secure credential storage');
  }
  
  // Implement NocturneViewer interface methods
  canonicalAddress(): CanonAddress {
    if (this._canonicalAddress) {
      return this._canonicalAddress;
    }
    
    // In a real implementation, this would use BabyJubJub.BasePointExtended.multiply()
    // For our prototype, we'll create a simple placeholder
    this._canonicalAddress = {
      x: BigInt(123456789),
      y: BigInt(987654321)
    };
    return this._canonicalAddress;
  }
  
  canonicalStealthAddress(): StealthAddress {
    const canonAddr = this.canonicalAddress();
    // In a real implementation, this would use the BabyJubJub points
    return {
      h1X: BigInt(1),
      h1Y: BigInt(2),
      h2X: canonAddr.x,
      h2Y: canonAddr.y
    };
  }
  
  generateRandomStealthAddress(): StealthAddress {
    // In a real implementation, this would generate a proper stealth address
    // with random components using the randomFr() function
    return {
      h1X: BigInt(Math.floor(Math.random() * 1000000)),
      h1Y: BigInt(Math.floor(Math.random() * 1000000)),
      h2X: BigInt(Math.floor(Math.random() * 1000000)),
      h2Y: BigInt(Math.floor(Math.random() * 1000000))
    };
  }
  
  isOwnAddress(addr: StealthAddress): boolean {
    // In a real implementation, this would verify if a stealth address belongs
    // to this viewer by using the viewing key
    // For our prototype, we'll return true for demonstration
    return true;
  }

  /**
   * Sets a KYC credential for this viewer and validates it
   * Implements safe parameter handling and validation
   */
  async setKYCCredential(credential: KYCCredential): Promise<boolean> {
    try {
      // Validate the credential format first with safe parameter handling
      if (!credential || typeof credential !== 'object') {
        safeLogger.warn('Invalid credential format');
        this.verificationStatus = VerificationStatus.INVALID;
        return false;
      }
      
      // Apply bounds checking to credential fields
      if (!credential.id || !credential.issuer || !credential.subject ||
          credential.id.length > MAX_PARAMETER_SIZES.CREDENTIAL_ID) {
        safeLogger.warn('Invalid credential fields or size');
        this.verificationStatus = VerificationStatus.INVALID;
        return false;
      }

      // Check that the credential has a valid signature
      safeLogger.info('Verifying credential with KYCProver', {
        credentialId: credential.id,
        issuer: credential.issuer,
        service: 'zk-kyc-wallet'
      });
      
      const isValid = await this.kycProver.verifyCredential(credential);
      if (!isValid) {
        safeLogger.warn('Credential verification failed', {
          credentialId: credential.id
        });
        this.verificationStatus = VerificationStatus.INVALID;
        return false;
      }
      
      // Store the credential securely
      const stored = await this.credentialStorage.storeCredential(credential);
      if (!stored) {
        safeLogger.error('Failed to store credential securely', {
          credentialId: credential.id
        });
        this.verificationStatus = VerificationStatus.ERROR;
        return false;
      }
      
      // Set this as the active credential
      this.kycCredential = credential;
      this.activeCredentialId = credential.id;
      this.verificationStatus = VerificationStatus.VERIFIED;
      
      safeLogger.info('KYC credential verification and storage completed', {
        credentialId: credential.id,
        issuer: credential.issuer,
        service: 'zk-kyc-wallet',
        status: 'VERIFIED'
      });
      
      return true;
    } catch (error) {
      safeLogger.error('Error setting KYC credential', { error });
      this.verificationStatus = VerificationStatus.ERROR;
      return false;
    }
  }

  /**
   * Generate a zero-knowledge proof for KYC verification
   * Reveals only the specified attributes from the KYC credential
   * @param attributesToReveal list of attribute names to include in the proof
   * @param credentialId optional ID of a specific credential to use (uses active credential if not specified)
   * @returns a KYC proof or null if generation fails
   */
  async generateKYCProof(attributesToReveal: string[] = [], credentialId?: string): Promise<any> {
    try {
      // Determine which credential to use
      let credential = this.kycCredential;
      
      // If a specific credential ID is provided, get it from secure storage
      if (credentialId) {
        // Apply bounds checking
        if (credentialId.length > MAX_PARAMETER_SIZES.CREDENTIAL_ID) {
          safeLogger.warn(`Credential ID exceeds maximum size: ${credentialId.length}`);
          return null;
        }
        
        // Retrieve from secure storage with safe parameter handling
        credential = await this.credentialStorage.getCredential(credentialId);
        if (!credential) {
          safeLogger.warn(`Credential ${credentialId} not found or expired`);
          return null;
        }
      }
      
      // Verify we have a valid credential
      if (!credential) {
        safeLogger.warn('No active KYC credential set');
        return null;
      }
      
      // Apply attributes list size bounds checking and validation
      const validatedAttributes = validateAttributeArray(attributesToReveal);
      if (validatedAttributes.length !== attributesToReveal.length) {
        safeLogger.warn('Some attributes were filtered due to validation');
      }
      
      // Log the operation with relevant but non-sensitive information
      safeLogger.info('Generating KYC proof', {
        attributeCount: validatedAttributes.length,
        credentialId: credential.id,
        service: 'zk-kyc-wallet'
      });
      const viewingKeyAsBigInt = BigInt(this.vk.toString());
      
      // Call our improved KYCProver implementation with proper null checking
      // At this point we've already verified credential is not null
      // but we'll add an assertion for TypeScript
      if (!credential) {
        safeLogger.error('Credential unexpectedly null after validation check');
        return { proof: {}, publicSignals: [], revealedAttributes: {} };
      }
      
      const proof = await this.kycProver.generateProof(
        credential, // Use the local credential variable that's been verified
        validatedAttributes,
        viewingKeyAsBigInt
      );
      
      safeLogger.debug('KYC proof generated successfully');
      return proof;
    } catch (error) {
      safeLogger.error('Error generating KYC proof', { error });
      // Return safe empty proof structure instead of throwing
      return { proof: {}, publicSignals: [], revealedAttributes: {} };
    }
  }

  /**
   * Get the verification status of the current KYC credential
   * @returns the current verification status
   */
  getVerificationStatus(): VerificationStatus {
    return this.verificationStatus;
  }
  
  /**
   * Get a list of all valid credential IDs stored securely
   * @returns Array of credential IDs
   */
  listCredentials(): string[] {
    try {
      // Get the list of credentials with safe parameter handling
      const credentialIds = this.credentialStorage.listCredentialIds();
      
      safeLogger.info(`Retrieved ${credentialIds.length} stored credentials`);
      return credentialIds;
    } catch (error) {
      safeLogger.error('Error listing credentials', { error });
      return [];
    }
  }
  
  /**
   * Retrieve a specific credential by ID from secure storage
   * @param credentialId ID of the credential to retrieve
   * @returns the credential or null if not found/invalid
   */
  async getCredential(credentialId: string): Promise<KYCCredential | null> {
    try {
      // Validate the credential ID with safe parameter handling
      if (!credentialId || typeof credentialId !== 'string' || 
          credentialId.length > MAX_PARAMETER_SIZES.CREDENTIAL_ID) {
        safeLogger.warn('Invalid credential ID requested');
        return null;
      }
      
      // Retrieve the credential with proper bounds checking
      const credential = await this.credentialStorage.getCredential(credentialId);
      
      if (!credential) {
        safeLogger.warn(`Credential ${credentialId} not found or expired`);
        return null;
      }
      
      safeLogger.info(`Retrieved credential ${credentialId}`);
      return credential;
    } catch (error) {
      safeLogger.error('Error retrieving credential', { error });
      return null;
    }
  }
  
  /**
   * Set a specific credential as the active credential by ID
   * @param credentialId ID of the credential to set as active
   * @returns true if successful, false otherwise
   */
  async setActiveCredential(credentialId: string): Promise<boolean> {
    try {
      // Apply bounds checking and validation
      if (!credentialId || typeof credentialId !== 'string' || 
          credentialId.length > MAX_PARAMETER_SIZES.CREDENTIAL_ID) {
        safeLogger.warn('Invalid credential ID for activation');
        return false;
      }
      
      // Retrieve the credential with safe parameter handling
      const credential = await this.credentialStorage.getCredential(credentialId);
      if (!credential) {
        safeLogger.warn(`Credential ${credentialId} not found or expired`);
        this.verificationStatus = VerificationStatus.INVALID;
        return false;
      }
      
      // Verify the credential is still valid
      const isValid = await this.kycProver.verifyCredential(credential);
      if (!isValid) {
        safeLogger.warn(`Credential ${credentialId} failed verification`);
        this.verificationStatus = VerificationStatus.INVALID;
        return false;
      }
      
      // Set it as the active credential
      this.kycCredential = credential;
      this.activeCredentialId = credentialId;
      this.verificationStatus = VerificationStatus.VERIFIED;
      
      safeLogger.info(`Set credential ${credentialId} as active`);
      return true;
    } catch (error) {
      safeLogger.error('Error setting active credential', { error });
      this.verificationStatus = VerificationStatus.ERROR;
      return false;
    }
  }
  
  /**
   * Remove a credential from secure storage
   * @param credentialId ID of the credential to remove
   * @returns true if successful, false otherwise
   */
  removeCredential(credentialId: string): boolean {
    try {
      // Apply safe parameter validation
      if (!credentialId || typeof credentialId !== 'string' || 
          credentialId.length > MAX_PARAMETER_SIZES.CREDENTIAL_ID) {
        safeLogger.warn('Invalid credential ID for removal');
        return false;
      }
      
      // Check if this is the active credential
      if (this.activeCredentialId === credentialId) {
        this.kycCredential = null;
        this.activeCredentialId = null;
        this.verificationStatus = VerificationStatus.UNVERIFIED;
      }
      
      // Remove from storage with proper error handling
      const removed = this.credentialStorage.removeCredential(credentialId);
      if (removed) {
        safeLogger.info(`Removed credential ${credentialId}`);
      } else {
        safeLogger.warn(`Failed to remove credential ${credentialId}`);
      }
      
      return removed;
    } catch (error) {
      safeLogger.error('Error removing credential', { error });
      return false;
    }
  }
  
  /**
   * Clean up expired credentials from storage
   * @returns Number of credentials removed
   */
  cleanupExpiredCredentials(): number {
    try {
      // Perform cleanup with proper bounds checking
      const removedCount = this.credentialStorage.cleanupExpiredCredentials();
      
      // If the active credential was removed, update state
      if (this.activeCredentialId && 
          !this.credentialStorage.isCredentialValid(this.activeCredentialId)) {
        this.kycCredential = null;
        this.activeCredentialId = null;
        this.verificationStatus = VerificationStatus.UNVERIFIED;
      }
      
      safeLogger.info(`Cleaned up ${removedCount} expired credentials`);
      return removedCount;
    } catch (error) {
      safeLogger.error('Error cleaning up expired credentials', { error });
      return 0;
    }
  }

  /**
   * Returns KYC credential if set
   */
  getKYCCredential(): KYCCredential | null {
    return this.kycCredential;
  }

  /**
   * Validates if a credential has the correct format
   * Implements strict validation with detailed logging
   */
  private validateCredentialFormat(credential: KYCCredential): boolean {
    try {
      // Parameter validation
      if (!credential || typeof credential !== 'object') {
        safeLogger.warn('Invalid credential format: not an object');
        return false;
      }

      // Basic validation checks with detailed logging
      if (!credential.id) {
        safeLogger.warn('Missing required field: id');
        return false;
      }
      
      if (!credential.issuer) {
        safeLogger.warn('Missing required field: issuer');
        return false;
      }
      
      if (!credential.subject) {
        safeLogger.warn('Missing required field: subject');
        return false;
      }

      // Validate dates with proper parsing
      if (!credential.issuedAt) {
        safeLogger.warn('Missing required field: issuedAt');
        return false;
      }
      
      // Validate expiration with safe date handling
      if (credential.expiresAt) {
        // Use proper date parsing with validation
        const expirationDate = new Date(credential.expiresAt);
        const currentDate = new Date();
        
        // Check if date parsing resulted in an invalid date
        if (isNaN(expirationDate.getTime())) {
          safeLogger.warn(`Invalid expiration date format: ${credential.expiresAt}`);
          return false;
        }
        
        if (expirationDate < currentDate) {
          safeLogger.warn(`Credential expired at ${expirationDate.toISOString()}`);
          return false;
        }
      }

      // Validate proof structure
      if (!credential.proof || typeof credential.proof !== 'object') {
        safeLogger.warn('Missing or invalid proof field');
        return false;
      }
      
      if (!credential.proof.type || !credential.proof.proofValue) {
        safeLogger.warn('Missing required proof subfields');
        return false;
      }
      
      // Validate attributes array with bounds checking
      if (!credential.attributes || typeof credential.attributes !== 'object') {
        safeLogger.warn('Missing or invalid attributes');
        return false;
      }

      return true;
    } catch (error) {
      safeLogger.error('Error in credential format validation', { error });
      return false; // Safe error handling
    }
  }

  /**
   * Verifies the KYC credential with the issuer 
   * Implements proper error handling and logging
   */
  private async verifyCredential(): Promise<boolean> {
    // Initial parameter validation with detailed logging
    if (!this.kycCredential) {
      safeLogger.warn('Attempted to verify null credential');
      return false;
    }

    try {
      // Perform format validation before sending to prover
      if (!this.validateCredentialFormat(this.kycCredential)) {
        safeLogger.warn('Credential failed format validation');
        return false;
      }

      safeLogger.info('Verifying credential with KYCProver', {
        credentialId: this.kycCredential.id,
        issuer: this.kycCredential.issuer
      });

      // Use the enhanced KYCProver to verify the credential
      const isValid = await this.kycProver.verifyCredential(this.kycCredential);
      
      if (!isValid) {
        safeLogger.warn('Credential verification failed', {
          credentialId: this.kycCredential.id
        });
      } else {
        safeLogger.info('Credential verified successfully');
      }
      
      return isValid;
    } catch (error) {
      safeLogger.error("Error verifying credential", { error });
      return false; // Safe error handling
    }
  }
}
