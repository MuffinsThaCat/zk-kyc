import { KYCCredential } from '../types';
import { safeLogger } from '../utils/logger';
import { safeKeccak256, encryptWithPassword, decryptWithPassword, MAX_PARAMETER_SIZES } from '../utils/crypto';

/**
 * Class for securely storing and managing KYC credentials
 * Implements safe parameter handling with bounds checking and proper validation
 */
export class CredentialStorage {
  private credentials: Map<string, string> = new Map(); // Encrypted credentials by ID
  private expiryIndex: Map<string, Date> = new Map(); // Track expiry dates for quick filtering
  private readonly viewingKey: string;
  
  /**
   * Create a new credential storage instance
   * @param viewingKey - Key used for encryption/decryption
   */
  constructor(viewingKey: string) {
    if (!viewingKey || typeof viewingKey !== 'string' || viewingKey.length < 16) {
      safeLogger.error('Invalid viewing key provided to CredentialStorage');
      throw new Error('Invalid viewing key');
    }
    
    // Use a hash of the viewing key for encryption to ensure sufficient entropy
    this.viewingKey = safeKeccak256(viewingKey);
    safeLogger.info('Initialized secure credential storage');
  }
  
  /**
   * Store a KYC credential securely
   * Implements safe parameter handling with proper validation and bounds checking
   * @param credential - The credential to store
   * @returns boolean indicating success
   */
  async storeCredential(credential: KYCCredential): Promise<boolean> {
    try {
      // Validate credential first 
      if (!credential || typeof credential !== 'object') {
        safeLogger.warn('Invalid credential format in storage operation');
        return false;
      }
      
      // Check required fields
      if (!credential.id || !credential.issuer || !credential.subject) {
        safeLogger.warn('Missing required fields in credential');
        return false;
      }
      
      // Enforce parameter size limits for security
      if (credential.id.length > MAX_PARAMETER_SIZES.CREDENTIAL_ID) {
        safeLogger.warn(`Credential ID exceeds maximum size: ${credential.id.length}`);
        return false;
      }
      
      // Check if a credential with this ID already exists
      if (this.credentials.has(credential.id)) {
        safeLogger.warn(`Credential with ID ${credential.id} already exists`);
        return false;
      }

      // Add to expiry index if expiry date is present
      if (credential.expiresAt) {
        const expiryDate = new Date(credential.expiresAt);
        if (isNaN(expiryDate.getTime())) {
          safeLogger.warn(`Invalid expiry date for credential ${credential.id}`);
          return false;
        }
        this.expiryIndex.set(credential.id, expiryDate);
      }
      
      // Encrypt the credential before storage
      const credentialString = JSON.stringify(credential);
      const encryptedCredential = await encryptWithPassword(
        credentialString,
        this.viewingKey
      );
      
      // Store with safe bounds checking
      if (!encryptedCredential || encryptedCredential.length === 0) {
        safeLogger.error('Encryption failed for credential');
        return false;
      }
      
      this.credentials.set(credential.id, encryptedCredential);
      safeLogger.info(`Stored credential ${credential.id} securely`);
      return true;
    } catch (error) {
      safeLogger.error('Error storing credential', { error });
      return false;
    }
  }
  
  /**
   * Retrieve a credential by ID
   * Implements safe parameter handling with proper validation
   * @param credentialId - ID of the credential to retrieve
   * @returns the decrypted credential or null if not found/error
   */
  async getCredential(credentialId: string): Promise<KYCCredential | null> {
    try {
      // Validate parameter
      if (!credentialId || typeof credentialId !== 'string') {
        safeLogger.warn('Invalid credential ID requested');
        return null;
      }
      
      // Apply bounds checking
      if (credentialId.length > MAX_PARAMETER_SIZES.CREDENTIAL_ID) {
        safeLogger.warn(`Credential ID exceeds maximum size: ${credentialId.length}`);
        return null;
      }
      
      // Check if credential exists
      const encryptedCredential = this.credentials.get(credentialId);
      if (!encryptedCredential) {
        safeLogger.warn(`Credential ${credentialId} not found`);
        return null;
      }
      
      // Decrypt with safe error handling
      try {
        const decryptedString = await decryptWithPassword(
          encryptedCredential,
          this.viewingKey
        );
        
        // Parse the decrypted credential with validation
        const credential = JSON.parse(decryptedString) as KYCCredential;
        
        // Check if credential has expired
        if (credential.expiresAt && new Date(credential.expiresAt) < new Date()) {
          safeLogger.warn(`Credential ${credentialId} has expired`);
          return null;
        }
        
        return credential;
      } catch (decryptError) {
        safeLogger.error('Error decrypting credential', { 
          credentialId,
          error: decryptError
        });
        return null;
      }
    } catch (error) {
      safeLogger.error('Error retrieving credential', { error });
      return null;
    }
  }
  
  /**
   * List all valid credential IDs (non-expired)
   * @returns Array of credential IDs
   */
  listCredentialIds(): string[] {
    const now = new Date();
    const validIds: string[] = [];
    
    // Apply bounds checking while building the list
    const maxResults = MAX_PARAMETER_SIZES.MAX_RESULTS; 
    
    for (const [id, expiryDate] of this.expiryIndex.entries()) {
      // Skip expired credentials
      if (expiryDate < now) continue;
      
      validIds.push(id);
      
      // Limit the result size for safety
      if (validIds.length >= maxResults) break;
    }
    
    // Add credentials without expiry dates
    for (const id of this.credentials.keys()) {
      if (!this.expiryIndex.has(id)) {
        validIds.push(id);
      }
      
      // Enforce result limit
      if (validIds.length >= maxResults) break;
    }
    
    return validIds;
  }
  
  /**
   * Remove a credential from storage
   * Implements safe parameter handling with proper validation
   * @param credentialId - ID of the credential to remove
   * @returns boolean indicating success
   */
  removeCredential(credentialId: string): boolean {
    try {
      // Validate parameter
      if (!credentialId || typeof credentialId !== 'string') {
        safeLogger.warn('Invalid credential ID for removal');
        return false;
      }
      
      // Apply bounds checking
      if (credentialId.length > MAX_PARAMETER_SIZES.CREDENTIAL_ID) {
        safeLogger.warn(`Credential ID exceeds maximum size: ${credentialId.length}`);
        return false;
      }
      
      // Check if credential exists
      if (!this.credentials.has(credentialId)) {
        safeLogger.warn(`Credential ${credentialId} not found for removal`);
        return false;
      }
      
      // Remove from both maps
      this.credentials.delete(credentialId);
      this.expiryIndex.delete(credentialId);
      
      safeLogger.info(`Removed credential ${credentialId}`);
      return true;
    } catch (error) {
      safeLogger.error('Error removing credential', { error });
      return false;
    }
  }
  
  /**
   * Check if a credential exists and is valid (not expired)
   * @param credentialId - ID of the credential to check
   * @returns boolean indicating if the credential is valid
   */
  async isCredentialValid(credentialId: string): Promise<boolean> {
    // First apply validation and bounds checking
    if (!credentialId || typeof credentialId !== 'string' || 
        credentialId.length > MAX_PARAMETER_SIZES.CREDENTIAL_ID) {
      return false;
    }
    
    // Check if credential exists
    if (!this.credentials.has(credentialId)) {
      return false;
    }
    
    // Check expiry
    if (this.expiryIndex.has(credentialId)) {
      const expiryDate = this.expiryIndex.get(credentialId);
      if (expiryDate && expiryDate < new Date()) {
        return false;
      }
    }
    
    // Verify the credential can be decrypted successfully
    const credential = await this.getCredential(credentialId);
    return credential !== null;
  }
  
  /**
   * Perform cleanup of expired credentials
   * @returns Number of credentials removed
   */
  cleanupExpiredCredentials(): number {
    const now = new Date();
    let removedCount = 0;
    
    // Create a list of expired credential IDs
    const expiredIds: string[] = [];
    for (const [id, expiryDate] of this.expiryIndex.entries()) {
      if (expiryDate < now) {
        expiredIds.push(id);
      }
    }
    
    // Remove each expired credential
    for (const id of expiredIds) {
      if (this.removeCredential(id)) {
        removedCount++;
      }
    }
    
    safeLogger.info(`Removed ${removedCount} expired credentials`);
    return removedCount;
  }
  
  /**
   * Get the count of stored credentials
   * @returns The number of credentials in storage
   */
  getCredentialCount(): number {
    return this.credentials.size;
  }
  
  /**
   * Clear all stored credentials
   * @returns boolean indicating success
   */
  clear(): boolean {
    try {
      this.credentials.clear();
      this.expiryIndex.clear();
      safeLogger.info('Cleared all credentials from storage');
      return true;
    } catch (error) {
      safeLogger.error('Error clearing credentials', { error });
      return false;
    }
  }
}
