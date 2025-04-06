import { CredentialStorage } from '../../src/storage/CredentialStorage';
import { KYCCredential } from '../../src/types';

// Mock the crypto utilities for predictable test results
jest.mock('../../src/utils/crypto', () => {
  const originalModule = jest.requireActual('../../src/utils/crypto');
  return {
    ...originalModule,
    encryptWithPassword: jest.fn().mockImplementation((data, password) => {
      // Simple mock implementation that adds a prefix to simulate encryption
      return Promise.resolve(`encrypted:${password}:${data}`);
    }),
    decryptWithPassword: jest.fn().mockImplementation((data, password) => {
      // Verify the format and decrypt our mock format
      if (data.startsWith('encrypted:') && data.includes(`:${password}:`)) {
        return Promise.resolve(data.split(`:${password}:`)[1]);
      }
      return Promise.resolve(''); // Simulate decryption failure
    }),
    safeKeccak256: jest.fn().mockImplementation((data) => {
      // Deterministic mock hash for testing
      return `hash_${data.toString().substring(0, 10)}`;
    })
  };
});

// Mock the logger to avoid console spam during tests
jest.mock('../../src/utils/logger', () => ({
  safeLogger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
  }
}));

describe('CredentialStorage', () => {
  let storage: CredentialStorage;
  const mockViewingKey = 'test_viewing_key_123456';
  
  // Create a valid sample credential for testing
  const sampleCredential: KYCCredential = {
    id: 'cred123456',
    issuer: '0x1234567890abcdef1234567890abcdef12345678',
    subject: '0xabcdef1234567890abcdef1234567890abcdef12',
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    attributes: {
      name: 'John Doe',
      country: 'US',
      birthdate: '1990-01-01',
      kycLevel: '2'
    },
    proof: {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: 'did:example:123#key-1',
      proofPurpose: 'assertionMethod',
      proofValue: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
    }
  };
  
  // Create an expired credential for testing
  const expiredCredential: KYCCredential = {
    ...sampleCredential,
    id: 'expired123',
    expiresAt: new Date(Date.now() - 1000).toISOString() // expired
  };

  beforeEach(() => {
    // Create a fresh storage instance for each test
    storage = new CredentialStorage(mockViewingKey);
  });

  describe('Initialization and Basic Functionality', () => {
    test('should initialize successfully with a valid viewing key', () => {
      expect(storage).toBeDefined();
      expect(storage.getCredentialCount()).toBe(0);
    });

    test('should handle invalid viewing key safely', () => {
      expect(() => new CredentialStorage('')).toThrow('Invalid viewing key');
      expect(() => new CredentialStorage('short')).toThrow('Invalid viewing key');
    });
    
    test('should return empty list when no credentials are stored', () => {
      const list = storage.listCredentialIds();
      expect(list).toEqual([]);
    });
  });

  describe('Credential Storage and Retrieval', () => {
    test('should store and retrieve a valid credential', async () => {
      // Store a credential
      const storeResult = await storage.storeCredential(sampleCredential);
      expect(storeResult).toBe(true);
      expect(storage.getCredentialCount()).toBe(1);
      
      // Retrieve and verify the credential
      const retrievedCredential = await storage.getCredential(sampleCredential.id);
      expect(retrievedCredential).toEqual(sampleCredential);
    });
    
    test('should handle duplicate credential IDs safely', async () => {
      // Store a credential
      await storage.storeCredential(sampleCredential);
      
      // Try to store another credential with the same ID
      const duplicateResult = await storage.storeCredential(sampleCredential);
      expect(duplicateResult).toBe(false);
      expect(storage.getCredentialCount()).toBe(1);
    });
    
    test('should handle invalid credentials safely', async () => {
      // @ts-ignore - Intentionally passing invalid input for testing
      const invalidResult = await storage.storeCredential(null);
      expect(invalidResult).toBe(false);
      
      // Test with missing required fields
      const invalidCredential = { ...sampleCredential, id: '' };
      const invalidResult2 = await storage.storeCredential(invalidCredential);
      expect(invalidResult2).toBe(false);
    });
    
    test('should handle oversized credential IDs safely', async () => {
      // Create a credential with an extremely long ID
      const longIdCredential = { 
        ...sampleCredential, 
        id: 'x'.repeat(1000) // Very long ID
      };
      
      const oversizeResult = await storage.storeCredential(longIdCredential);
      expect(oversizeResult).toBe(false);
    });
  });

  describe('Credential Removal and Lifecycle', () => {
    test('should remove a credential successfully', async () => {
      // Store a credential first
      await storage.storeCredential(sampleCredential);
      expect(storage.getCredentialCount()).toBe(1);
      
      // Remove it
      const removeResult = storage.removeCredential(sampleCredential.id);
      expect(removeResult).toBe(true);
      expect(storage.getCredentialCount()).toBe(0);
      
      // Verify it's gone
      const retrievedCredential = await storage.getCredential(sampleCredential.id);
      expect(retrievedCredential).toBeNull();
    });
    
    test('should handle expired credentials correctly', async () => {
      // Store an expired credential
      await storage.storeCredential(expiredCredential);
      
      // Verify it's stored but retrieval returns null due to expiry
      expect(storage.getCredentialCount()).toBe(1);
      const retrievedCredential = await storage.getCredential(expiredCredential.id);
      expect(retrievedCredential).toBeNull();
    });
    
    test('should clean up expired credentials', async () => {
      // Store both valid and expired credentials
      await storage.storeCredential(sampleCredential);
      await storage.storeCredential(expiredCredential);
      expect(storage.getCredentialCount()).toBe(2);
      
      // Run cleanup
      const removedCount = storage.cleanupExpiredCredentials();
      expect(removedCount).toBe(1);
      expect(storage.getCredentialCount()).toBe(1);
      
      // Verify only the expired credential was removed
      const validCred = await storage.getCredential(sampleCredential.id);
      expect(validCred).not.toBeNull();
      const expiredCred = await storage.getCredential(expiredCredential.id);
      expect(expiredCred).toBeNull();
    });
    
    test('should validate credential correctly', async () => {
      // Store both valid and expired credentials
      await storage.storeCredential(sampleCredential);
      await storage.storeCredential(expiredCredential);
      
      // Check validity
      const validResult = await storage.isCredentialValid(sampleCredential.id);
      expect(validResult).toBe(true);
      
      const expiredResult = await storage.isCredentialValid(expiredCredential.id);
      expect(expiredResult).toBe(false);
      
      const nonExistentResult = await storage.isCredentialValid('non-existent-id');
      expect(nonExistentResult).toBe(false);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    test('should handle getCredential with invalid ID safely', async () => {
      // Try to retrieve with null/invalid ID
      // @ts-ignore - Intentionally passing invalid input for testing
      const result1 = await storage.getCredential(null);
      expect(result1).toBeNull();
      
      // Try with excessively long ID
      const result2 = await storage.getCredential('x'.repeat(1000));
      expect(result2).toBeNull();
    });
    
    test('should handle removeCredential with invalid ID safely', () => {
      // Try to remove with null/invalid ID
      // @ts-ignore - Intentionally passing invalid input for testing
      const result1 = storage.removeCredential(null);
      expect(result1).toBe(false);
      
      // Try to remove non-existent credential
      const result2 = storage.removeCredential('non-existent-id');
      expect(result2).toBe(false);
    });
    
    test('should handle clear operation properly', async () => {
      // Store multiple credentials
      await storage.storeCredential(sampleCredential);
      await storage.storeCredential({ ...sampleCredential, id: 'second-cred' });
      expect(storage.getCredentialCount()).toBe(2);
      
      // Clear all credentials
      const clearResult = storage.clear();
      expect(clearResult).toBe(true);
      expect(storage.getCredentialCount()).toBe(0);
      
      // Verify all credentials are gone
      const list = storage.listCredentialIds();
      expect(list).toEqual([]);
    });
  });
});
