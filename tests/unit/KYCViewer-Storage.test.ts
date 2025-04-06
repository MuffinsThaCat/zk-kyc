import { KYCViewer } from '../../src/KYCViewer';
import { KYCProver } from '../../src/KYCProver';
import { KYCCredential, VerificationStatus } from '../../src/types';

// Mock the KYCProver for focused storage testing
jest.mock('../../src/KYCProver', () => {
  return {
    KYCProver: jest.fn().mockImplementation(() => ({
      verifyCredential: jest.fn().mockResolvedValue(true),
      generateProof: jest.fn().mockResolvedValue({
        proof: { mockProof: true },
        publicSignals: ['mockSignal1', 'mockSignal2'],
        revealedAttributes: {}
      })
    }))
  };
});

// Mock credential storage methods for isolation
jest.mock('../../src/storage/CredentialStorage', () => {
  return {
    CredentialStorage: jest.fn().mockImplementation(() => {
      const storedCredentials = new Map<string, KYCCredential>();
      const expiryDates = new Map<string, Date>();
      
      return {
        storeCredential: jest.fn().mockImplementation((credential: KYCCredential) => {
          // Simulate storage with parameter validation
          if (!credential || !credential.id) {
            return Promise.resolve(false);
          }
          
          // Check for duplicates (bounds checking)
          if (storedCredentials.has(credential.id)) {
            return Promise.resolve(false);
          }
          
          // Store the credential
          storedCredentials.set(credential.id, credential);
          
          // Add to expiry index if applicable
          if (credential.expiresAt) {
            expiryDates.set(credential.id, new Date(credential.expiresAt));
          }
          
          return Promise.resolve(true);
        }),
        
        getCredential: jest.fn().mockImplementation((credentialId: string) => {
          // Validate parameter
          if (!credentialId) {
            return Promise.resolve(null);
          }
          
          // Check if credential exists
          const credential = storedCredentials.get(credentialId);
          if (!credential) {
            return Promise.resolve(null);
          }
          
          // Check if expired
          if (credential.expiresAt) {
            const expiryDate = new Date(credential.expiresAt);
            if (expiryDate < new Date()) {
              return Promise.resolve(null);
            }
          }
          
          return Promise.resolve(credential);
        }),
        
        removeCredential: jest.fn().mockImplementation((credentialId: string) => {
          // Validate parameter
          if (!credentialId) {
            return false;
          }
          
          // Check if credential exists
          if (!storedCredentials.has(credentialId)) {
            return false;
          }
          
          // Remove the credential
          storedCredentials.delete(credentialId);
          expiryDates.delete(credentialId);
          
          return true;
        }),
        
        listCredentialIds: jest.fn().mockImplementation(() => {
          const now = new Date();
          const validIds: string[] = [];
          
          // Filter out expired credentials
          for (const [id, credential] of storedCredentials.entries()) {
            if (credential.expiresAt) {
              const expiryDate = new Date(credential.expiresAt);
              if (expiryDate > now) {
                validIds.push(id);
              }
            } else {
              validIds.push(id);
            }
          }
          
          return validIds;
        }),
        
        isCredentialValid: jest.fn().mockImplementation((credentialId: string) => {
          // Validate parameter
          if (!credentialId) {
            return Promise.resolve(false);
          }
          
          // Check if credential exists
          if (!storedCredentials.has(credentialId)) {
            return Promise.resolve(false);
          }
          
          // Check if expired
          const credential = storedCredentials.get(credentialId);
          if (credential && credential.expiresAt) {
            const expiryDate = new Date(credential.expiresAt);
            if (expiryDate < new Date()) {
              return Promise.resolve(false);
            }
          }
          
          return Promise.resolve(true);
        }),
        
        cleanupExpiredCredentials: jest.fn().mockImplementation(() => {
          const now = new Date();
          let removedCount = 0;
          
          // Find expired credentials
          const expiredIds: string[] = [];
          for (const [id, expiryDate] of expiryDates.entries()) {
            if (expiryDate < now) {
              expiredIds.push(id);
            }
          }
          
          // Remove them
          for (const id of expiredIds) {
            storedCredentials.delete(id);
            expiryDates.delete(id);
            removedCount++;
          }
          
          return removedCount;
        }),
        
        getCredentialCount: jest.fn().mockImplementation(() => {
          return storedCredentials.size;
        }),
        
        clear: jest.fn().mockImplementation(() => {
          storedCredentials.clear();
          expiryDates.clear();
          return true;
        })
      };
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

describe('KYCViewer with Secure Storage', () => {
  let kycViewer: KYCViewer;
  const mockViewingKey = BigInt('0x123456789abcdef');
  const mockNonce = BigInt('0x987654321');
  
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
  
  // Create additional credentials for testing multi-credential functionality
  const credential2: KYCCredential = {
    ...sampleCredential,
    id: 'cred2',
    attributes: {
      ...sampleCredential.attributes,
      name: 'Jane Smith',
      country: 'JP',
      kycLevel: '3'
    }
  };
  
  const credential3: KYCCredential = {
    ...sampleCredential,
    id: 'cred3',
    attributes: {
      ...sampleCredential.attributes,
      name: 'Bob Johnson',
      country: 'UK',
      kycLevel: '1'
    }
  };
  
  // Create an expired credential for testing
  const expiredCredential: KYCCredential = {
    ...sampleCredential,
    id: 'expired123',
    expiresAt: new Date(Date.now() - 1000).toISOString() // expired
  };
  
  beforeEach(() => {
    // Create a fresh KYCViewer instance with a new KYCProver
    const kycProver = new KYCProver({
      circuitPath: '/tmp/mock-circuits/kyc.wasm',
      provingKeyPath: '/tmp/mock-circuits/kyc.zkey',
      verificationKeyPath: '/tmp/mock-circuits/verification_key.json',
      issuerPublicKeys: {
        '0x1234567890abcdef1234567890abcdef12345678': 'mockPublicKey'
      }
    });
    
    kycViewer = new KYCViewer(mockViewingKey, mockNonce, kycProver);
    
    // Reset all mocks between tests
    jest.clearAllMocks();
  });
  
  describe('Credential Storage Integration', () => {
    test('should store credential securely via setKYCCredential', async () => {
      const result = await kycViewer.setKYCCredential(sampleCredential);
      expect(result).toBe(true);
      expect(kycViewer.getVerificationStatus()).toBe(VerificationStatus.VERIFIED);
    });
    
    test('should list stored credentials', async () => {
      // Store multiple credentials
      await kycViewer.setKYCCredential(sampleCredential);
      await kycViewer.setKYCCredential(credential2);
      await kycViewer.setKYCCredential(credential3);
      
      // Get the list
      const credentials = kycViewer.listCredentials();
      expect(credentials.length).toBe(3);
      expect(credentials).toContain(sampleCredential.id);
      expect(credentials).toContain(credential2.id);
      expect(credentials).toContain(credential3.id);
    });
    
    test('should retrieve specific credential by ID', async () => {
      // Store multiple credentials
      await kycViewer.setKYCCredential(sampleCredential);
      await kycViewer.setKYCCredential(credential2);
      
      // Retrieve one credential
      const credential = await kycViewer.getCredential(credential2.id);
      expect(credential).not.toBeNull();
      expect(credential?.id).toBe(credential2.id);
    });
    
    test('should activate different credentials', async () => {
      // Store multiple credentials
      await kycViewer.setKYCCredential(sampleCredential);
      await kycViewer.setKYCCredential(credential2);
      
      // The last one added should be active
      expect(kycViewer.getKYCCredential()?.id).toBe(credential2.id);
      
      // Switch to the first one
      const result = await kycViewer.setActiveCredential(sampleCredential.id);
      expect(result).toBe(true);
      expect(kycViewer.getKYCCredential()?.id).toBe(sampleCredential.id);
    });
    
    test('should remove credentials properly', async () => {
      // Store multiple credentials
      await kycViewer.setKYCCredential(sampleCredential);
      await kycViewer.setKYCCredential(credential2);
      
      // Remove one
      const result = kycViewer.removeCredential(sampleCredential.id);
      expect(result).toBe(true);
      
      // Check it's removed from list
      const credentials = kycViewer.listCredentials();
      expect(credentials.length).toBe(1);
      expect(credentials).not.toContain(sampleCredential.id);
      expect(credentials).toContain(credential2.id);
    });
    
    test('should handle removal of active credential', async () => {
      // Store and activate a credential
      await kycViewer.setKYCCredential(sampleCredential);
      
      // Remove the active credential
      const result = kycViewer.removeCredential(sampleCredential.id);
      expect(result).toBe(true);
      
      // Check state is updated
      expect(kycViewer.getKYCCredential()).toBeNull();
      expect(kycViewer.getVerificationStatus()).toBe(VerificationStatus.UNVERIFIED);
    });
    
    test('should handle expired credentials cleanup', async () => {
      // Store one normal and one expired credential
      await kycViewer.setKYCCredential(sampleCredential);
      await kycViewer.setKYCCredential(expiredCredential);
      
      // The mock implementation already filters expired credentials in listCredentialIds
      // so we won't see the expired credential in the list from the start
      // This reflects the actual implementation's behavior
      const initialCredentials = kycViewer.listCredentials();
      expect(initialCredentials.length).toBe(1);
      expect(initialCredentials).toContain(sampleCredential.id);
      
      // Clean up expired - this is still expected to find and remove the expired credential
      const removedCount = kycViewer.cleanupExpiredCredentials();
      expect(removedCount).toBe(1);
      
      // After cleanup, valid credentials should remain
      const credentials = kycViewer.listCredentials();
      expect(credentials.length).toBe(1);
      expect(credentials).toContain(sampleCredential.id);
      expect(credentials).not.toContain(expiredCredential.id);
    });
  });
  
  describe('Proof Generation with Multiple Credentials', () => {
    test('should generate proof from active credential by default', async () => {
      // Store multiple credentials
      await kycViewer.setKYCCredential(sampleCredential);
      await kycViewer.setKYCCredential(credential2);
      
      // Generate a proof without specifying credential
      const proof = await kycViewer.generateKYCProof(['kycLevel']);
      
      // Should use the active credential (credential2)
      expect(proof).not.toBeNull();
      expect(kycViewer.getKYCCredential()?.id).toBe(credential2.id);
    });
    
    test('should generate proof from specified credential', async () => {
      // Store multiple credentials
      await kycViewer.setKYCCredential(sampleCredential);
      await kycViewer.setKYCCredential(credential2);
      
      // Generate a proof from the first credential (not the active one)
      const proof = await kycViewer.generateKYCProof(['kycLevel'], sampleCredential.id);
      
      // Should succeed but not change the active credential
      expect(proof).not.toBeNull();
      expect(kycViewer.getKYCCredential()?.id).toBe(credential2.id);
    });
    
    test('should handle invalid credential ID for proof generation', async () => {
      // Store a credential
      await kycViewer.setKYCCredential(sampleCredential);
      
      // Try to generate proof with non-existent ID
      const proof = await kycViewer.generateKYCProof(['kycLevel'], 'non-existent-id');
      
      // Should fail safely
      expect(proof).toBeNull();
    });
    
    test('should apply safe parameter handling for attributes list', async () => {
      // Store a credential
      await kycViewer.setKYCCredential(sampleCredential);
      
      // Create an oversized attributes array (should be handled safely)
      const hugeAttributesList = Array(2000).fill('attribute');
      
      // Should handle this safely without crashing
      const proof = await kycViewer.generateKYCProof(hugeAttributesList);
      
      // Even with oversized input, it should generate a proof with sanitized inputs
      expect(proof).not.toBeNull();
    });
  });
  
  describe('Error Handling and Parameter Validation', () => {
    test('should handle invalid credential format safely', async () => {
      // @ts-ignore - Intentionally passing invalid input for testing
      const result = await kycViewer.setKYCCredential(null);
      expect(result).toBe(false);
      expect(kycViewer.getVerificationStatus()).toBe(VerificationStatus.INVALID);
    });
    
    test('should handle oversized credential ID', async () => {
      // Create a credential with an extremely long ID
      const longIdCredential = { 
        ...sampleCredential, 
        id: 'x'.repeat(1000) // Very long ID
      };
      
      const result = await kycViewer.setKYCCredential(longIdCredential);
      expect(result).toBe(false);
    });
    
    test('should handle invalid credential IDs in operations', async () => {
      // Store a valid credential first
      await kycViewer.setKYCCredential(sampleCredential);
      
      // Test with invalid ID
      // @ts-ignore - Intentionally passing invalid input for testing
      const result1 = await kycViewer.getCredential(null);
      expect(result1).toBeNull();
      
      // Test with oversized ID
      const result2 = await kycViewer.getCredential('x'.repeat(1000));
      expect(result2).toBeNull();
      
      // Test setActive with invalid ID
      // @ts-ignore - Intentionally passing invalid input for testing
      const result3 = await kycViewer.setActiveCredential(null);
      expect(result3).toBe(false);
      
      // Test remove with invalid ID
      // @ts-ignore - Intentionally passing invalid input for testing
      const result4 = kycViewer.removeCredential(null);
      expect(result4).toBe(false);
    });
  });
});
