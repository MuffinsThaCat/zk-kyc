import { KYCViewer } from '../../src/KYCViewer';
import { KYCProver } from '../../src/KYCProver';
import { KYCCredential, VerificationStatus } from '../../src/types';

// Define test constants for safe parameter handling
const TEST_MAX_PARAMETER_SIZES = {
  CREDENTIAL_ID: 128,           // Maximum credential ID length
  ISSUER_ID: 64,                // Maximum issuer ID length
  SUBJECT_ID: 64,               // Maximum subject ID length
  ATTRIBUTE_NAME: 64,           // Maximum attribute name length
  ATTRIBUTE_VALUE: 1024,        // Maximum attribute value length
  ATTRIBUTE_ARRAY: 100          // Maximum number of attributes in an array
};

// We don't need to mock the NocturneViewer since KYCViewer already has proper implementations
// and we're focused on testing the credential storage functionality

// Mock the CredentialStorage with safe parameter handling behavior
const mockCredentialStoreFactory = () => {
  // Create a new isolated credential store for each test
  const credentialStore = new Map<string, any>();
  
  return {
    // Implement safe parameter handling in our test mocks
    storeCredential: jest.fn().mockImplementation((credential: any) => {
      // Validate credential with safe parameter handling
      if (!credential || !credential.id) return Promise.resolve(false);
      if (credential.id.length > TEST_MAX_PARAMETER_SIZES.CREDENTIAL_ID) return Promise.resolve(false);
      
      // Store and return success
      credentialStore.set(credential.id, credential);
      return Promise.resolve(true);
    }),
    
    getCredential: jest.fn().mockImplementation((id: string) => {
      // Safe parameter handling
      if (!id || typeof id !== 'string') return Promise.resolve(null);
      if (id.length > TEST_MAX_PARAMETER_SIZES.CREDENTIAL_ID) return Promise.resolve(null);
      
      // Retrieve credential
      const credential = credentialStore.get(id);
      return Promise.resolve(credential || null);
    }),
    
    removeCredential: jest.fn().mockImplementation((id: string) => {
      // Safe parameter handling
      if (!id || typeof id !== 'string') return false;
      if (id.length > TEST_MAX_PARAMETER_SIZES.CREDENTIAL_ID) return false;
      
      // Check if exists and remove
      if (!credentialStore.has(id)) return false;
      
      credentialStore.delete(id);
      return true;
    }),
    
    listCredentialIds: jest.fn().mockImplementation(() => {
      return Array.from(credentialStore.keys());
    }),
    
    isCredentialValid: jest.fn().mockImplementation((id: string) => {
      // Safe parameter handling
      if (!id || typeof id !== 'string') return Promise.resolve(false);
      if (id.length > TEST_MAX_PARAMETER_SIZES.CREDENTIAL_ID) return Promise.resolve(false);
      
      return Promise.resolve(credentialStore.has(id));
    }),
    
    cleanupExpiredCredentials: jest.fn().mockReturnValue(0),
    
    clear: jest.fn().mockImplementation(() => {
      credentialStore.clear();
      return true;
    }),
    
    // Allow direct access to the store for test validation
    _getStore: () => credentialStore
  };
};

jest.mock('../../src/storage/CredentialStorage', () => {
  return {
    // Return a new instance with isolated state for each test
    CredentialStorage: jest.fn().mockImplementation(() => mockCredentialStoreFactory())
  };
});

// Create a test implementation of KYCProver
class TestKYCProver implements Partial<KYCProver> {
  verifyCredential = jest.fn().mockResolvedValue(true);
  generateProof = jest.fn().mockResolvedValue({
    proof: { pi_a: [1, 2], pi_b: [[3, 4], [5, 6]], pi_c: [7, 8] },
    publicSignals: [9, 10],
    revealedAttributes: {}
  });
}

describe('KYCViewer', () => {
  let kycViewer: KYCViewer;
  let kycProver: TestKYCProver;
  // We need to use BigInt for KYCViewer's constructor but ensure it's converted to a sufficiently long string internally
  const mockViewingKey = BigInt('0x123456789abcdef');
  const mockNonce = BigInt('0x987654321');
  
  // Mock crypto module to avoid issues with WebCrypto API in testing environment
  jest.mock('../../src/utils/crypto', () => {
    const originalModule = jest.requireActual('../../src/utils/crypto');
    return {
      ...originalModule,
      // Provide safe mock implementations
      safeKeccak256: jest.fn().mockReturnValue('0xmockedhash'),
      encryptWithPassword: jest.fn().mockImplementation((data, password) => {
        return Promise.resolve(`ENCRYPTED:${data}`);
      }),
      decryptWithPassword: jest.fn().mockImplementation((data, password) => {
        if (data.startsWith('ENCRYPTED:')) {
          return Promise.resolve(data.substring(10));
        }
        return Promise.reject(new Error('Mock decryption failed'));
      })
    };
  });

  // Mock logger to avoid console spam
  jest.mock('../../src/utils/logger', () => ({
    safeLogger: {
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      debug: jest.fn()
    }
  }));
  
  // We don't need a reference to the credential store anymore since each test uses its own isolated instance
  
  beforeEach(() => {
    // Reset all mocks and state between tests
    jest.clearAllMocks();
    
    // Create a fresh instance of everything for each test
    
    // Create a fresh KYCProver for each test
    kycProver = new TestKYCProver() as any;
    
    // Use a mock key that's guaranteed to work with our mocks
    const safeViewingKey = BigInt('0x123456789abcdef123456789abcdef');
    kycViewer = new KYCViewer(safeViewingKey, mockNonce, kycProver as any);
    
    // Reset verification status mock
    (kycProver.verifyCredential as jest.Mock).mockResolvedValue(true);
  });

  describe('KYC Credentials Management', () => {
    const sampleCredential: KYCCredential = {
      id: 'test-cred-123',
      issuer: '0x1234567890abcdef1234567890abcdef12345678',
      subject: '0xabcdef1234567890abcdef1234567890abcdef12',
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      attributes: {
        name: 'Test User',
        country: 'US',
        kycLevel: '2'
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: 'did:example:123#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: '0xsignature'
      }
    };

    test('setKYCCredential should store and verify credential', async () => {
      // Set up the KYCProver to verify successfully
      (kycProver.verifyCredential as jest.Mock).mockResolvedValueOnce(true);
      
      // Set the credential
      const result = await kycViewer.setKYCCredential(sampleCredential);
      
      // Verify expectations
      expect(result).toBe(true);
      expect(kycProver.verifyCredential).toHaveBeenCalledWith(sampleCredential);
      expect(kycViewer.getVerificationStatus()).toBe(VerificationStatus.VERIFIED);
    });

    test('getKYCCredential should return the stored credential', async () => {
      // First set a credential
      (kycProver.verifyCredential as jest.Mock).mockResolvedValueOnce(true);
      await kycViewer.setKYCCredential(sampleCredential);
      
      // Then retrieve it
      const credential = kycViewer.getKYCCredential();
      expect(credential).toEqual(sampleCredential);
    });
  });

  describe('Secure Credential Management', () => {
    const sampleCredential1: KYCCredential = {
      id: 'cred-123',
      issuer: '0x1234567890abcdef1234567890abcdef12345678',
      subject: '0xabcdef1234567890abcdef1234567890abcdef12',
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      attributes: {
        name: 'Test User 1',
        country: 'US',
        kycLevel: '2'
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: 'did:example:123#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: '0xsignature1'
      }
    };
    
    const sampleCredential2: KYCCredential = {
      id: 'cred-456',
      issuer: '0x1234567890abcdef1234567890abcdef12345678',
      subject: '0xabcdef1234567890abcdef1234567890abcdef12',
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      attributes: {
        name: 'Test User 2',
        country: 'JP',
        kycLevel: '3'
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: 'did:example:123#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: '0xsignature2'
      }
    };

    test('should store multiple credentials and list them', async () => {
      // Make sure credential store is empty at the start
      expect(kycViewer.listCredentials().length).toBe(0);
      
      // Store multiple credentials
      const result1 = await kycViewer.setKYCCredential(sampleCredential1);
      const result2 = await kycViewer.setKYCCredential(sampleCredential2);
      
      // Verify storage was successful
      expect(result1).toBe(true);
      expect(result2).toBe(true);
      
      // List the credentials and verify exactly what we stored is there
      const credentialIds = kycViewer.listCredentials().sort();
      expect(credentialIds).toEqual(['cred-123', 'cred-456']);
      expect(credentialIds.length).toBe(2);
    });

    test('should retrieve a specific credential by ID', async () => {
      // Set up the KYCProver to verify successfully
      (kycProver.verifyCredential as jest.Mock).mockResolvedValue(true);
      
      // Store multiple credentials
      await kycViewer.setKYCCredential(sampleCredential1);
      await kycViewer.setKYCCredential(sampleCredential2);
      
      // Get the first credential (not the active one)
      const credential = await kycViewer.getCredential('cred-123');
      expect(credential).toEqual(sampleCredential1);
    });
  });
  
  describe('KYC Proof Generation', () => {
    const mockCredential: KYCCredential = {
      id: '123456789',
      issuer: '0x1234567890abcdef1234567890abcdef12345678',
      subject: '0xabcdef1234567890abcdef1234567890abcdef12',
      issuedAt: new Date().toISOString(),
      attributes: {
        name: 'Test User',
        country: 'US',
        kycLevel: '2'
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: 'did:example:123#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: '0xsignature'
      }
    };

    test('generateKYCProof should create a valid proof from active credential', async () => {
      // First set a credential
      (kycProver.verifyCredential as jest.Mock).mockResolvedValue(true);
      await kycViewer.setKYCCredential(mockCredential);
      
      // Then generate a proof
      const attributesToReveal = ['kycLevel'];
      const proof = await kycViewer.generateKYCProof(attributesToReveal);
      
      // Verify the proof was generated correctly
      expect(proof).toBeDefined();
      expect(kycProver.generateProof).toHaveBeenCalled();
      // Verify we passed the right attributes to reveal
      expect(kycProver.generateProof).toHaveBeenCalledWith(
        expect.objectContaining({ id: mockCredential.id }),
        expect.arrayContaining(attributesToReveal),
        expect.anything()
      );
    });
    
    test('generateKYCProof should create a proof from specified credential', async () => {
      // Setup two credentials
      const cred1 = { ...mockCredential, id: 'cred1' };
      const cred2 = { ...mockCredential, id: 'cred2' };
      
      (kycProver.verifyCredential as jest.Mock).mockResolvedValue(true);
      await kycViewer.setKYCCredential(cred1);
      await kycViewer.setKYCCredential(cred2);
      
      // Get mock storage to return the first credential when requested
      jest.spyOn(kycViewer['credentialStorage'], 'getCredential')
          .mockResolvedValueOnce(cred1);
      
      // Generate proof for a specific credential (not the active one)
      const proof = await kycViewer.generateKYCProof(['kycLevel'], 'cred1');
      
      // Verify the correct credential was used
      expect(proof).toBeDefined();
      expect(kycViewer['credentialStorage'].getCredential).toHaveBeenCalledWith('cred1');
      expect(kycProver.generateProof).toHaveBeenCalled();
    });
  });
});
