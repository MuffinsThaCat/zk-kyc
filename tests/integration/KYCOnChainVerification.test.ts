import { KYCClient } from '../../src/KYCClient';
import { KYCCredential, VerificationStatus } from '../../src/types';
import { BlockchainServiceConfig } from '../../src/blockchain/BlockchainService';
import logger from '../../src/utils/logger';

// Create direct mocks for our dependencies
const mockVerifyCredential = jest.fn().mockResolvedValue(true);
const mockGenerateProof = jest.fn().mockResolvedValue({
  proof: {
    a: [BigInt(100), BigInt(200)],
    b: [[BigInt(300), BigInt(400)], [BigInt(500), BigInt(600)]],
    c: [BigInt(700), BigInt(800)]
  },
  publicSignals: [BigInt(900), BigInt(1000)],
  revealedAttributes: { 'over18': true, 'country': 'US' }
});
const mockVerifyProof = jest.fn().mockResolvedValue(true);

// Mock implementations
jest.mock('../../src/KYCProver', () => {
  return {
    KYCProver: jest.fn().mockImplementation(() => ({
      verifyCredential: mockVerifyCredential,
      generateProof: mockGenerateProof,
      verifyProof: mockVerifyProof
    }))
  };
});

// Mock out credential storage
jest.mock('../../src/storage/CredentialStorage', () => {
  const mockCredentials = new Map();
  
  return {
    CredentialStorage: jest.fn().mockImplementation(() => ({
      storeCredential: jest.fn().mockImplementation((credential) => {
        mockCredentials.set(credential.id, credential);
        return Promise.resolve(true);
      }),
      getCredential: jest.fn().mockImplementation((id) => {
        return Promise.resolve(mockCredentials.get(id) || null);
      }),
      removeCredential: jest.fn().mockReturnValue(true),
      cleanupExpiredCredentials: jest.fn().mockReturnValue(0),
      isCredentialValid: jest.fn().mockReturnValue(true),
      clear: jest.fn()
    }))
  };
});

describe('KYC On-Chain Verification Integration', () => {
  // Mock provider
  const mockProvider = {
    getSigner: jest.fn().mockReturnValue({
      getAddress: jest.fn().mockResolvedValue('0x1234567890abcdef1234567890abcdef12345678')
    })
  };

  const mockKYCProverConfig = {
    circuitPath: './test-circuits/kyc-verification.json',
    provingKeyPath: './test-circuits/proving-key.json', 
    verificationKeyPath: './test-circuits/verification-key.json',
    issuerPublicKeys: {
      '0x1234567890abcdef1234567890abcdef12345678': 'test-key'
    }
  };
  


  const mockViewingKey = BigInt("0x123456789abcdef");
  const mockNonce = BigInt(1);

  const blockchainConfig: BlockchainServiceConfig = {
    providerUrl: 'https://localhost:8545',
    kycVerifierAddress: '0xabcdef1234567890abcdef1234567890abcdef12',
    privateKey: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
  };

  const createKYCClient = async () => {
    return await KYCClient.create(
      {
        kycProverConfig: mockKYCProverConfig,
        nocturneViewerParams: {
          viewingKey: mockViewingKey,
          nonce: mockNonce
        }
      },
      mockProvider,
      'localhost',
      blockchainConfig
    );
  };

  // Create a mock KYC credential
  const createMockCredential = (id: string, expired = false): KYCCredential => ({
    id,
    issuer: '0x1234567890abcdef1234567890abcdef12345678',
    subject: 'did:example:123456789abcdefghi',
    issuedAt: new Date().toISOString(),
    expiresAt: expired 
      ? new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString() // 1 day ago
      : new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year from now
    attributes: {
      name: 'John Doe',
      country: 'US',
      over18: true,
      over21: true,
      kycLevel: 3
    },
    proof: {
      // Using ZKP type that our mocked KYCProver will validate
      type: 'ZKProof2023',
      created: new Date().toISOString(),
      verificationMethod: 'did:example:123456789abcdefghi#keys-1',
      proofPurpose: 'assertionMethod',
      proofValue: 'valid-test-proof-value'
    }
  });

  describe('On-Chain Verification Flow', () => {
    beforeEach(() => {
      jest.clearAllMocks();
      // Reset our mocks to default values
      mockVerifyCredential.mockReset().mockResolvedValue(true);
      mockGenerateProof.mockReset().mockResolvedValue({
        proof: {
          a: [BigInt(100), BigInt(200)],
          b: [[BigInt(300), BigInt(400)], [BigInt(500), BigInt(600)]],
          c: [BigInt(700), BigInt(800)]
        },
        publicSignals: [BigInt(900), BigInt(1000)],
        revealedAttributes: { 'over18': true, 'country': 'US' }
      });
      mockVerifyProof.mockReset().mockResolvedValue(true);
    });

    test('should set up KYCClient with blockchain service', async () => {
      const client = await createKYCClient();
      expect(client).toBeDefined();
    });

    test('should register KYC credential and verify on-chain', async () => {
      const client = await createKYCClient();
      const credential = createMockCredential('on-chain-test-cred-1');
      
      // Mock the blockchain service verification method to return success
      const mockTxReceipt = {
        status: 1,
        blockNumber: 12345678,
        transactionHash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
      };
      
      // Set up mock implementations
      (client as any).blockchainService = {
        verifyKYCProofOnChain: jest.fn().mockResolvedValue(mockTxReceipt),
        isUserVerified: jest.fn().mockResolvedValue(true),
        hasAttribute: jest.fn().mockResolvedValue(true)
      };
      
      // Set the credential
      const setResult = await client.setKYCCredential(credential);
      expect(setResult).toBe(true);
      expect(client.getKYCVerificationStatus()).toBe(VerificationStatus.VERIFIED);
      
      // Submit the proof on-chain
      const onChainResult = await client.submitKYCProof(['country', 'over18']);
      expect(onChainResult).toBeDefined();
      expect(onChainResult.status).toBe(1);
      
      // Check verification status on-chain
      const isVerified = await client.isVerifiedOnChain();
      expect(isVerified).toBe(true);
      
      // Check attribute verification
      const hasAttribute = await client.hasAttributeOnChain('over18');
      expect(hasAttribute).toBe(true);
    });

    test('should handle on-chain verification with multiple credentials', async () => {
      const client = await createKYCClient();
      
      // Create multiple credentials
      const credential1 = createMockCredential('on-chain-test-cred-2-1');
      const credential2 = createMockCredential('on-chain-test-cred-2-2');
      const credential3 = createMockCredential('on-chain-test-cred-2-3');
      
      // Mock the blockchain service methods
      (client as any).blockchainService = {
        verifyKYCProofOnChain: jest.fn().mockResolvedValue({
          status: 1,
          blockNumber: 12345678,
          transactionHash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
        }),
        isUserVerified: jest.fn().mockResolvedValue(true),
        hasAttribute: jest.fn().mockImplementation((addr, attr) => {
          return Promise.resolve(attr === 'over18' || attr === 'country' === true);
        })
      };
      
      // Set multiple credentials
      await client.setKYCCredential(credential1);
      await client.setKYCCredential(credential2);
      await client.setKYCCredential(credential3);
      
      // Verify first credential on-chain
      const onChainResult1 = await client.submitKYCProof(['over18']);
      expect(onChainResult1.status).toBe(1);
      
      // Check verification status
      const isVerified = await client.isVerifiedOnChain();
      expect(isVerified).toBe(true);
      
      // Check attribute verification
      const hasOver18 = await client.hasAttributeOnChain('over18');
      expect(hasOver18).toBe(true);
      
      const hasOver21 = await client.hasAttributeOnChain('over21');
      expect(hasOver21).toBe(false); // We didn't reveal this attribute
    });
    
    test('should handle errors in on-chain verification process', async () => {
      const client = await createKYCClient();
      const credential = createMockCredential('on-chain-test-cred-3');
      
      // Mock blockchain service to simulate failure
      (client as any).blockchainService = {
        verifyKYCProofOnChain: jest.fn().mockRejectedValue(new Error('Blockchain verification failed')),
        isUserVerified: jest.fn().mockResolvedValue(false),
        hasAttribute: jest.fn().mockResolvedValue(false)
      };
      
      // Mock credential verification to succeed
      mockVerifyCredential.mockResolvedValue(true);
      
      // Set the credential
      const setResult = await client.setKYCCredential(credential);
      expect(setResult).toBe(true);
      
      // Verify on-chain should fail
      await expect(client.submitKYCProof(['country'])).rejects.toThrow('Blockchain verification failed');
      
      // Verification status should be false
      const isVerified = await client.isVerifiedOnChain();
      expect(isVerified).toBe(false);
    });

    test('should handle expired credentials for on-chain verification', async () => {
      // Configure mock to check expiration for this test only
      mockVerifyCredential.mockImplementationOnce((credential) => {
        // Check if credential is expired
        const expiresAt = new Date(credential.expiresAt || '');
        const now = new Date();
        return Promise.resolve(expiresAt > now);
      });
      
      const client = await createKYCClient();
      const expiredCredential = createMockCredential('expired-on-chain-cred', true);
      
      // Set expired credential (should be rejected due to our mock)
      const setResult = await client.setKYCCredential(expiredCredential);
      expect(setResult).toBe(false); // Should reject expired credential
      
      // Attempt to verify on-chain should fail
      await expect(client.submitKYCProof(['country'])).rejects.toThrow();
    });
  });
  
  describe('Safe Parameter Handling', () => {
    test('should safely handle invalid attribute names', async () => {
      // Reset mocks for this test
      mockVerifyCredential.mockReset().mockResolvedValue(true);

      const client = await createKYCClient();
      const credential = createMockCredential('safe-params-cred-1');
      
      // Mock blockchain service
      (client as any).blockchainService = {
        verifyKYCProofOnChain: jest.fn().mockResolvedValue({
          status: 1,
          blockNumber: 12345678,
          transactionHash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
        }),
        isUserVerified: jest.fn().mockResolvedValue(true),
        hasAttribute: jest.fn().mockResolvedValue(true)
      };
      
      // Set the credential
      const setResult = await client.setKYCCredential(credential);
      expect(setResult).toBe(true);
      
      // Test with too many attributes
      const tooManyAttributes = Array(25).fill(0).map((_, i) => `attr${i}`);
      await expect(client.submitKYCProof(tooManyAttributes)).rejects.toThrow();
      
      // Test with invalid attribute name (very long)
      const longAttributeName = 'a'.repeat(1000);
      await expect(client.hasAttributeOnChain(longAttributeName)).rejects.toThrow();
    });
    
    test('should safely handle invalid blockchain addresses', async () => {
      const client = await createKYCClient();
      
      // Mocks for testing
      (mockProvider.getSigner as jest.Mock).mockReturnValueOnce({
        getAddress: jest.fn().mockRejectedValue(new Error('Invalid address'))
      });
      
      // Should handle errors when getting connected address
      await expect(client.isVerifiedOnChain()).rejects.toThrow();
    });
  });
});
