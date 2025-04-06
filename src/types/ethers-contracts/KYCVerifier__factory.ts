import { ethers } from 'ethers';

// KYCVerifier contract ABI
const KYCVerifierABI = [
  // Events
  "event KYCVerified(address indexed user, bytes32 proofHash)",
  "event IssuerAdded(address indexed issuer)",
  "event IssuerRemoved(address indexed issuer)",
  "event AdminChanged(address indexed oldAdmin, address indexed newAdmin)",
  "event VerifierChanged(address indexed oldVerifier, address indexed newVerifier)",
  "event AttributeVerified(address indexed user, string attributeName, bool value)",
  
  // View functions
  "function admin() view returns (address)",
  "function trustedIssuers(address) view returns (bool)",
  "function verifiedUsers(address) view returns (bool)",
  "function groth16Verifier() view returns (address)",
  "function isUserVerified(address _user) view returns (bool)",
  "function hasAttribute(address _user, string calldata _attributeName) view returns (bool)",
  
  // Admin functions
  "function changeAdmin(address _newAdmin)",
  "function addTrustedIssuer(address _issuer)",
  "function removeTrustedIssuer(address _issuer)",
  "function updateVerifier(address _newVerifier)",
  
  // Main verification function
  "function verifyKYCProof(uint256[] calldata _proof, uint256[] calldata _publicSignals, string[] calldata _revealedAttributes) returns (bool)"
];

/**
 * Factory class for creating KYCVerifier contract instances
 */
export class KYCVerifier__factory {
  /**
   * Create a new KYCVerifier contract connected to the given address
   * @param address Contract address
   * @param signerOrProvider Signer or provider to use for transactions
   * @returns Connected contract instance
   */
  static connect(
    address: string,
    signerOrProvider: ethers.Signer | ethers.providers.Provider
  ): ethers.Contract {
    return new ethers.Contract(address, KYCVerifierABI, signerOrProvider);
  }
  
  /**
   * Deploy a new KYCVerifier contract
   * @param signer Signer to deploy with
   * @param admin Admin address
   * @param initialIssuers Initial trusted issuers
   * @param verifierAddress Address of the Groth16 verifier contract
   * @returns Deployed contract instance
   */
  static async deploy(
    signer: ethers.Signer,
    admin: string,
    initialIssuers: string[],
    verifierAddress: string
  ): Promise<ethers.Contract> {
    // Create contract factory
    const factory = new ethers.ContractFactory(
      KYCVerifierABI,
      "0x608060...", // Bytecode would be here in a real implementation
      signer
    );
    
    // Deploy contract
    const contract = await factory.deploy(admin, initialIssuers, verifierAddress);
    
    // Wait for deployment
    await contract.deployed();
    
    return contract;
  }
}
