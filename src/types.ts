/**
 * Status of the KYC verification process
 */
export enum VerificationStatus {
  UNVERIFIED = "UNVERIFIED", // Not yet verified
  PENDING = "PENDING",       // Verification in progress
  VERIFIED = "VERIFIED",     // Successfully verified
  INVALID = "INVALID",       // Verification failed
  ERROR = "ERROR"            // Error during verification process
}

/**
 * Represents a KYC credential issued by a trusted provider
 */
export interface KYCCredential {
  id: string;                // Unique identifier for the credential
  issuer: string;            // Issuer of the credential (e.g., KYC provider)
  subject: string;           // Subject identifier (e.g., hash of user's ID)
  issuedAt: string;          // ISO timestamp when the credential was issued
  expiresAt?: string;        // Optional expiration timestamp
  attributes: {              // KYC attributes that can be selectively disclosed
    [key: string]: any;      // e.g., "over18": true, "country": "US"
  };
  proof: {                   // Cryptographic proof from the issuer
    type: string;            // Type of proof (e.g., "Ed25519Signature2020")
    created: string;         // When the proof was created
    verificationMethod: string; // Method to verify this proof
    proofPurpose: string;    // Purpose of this proof
    proofValue: string;      // The actual cryptographic proof value
  };
}

/**
 * Configuration for the KYC prover
 */
export interface KYCProverConfig {
  circuitPath: string;       // Path to the compiled zk-SNARK circuit
  provingKeyPath: string;    // Path to the proving key
  verificationKeyPath: string; // Path to the verification key
  issuerPublicKeys: {        // Public keys of trusted KYC issuers
    [issuer: string]: string;
  };
}

/**
 * Input for generating a KYC proof
 */
export interface KYCProofInput {
  credential: KYCCredential;
  revealedAttributes: string[];
  viewingKey: bigint;
}

/**
 * Output of the KYC proof generation
 */
export interface KYCProof {
  proof: any;               // zkSNARK proof
  publicSignals: any;       // Public signals from the proof
  revealedAttributes: {     // Values of the revealed attributes
    [key: string]: any; 
  };
}

/**
 * Parameters for initializing a KYC client
 */
export interface KYCClientParams {
  nocturneViewerParams: {
    viewingKey: bigint;
    nonce: bigint;
  };
  kycProverConfig: KYCProverConfig;
}
