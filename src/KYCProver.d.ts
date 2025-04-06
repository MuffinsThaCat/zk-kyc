import { KYCCredential, KYCProof, KYCProverConfig } from "./types";

export declare class KYCProver {
  constructor(config: KYCProverConfig);
  
  generateProof(
    credential: KYCCredential,
    attributesToReveal?: string[],
    viewingKey?: bigint
  ): Promise<KYCProof>;
  
  verifyCredential(credential: KYCCredential): Promise<boolean>;
  
  verifyProof(proof: any, publicSignals: any): Promise<boolean>;
}
