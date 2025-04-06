// Declare Nocturne modules
declare module '@nocturne-xyz/client' {
  export * from '@nocturne-xyz/client/dist/index';
}

declare module '@nocturne-xyz/crypto' {
  export * from '@nocturne-xyz/crypto/dist/index';
}

declare module '@nocturne-xyz/core' {
  export * from '@nocturne-xyz/core/dist/index';
}

declare module '@nocturne-xyz/config' {
  export * from '@nocturne-xyz/config/dist/index';
}

declare module '@nocturne-xyz/contracts' {
  // For Handler__factory
  export const Handler__factory: any;
}

// Declare client source modules
declare module '@nocturne-xyz/client/src/OpTracker' {
  export * from '@nocturne-xyz/client/dist/OpTracker';
}

declare module '@nocturne-xyz/client/src/NocturneDB' {
  export * from '@nocturne-xyz/client/dist/NocturneDB';
}

declare module '@nocturne-xyz/client/src/conversion' {
  export * from '@nocturne-xyz/client/dist/conversion';
}

// Declare crypto source modules
declare module '@nocturne-xyz/crypto/src/keys' {
  export interface ViewingKey extends BigInt {}
}

declare module '@nocturne-xyz/crypto/src/address' {
  export interface CanonAddress {
    x: bigint;
    y: bigint;
  }
  
  export interface StealthAddress {
    h1X: bigint;
    h1Y: bigint;
    h2X: bigint;
    h2Y: bigint;
  }
  
  export const StealthAddressTrait: any;
}

// Declare external modules
declare module 'snarkjs' {
  export const groth16: {
    fullProve: (input: any, wasmFile: string, zkeyFile: string) => Promise<{ proof: any, publicSignals: any }>;
    verify: (verificationKey: any, publicSignals: any, proof: any) => Promise<boolean>;
  };
}

declare module 'bigint-json-serialization' {
  export function parse(json: string): any;
  export function stringify(obj: any): string;
}
