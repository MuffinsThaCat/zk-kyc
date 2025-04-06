/**
 * Type definitions for Nocturne components we're extending
 * This file contains interfaces that match Nocturne's actual implementation
 * but allows us to build our extension without direct dependencies
 */

// Core Nocturne types
export interface ViewingKey extends BigInt {}
export interface SpendingKey extends BigInt {}
export interface SpendPk extends BigInt {}

// Address types
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

export interface StealthAddressTrait {
  fromPoints(points: { h1: CanonAddress; h2: CanonAddress }): StealthAddress;
  toPoints(addr: StealthAddress): { h1: CanonAddress; h2: CanonAddress };
}

// BabyJubJub types for cryptographic operations
export interface AffinePoint {
  x: bigint;
  y: bigint;
}

export interface ExtendedPoint {
  toAffine(): AffinePoint;
  multiply(scalar: bigint): ExtendedPoint;
  equals(other: ExtendedPoint): boolean;
}

export interface BabyJubJubStatic {
  BasePointExtended: ExtendedPoint;
  BasePointAffine: AffinePoint;
  ExtendedPoint: {
    fromAffine(point: AffinePoint): ExtendedPoint;
  };
}

// NocturneViewer class that we'll extend
export interface NocturneViewer {
  vk: ViewingKey;
  vkNonce: bigint;
  canonicalAddress(): CanonAddress;
  canonicalStealthAddress(): StealthAddress;
  generateRandomStealthAddress(): StealthAddress;
  isOwnAddress(addr: StealthAddress): boolean;
}

// Asset and related types
export interface Asset {
  assetType: number;
  assetAddr: string;
  id: bigint;
}

export interface AssetWithBalance {
  asset: Asset;
  balance: bigint;
  numNotes: number;
}

export interface AssetTrait {
  erc20AddressToAsset(address: string): Asset;
  parseAssetType(type: string): number;
}

// NocturneDB and related types
export interface KVStore {
  clear(): Promise<void>;
  getString(key: string): Promise<string | undefined>;
  putString(key: string, value: string): Promise<void>;
}

export interface NocturneDB {
  kv: KVStore;
  getAllNotes(opts?: any): Promise<Map<string, any[]>>;
  getBalanceForAsset(asset: Asset, opts?: any): Promise<bigint>;
  latestSyncedMerkleIndex(): Promise<number | undefined>;
  latestCommittedMerkleIndex(): Promise<number | undefined>;
}

// Operation types
export interface OperationRequest {
  joinSplitRequests: any[];
  // Add other fields as needed
}

export enum OperationStatus {
  PENDING,
  SUCCEEDED,
  FAILED
}

export interface PreSignOperation {}
export interface SignedOperation {}

// Merkle prover
export interface SparseMerkleProver {
  getRoot(): bigint;
}

// Client-related interfaces
export interface SDKSyncAdapter {}

export interface EthToTokenConverter {}

export interface OpTracker {}

export interface NocturneConfig {
  handlerAddress: string;
  erc20s: Map<string, any>;
  finalityBlocks: number;
}

// Handler contract
export interface Handler {
  // Add methods as needed
}

export interface Handler__factory {
  connect(address: string, provider: any): Handler;
}

// Config loader
export function loadNocturneConfig(networkName: string): NocturneConfig {
  // This is just a type declaration - implementation would be provided by Nocturne
  return {} as NocturneConfig;
}

// NocturneClient class that we'll extend
export class NocturneClient {
  protected provider: any;
  protected config: NocturneConfig;
  protected handlerContract: Handler;
  protected merkleProver: SparseMerkleProver;
  protected db: NocturneDB;
  protected syncAdapter: SDKSyncAdapter;
  protected tokenConverter: EthToTokenConverter;
  protected opTracker: OpTracker;

  readonly viewer: NocturneViewer;
  readonly gasAssets: Map<string, Asset>;

  constructor(
    viewer: NocturneViewer,
    provider: any,
    configOrNetworkName: NocturneConfig | string,
    merkleProver: SparseMerkleProver,
    db: NocturneDB,
    syncAdapter: SDKSyncAdapter,
    tokenConverter: EthToTokenConverter,
    nullifierChecker: OpTracker
  ) {
    this.viewer = viewer;
    this.provider = provider;
    
    // Initialize with mock values for prototype
    this.config = typeof configOrNetworkName === 'string' 
      ? loadNocturneConfig(configOrNetworkName) 
      : configOrNetworkName;
    this.merkleProver = merkleProver;
    this.db = db;
    this.syncAdapter = syncAdapter;
    this.tokenConverter = tokenConverter;
    this.opTracker = nullifierChecker;
    this.handlerContract = {} as Handler;
    this.gasAssets = new Map();
  }

  // Basic methods every NocturneClient needs to have
  async clearDb(): Promise<void> {
    await this.db.kv.clear();
  }

  async sync(opts?: any): Promise<number | undefined> {
    // Mock implementation for prototype
    return 0;
  }

  async getAllAssetBalances(opts?: any): Promise<AssetWithBalance[]> {
    // Mock implementation for prototype
    return [];
  }

  async getBalanceForAsset(asset: Asset, opts?: any): Promise<bigint> {
    // Mock implementation for prototype
    return BigInt(0);
  }
}
