# Nocturne ZK-KYC

Zero-knowledge KYC verification for Nocturne protocol with safe parameter handling.

## Overview

This repository contains an implementation of a zero-knowledge KYC (Know Your Customer) verification system for the Nocturne privacy protocol. It enables on-chain verification of KYC credentials without revealing sensitive identity information.

## Key Features

- **Zero-Knowledge Proofs**: Verify identity credentials without revealing personal information
- **On-Chain Verification**: Submit proofs to blockchain for compliance verification
- **Selective Disclosure**: Control which attributes from credentials are revealed
- **Safe Parameter Handling**: Comprehensive validation for all inputs to prevent security vulnerabilities

## Safe Parameter Handling

The implementation includes robust parameter validation techniques:

- Bounds checking for all array lengths and string sizes
- BigInt value validation to prevent overflow attacks
- Input sanitization for all user-provided data
- Fallback mechanisms that gracefully handle validation failures
- Comprehensive logging for security monitoring

## Architecture

- **KYCClient**: Main client interface for managing KYC credentials and verification
- **KYCViewer**: Interface for managing and displaying KYC credentials
- **KYCProver**: Generates zero-knowledge proofs for KYC verification
- **BlockchainService**: Handles on-chain verification of ZK proofs
- **CredentialStorage**: Secure storage for KYC credentials

## Integration

This component is designed to integrate with the Nocturne privacy protocol, providing a regulatory compliance layer while maintaining user privacy through zero-knowledge proofs and relayer infrastructure.

## Security

Security is a primary focus in this implementation, with extensive validation of all parameters to prevent common vulnerabilities:
- Buffer overflow protection
- Integer overflow prevention
- Proper error handling with fallbacks
- Strict validation of credential formats

## License

MIT
