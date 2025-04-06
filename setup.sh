#!/bin/bash

# Install dependencies
npm install

# Install required type declarations
npm install --save-dev @types/node

# Link local Nocturne packages
npm link ../monorepo/packages/client
npm link ../monorepo/packages/config
npm link ../monorepo/packages/core
npm link ../monorepo/packages/crypto
npm link ../monorepo/packages/contracts

# Create necessary directories
mkdir -p dist
mkdir -p scripts
