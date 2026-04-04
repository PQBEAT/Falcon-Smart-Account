# Account Abstraction with Falcon Signatures

This repository is a proof-of-concept adaptation of the ERC-4337 account-abstraction codebase. It keeps the standard `EntryPoint` and `SimpleAccount` stack from Infinitism and adds an experimental Falcon-based account implementation to explore post-quantum signature verification inside the ERC-4337 execution model.

In practice, this repo is best understood as two things at once:

- a working ERC-4337 reference-style sandbox built around the usual `EntryPoint` flow
- a Falcon signature experiment layered on top of that base

## What Is In This Repo

- Core ERC-4337 contracts: `EntryPoint`, `BaseAccount`, paymaster, nonce, staking, and sender-creation infrastructure
- Standard sample account path: `SimpleAccount` plus `SimpleAccountFactory`
- Falcon experiment: `FalconSimpleAccount` plus `ZKNOX_*` verification helpers
- TypeScript tooling for packing, signing, simulating, and sending `UserOperation`s
- Hardhat deploy scripts, runtime demo scripts, gas measurement scripts, and tests

The package metadata under [`contracts/package.json`](contracts/package.json) still tracks the Infinitism `account-abstraction` package lineage, while this repository's root setup and tests introduce the Falcon-specific work.

## Project Intent

The standard ERC-4337 code in this repo is the foundation. The Falcon work is an experiment that uses the account-abstraction model to swap the normal ECDSA account validation step for Falcon verification.

That distinction matters because:

- the default deploy scripts still deploy the standard `SimpleAccount` flow
- the TypeScript runtime helpers still target the standard account/factory path
- the Falcon path currently lives in a dedicated sample contract and a focused test

So this is not a fully Falcon-native account-abstraction stack yet. It is a standard ERC-4337 codebase with an experimental Falcon account implementation.

## High-Level Architecture

At a high level, the execution flow is:

1. A `UserOperation` is assembled in TypeScript.
2. The operation is packed and hashed according to the ERC-4337 domain.
3. A bundler, local sender, or test harness submits it to `EntryPoint`.
4. `EntryPoint` validates prefund, nonce, paymaster data, and calls `account.validateUserOp(...)`.
5. The account implementation decides whether the signature scheme is valid.
6. If validation passes, `EntryPoint` executes the requested call and charges gas from deposit/prefund.

The key extension point is the account's `_validateSignature(...)` implementation:

- `SimpleAccount` uses ECDSA recovery
- `FalconSimpleAccount` attempts Falcon verification through the ZKNOX helper contracts

## Main Contract Areas

### Core ERC-4337 contracts

- [`contracts/core/EntryPoint.sol`](contracts/core/EntryPoint.sol): singleton entry point for validation, execution, fee accounting, and bundler-facing flows
- [`contracts/core/BaseAccount.sol`](contracts/core/BaseAccount.sol): shared account-side `validateUserOp` skeleton
- [`contracts/core/BasePaymaster.sol`](contracts/core/BasePaymaster.sol): paymaster foundation
- [`contracts/core/NonceManager.sol`](contracts/core/NonceManager.sol): nonce handling
- [`contracts/core/StakeManager.sol`](contracts/core/StakeManager.sol): deposits and stake lifecycle
- [`contracts/core/SenderCreator.sol`](contracts/core/SenderCreator.sol): controlled account deployment helper

### Standard account path

- [`contracts/samples/SimpleAccount.sol`](contracts/samples/SimpleAccount.sol): UUPS-upgradeable sample smart account that validates with ECDSA
- [`contracts/samples/SimpleAccountFactory.sol`](contracts/samples/SimpleAccountFactory.sol): deterministic ERC1967 proxy factory for `SimpleAccount`
- [`deploy/1_deploy_entrypoint.ts`](deploy/1_deploy_entrypoint.ts): deploys `EntryPoint`
- [`deploy/2_deploy_SimpleAccountFactory.ts`](deploy/2_deploy_SimpleAccountFactory.ts): deploys `SimpleAccountFactory` and `TestCounter` on local networks

### Falcon account path

- [`contracts/samples/FalconSimpleAccount.sol`](contracts/samples/FalconSimpleAccount.sol): sample account that stores Falcon public-key material and uses Falcon verification during `validateUserOp`
- [`contracts/samples/ZKNOX_falcon.sol`](contracts/samples/ZKNOX_falcon.sol): Falcon verification logic
- [`contracts/samples/ZKNOX_NTT.sol`](contracts/samples/ZKNOX_NTT.sol): NTT-related math used by the Falcon verifier
- [`contracts/samples/HashToPoint_ZKNOX.sol`](contracts/samples/HashToPoint_ZKNOX.sol): hash-to-point helper
- [`contracts/samples/FalconConstants.sol`](contracts/samples/FalconConstants.sol): constants used by the Falcon implementation

## TypeScript Tooling

- [`test/UserOp.ts`](test/UserOp.ts): pack, hash, fill, and sign user operations
- [`test/testutils.ts`](test/testutils.ts): shared test helpers, deploy helpers, revert decoding, funding helpers
- [`src/AASigner.ts`](src/AASigner.ts): account-abstraction aware signer and user-op senders
- [`src/runop.ts`](src/runop.ts): runnable example that deploys default contracts when needed and sends a sample operation
- [`src/Create2Factory.ts`](src/Create2Factory.ts): deterministic deployment helper

The current TypeScript tooling is centered on the standard `SimpleAccount` path. The Falcon path is not yet wired into `AASigner`, the standard factory flow, or the default runtime script.

## Repository Layout

```text
contracts/
  core/         ERC-4337 core contracts
  interfaces/   contract interfaces and packed user-op types
  legacy/       compatibility interfaces for older versions
  samples/      sample accounts, callback handlers, Falcon experiment
  test/         Solidity test helper contracts
deploy/         hardhat-deploy scripts
src/            runtime helpers and demo script
test/           Hardhat/TypeScript test suite
gascalc/        gas-reporting tests and helpers
audits/         audit PDFs included with the repo
reports/        generated gas checker output
scripts/        wrappers, packaging scripts, gas scripts
```

## Setup

### Required sibling dependency

This repository depends on a local sibling package:

```json
"falcon-sign": "file:../falcon-sign-js"
```

You need to clone it first:

```bash
cd ..
git clone https://github.com/asanso/falcon-sign-js.git
cd account-abstraction
yarn install
```

The original short README note about this dependency is important: without `../falcon-sign-js`, `yarn install` will fail.

### Optional environment variables

The repo can also use these environment variables:

- `MNEMONIC_FILE`: file containing the mnemonic for configured non-local networks
- `INFURA_ID`: Infura project id for the configured `goerli` and `sepolia` networks
- `ETHERSCAN_API_KEY`: verification key for Etherscan plugin usage
- `SALT`: deterministic deployment salt override
- `AA_URL`: external endpoint supporting `eth_sendUserOperation` for `src/runop.ts`
- `AA_INDEX`: account index used by `AASigner`

## Common Commands

```bash
yarn compile
yarn test
yarn test test/falcon-simple-wallet.test.ts
yarn run runop
yarn gas-calc
yarn coverage
yarn lint
```

What those commands do:

- `yarn compile`: compile contracts through the Hardhat wrapper
- `yarn test`: run the Hardhat test suite
- `yarn test test/falcon-simple-wallet.test.ts`: run the Falcon-focused validation test
- `yarn run runop`: run the demo AA flow using the default `SimpleAccount` setup
- `yarn gas-calc`: generate gas reports
- `yarn coverage`: run Solidity coverage
- `yarn lint`: run Solidity and JS/TS linting

## What Is Well Integrated Today

- The core ERC-4337 `EntryPoint` flow
- The standard `SimpleAccount` and `SimpleAccountFactory` path
- Local deployment via `hardhat-deploy`
- TypeScript helpers for packing, signing, and sending standard user operations
- Extensive upstream-style tests for entry point, paymaster, gas, and account behavior

## Falcon-Specific Status

The Falcon work is the distinctive part of this repository, but it is still experimental.

Today, the Falcon path looks like this:

- `FalconSimpleAccount` stores Falcon public-key data on the account
- verification is delegated to the `ZKNOX_falcon` helper stack
- the main Falcon sanity coverage is in [`test/falcon-simple-wallet.test.ts`](test/falcon-simple-wallet.test.ts)
- the Falcon account is manually deployed in the test rather than deployed through the default factory path

## Current Caveats And Limitations

- The default deployment flow does not deploy a Falcon factory or Falcon account.
- The default runtime tooling still assumes the standard `SimpleAccount`.
- The Falcon validation path currently contains a temporary workaround for signature encoding compatibility between `falcon-sign-js` and the Solidity verifier.
- In the current Falcon test flow, `userOp.callData` is reused to carry Falcon salt into the verifier.
- The Falcon test directly exercises `validateUserOp` on a manually deployed proxy-backed account rather than a fully integrated factory-plus-bundler path.

That means the Falcon code should be treated as a proof of concept rather than a production-ready account implementation.

## Test Suite Shape

The test suite mixes several layers of coverage:

- core ERC-4337 behavior tests such as [`test/entrypoint.test.ts`](test/entrypoint.test.ts)
- standard account behavior tests such as [`test/simple-wallet.test.ts`](test/simple-wallet.test.ts)
- helper and utility tests
- a Falcon-specific validation test in [`test/falcon-simple-wallet.test.ts`](test/falcon-simple-wallet.test.ts)

CI is configured in [`.github/workflows/build.yml`](.github/workflows/build.yml) to run compile, typecheck, tests, gas checks, lint, and coverage.




