# TODO

* Improve wallet reshare operation (needs updates in the TSS library)
* Solana SPL sends: port the Token-2022 transfer-fee path and simulation-based
  compute-unit sizing (currently a fixed CU limit; fee-extension mints 501)
* mpurse_sendAsset: validate the Counterparty `create_send` contract against a
  live node and settle the default endpoint
* Bitcoin transaction-history provider (backfill is EVM/Solana only)
* Author Rust cross-compile release steps for any remaining targets (Windows)
