Instructions to run:

1. Start firestore server from aptos-core/: gcloud emulators firestore start --host-port=localhost:8081
2. Start pepper service from aptos-core/: cargo run -p aptos-keyless-pepper-service
3. Start prover-service (zk-contract) prover-service/: cargo run | grep 'selected,'

1. To initiate a voting round from keyless-voting/: cargo run -- init --election-id test --prover-key dummy_prover.key --verifier-key dummy_verifier.key
2. To register user from keyless-voting/: cargo run -- register --election-id test