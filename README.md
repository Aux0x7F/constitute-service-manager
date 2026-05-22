# constitute-service-manager

Rust service lifecycle boundary for Constitution.

`constitute-service-manager` emits protocol-validated service-manager
operations, proof digests, and posture records for install, update, start, stop,
restart, release, rollback, secret readiness, health checks, and promotion.

It does not own service domain semantics. Services own domain execution;
protocol owns record grammar; fabric reduces host composition; the service
manager owns corporeal lifecycle coordination and proof posture.

## Commands

```powershell
cargo test
cargo run -- fixture lifecycle
cargo run -- operation --operation restart --state succeeded
cargo run -- init --state target/service-manager-state.json
cargo run -- run --state target/service-manager-state.json --operation start
cargo run -- status --state target/service-manager-state.json
```
