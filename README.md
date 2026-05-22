# constitute-service-manager

Rust service lifecycle boundary for Constitution.

`constitute-service-manager` emits protocol-validated service-manager
operations, proof digests, and posture records for install, update, start, stop,
restart, release, rollback, secret readiness, health checks, and promotion.
It also emits a lab Linux contract-target fixture that keeps host-side gateway,
storage, service-manager, and NVR service slots separate from client-side
runtime/surface proof and protected lab automation posture.

It does not own service domain semantics. Services own domain execution;
protocol owns record grammar; fabric reduces host composition; the service
manager owns corporeal lifecycle coordination and proof posture.

Release and lifecycle posture consume source operation refs, source snapshots,
content-index refs, project/work refs, build runs/artifacts/proofs, release
candidate refs, and rollback refs as inputs owned by source, storage, build,
project, and release contracts. Service-manager uses those refs for lifecycle
preflight and host-fabric contribution evidence; it does not own source graph,
artifact storage, project workflow, or release semantics.

Fabric fulfillment plans can now be consumed as a role-scoped control preflight
for service-manager operations. This lets host-fabric posture approve, block,
or degrade a start/stop/update/proof decision without moving OS effects or
service-domain semantics into fabric.

## Commands

```powershell
cargo test
cargo run -- fixture lifecycle
cargo run -- fixture lab-target
cargo run -- operation --operation restart --state succeeded
cargo run -- init --state target/service-manager-state.json
cargo run -- run --state target/service-manager-state.json --operation start
cargo run -- run --state target/service-manager-state.json --operation restart --fabric-control-role hostServiceAdapter
cargo run -- status --state target/service-manager-state.json
```
