# Handwritten Lua Components

Use the component's real runtime flow to locate ownership. Common layers include
Skynet entrypoints, generated service initialization, adapters, services,
domain modules, persistence, and modeled objects; directory names vary by
repository.

## Establish the observable contract

Trace:

```text
caller or event
  -> exported Lua function, callback, or RPC
  -> service/domain rule
  -> modeled property, signal, persistence, hardware, result, or error
```

Record the applicable inputs, nil/default behavior, multi-return shape, errors,
side effects, and lifecycle. Keep generated callbacks and protocol adapters
thin, and place reusable rules in the existing source owner.

## Preserve modeled-object integrity

Treat generated model and ORM instances as closed shapes. Store private caches,
coordination flags, and pending-operation state in the owning service,
collection, or a map keyed by stable object identity. Use strict test doubles
that reject undeclared properties.

Preserve caller context, privilege, modeled error conversion, object identity,
and asynchronous completion semantics. Keep per-host, per-board, and per-device
state separate unless the runtime contract is genuinely singleton.

## Follow lifecycle and concurrency

Inspect the generated base and nearby components for the actual `ctor`,
`pre_init`, `init`, `start`, teardown, reboot, and exit ordering.

- Register signals and background work in an order that cannot expose a false
  ready state.
- Use framework task and lifecycle helpers rather than unmanaged coroutines.
- Treat message delivery as distinct from business completion.
- Bound queues, retries, and externally influenced work.
- Define cancellation, late callback, replacement, restart, and stale-cache
  behavior where they affect callers.
- Keep lock behavior explicit around sleep, MDB calls, callbacks, and hardware
  access.

## Handle errors and inputs

Use one failure protocol per public function and one conversion point at the
framework edge. Validate external files, configuration, RPC payloads, network
data, and hardware results before indexing, allocation, path construction, or
execution.

Prefer structured process interfaces to shell composition. Keep credentials,
tokens, sensitive properties, and complete sensitive requests out of logs.
Include component, object, action, outcome, and correlation data when useful.

## Inspect persistence code generation

Read both the authored model and the generated Lua database code when a Lua
persistence lifetime or Retain behavior matters. Confirm the generator's
current mapping rather than normalizing names from memory. Keep persistence
compatibility conclusions tied to the language/runtime implementation that will
consume the model.

## Test the behavior seam

Preserve a focused failing example before changing a defect when the repository
has a practical seam. Test exported behavior, not private helpers or callback
ordering.

Match real nil/default, multi-return, exception, and asynchronous shapes in
test adapters. Restore replaced modules, globals, package cache entries,
singletons, timers, and subscriptions. Cover material cases such as an event
arriving during refresh, stale completion, partial startup, cleanup, retry
exhaustion, idempotent start/stop, restart, replacement, and hotplug.
