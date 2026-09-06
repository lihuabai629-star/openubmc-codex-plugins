# MDB, MDS, and Modeled Contracts

Treat modeled contracts as public behavior shared by interface definitions,
component MDS inputs, generators, language bindings, and direct consumers.

## Locate the authored contract

Inspect the forms present in the target version:

- interface JSON beneath the `mdb_interface` hierarchy;
- component `model.json`, `types.json`, `service.json`, `datas.yaml`, or IPMI
  model inputs;
- legacy Proto-style request/response definitions and generated type validators;
- generated Lua/C++ bindings used by direct callers.

Generated `proto_property`, validators, bindings, or model classes reveal the
deployed shape but remain derivatives. Trace them back to the authored interface
or model input before editing.

Confirm the applicable contract:

```text
identity: resource path, hierarchy, variables, and object lifetime
member: property, method, signal, request, response, or modeled error
data: type, signature, enum, range, format, default, and nullability
behavior: sync/async, timeout, idempotency, ordering, and partial success
access: privilege, sensitivity, visibility, and lock behavior
persistence: lifetime, table/key, alias, migration, and import/export
compatibility: current consumers, mixed versions, upgrade, and rollback
```

## Evolve the contract

Search current definitions before adding a member. Extend the existing owner
when the concept already exists. Keep private component state out of shared
interfaces, and keep defaults inside declared validation ranges.

For removal, rename, path, type/signature, permission, persistence, or request
shape changes, define old/new interoperability and rollback behavior first.
Update only consumers whose behavior actually depends on the changed contract.

For legacy Proto-style models, verify both the authored request/response
definition and the generated validation shape. Preserve unknown-field policy,
required fields, enum conversion, sensitive values, and error compatibility.

## Keep generation coherent

Record each authored input, expected generated output, generator, and consuming
language. Treat a successful compiler or package command as separate from
generator completeness.

When generation is part of the accepted source outcome:

1. validate the authored definition;
2. run the source-stage generator;
3. inspect created, replaced, deleted, empty, and truncated outputs;
4. compare sibling language bindings where more than one runtime consumes the
   contract;
5. run focused contract and consumer validation.

## Validate compatibility

Run repository schema, JSON, lint, formatting, and contract validators that
cover the changed definition. Confirm they selected the intended interface or
model. Inspect direct consumers for semantic assumptions that a schema cannot
prove, including default handling, method completion, path identity, and errors.
