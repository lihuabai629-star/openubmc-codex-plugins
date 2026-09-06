# Publish Mode

Use only for explicit remote publication of a planned package.

## Required inputs

- package identity and local evidence;
- exact publish argv;
- named remote and stage/channel;
- explicit authorization to perform the remote write.

Verify Conan authentication using [../conan-auth.md](../conan-auth.md). Preserve the supplied argv and record publication as its own Plan and Attempt.

Publishing does not create an HPM and does not connect to a BMC.

## Completion

The intended package identity was published to the named remote, or the Attempt failed with preserved evidence. No alternate remote or local-source substitution is implicit.
