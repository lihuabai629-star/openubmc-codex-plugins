# 2.1.9

Windows process probes reuse the standard `ctypes.wintypes.FILETIME` type. Repeated
probes no longer retain a new structure and pointer type in the ctypes cache.
Process creation identities and handle cleanup retain their existing behavior.

MCP processes with unknown ownership now honor the configured idle timeout.
Shutdown uses the process-local active request count and starts the idle interval
after the last accepted response has finished. Persisted zero-request records do
not authorize terminating a running process.

Version 2.1.8 is reserved for the local sidebar preview; this maintenance release
updates the public 2.1.7 package.
