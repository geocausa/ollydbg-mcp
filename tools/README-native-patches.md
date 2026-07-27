# Native hardening patch helpers

The two scripts in this directory apply exact, one-time source transformations to the legacy OllyDbg 1.10 plugin source. Each replacement requires exactly one matching source block and aborts otherwise, preventing a partial patch when the native source changes unexpectedly.

They are retained to make the generated C changes auditable and reproducible. They are not part of the runtime bridge.
