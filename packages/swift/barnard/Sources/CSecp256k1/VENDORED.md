# Vendored libsecp256k1

This target vendors bitcoin-core/secp256k1 release tag `v0.6.0`. The upstream
license is preserved at `vendor/COPYING`. Only the recovery module is enabled by
the Barnard shim; no platform framework or Foundation dependency is introduced.
