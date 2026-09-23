# Schema

This directory contains **language-agnostic** schemas for Barnard.

Goals
- Keep Dart / Swift / Kotlin / JS implementations consistent without sharing code across languages
- Define stable event/config/capabilities shapes for upper layers (Flutter/RN/etc.)
- Enable conformance testing via shared test vectors

Layout
- `schema/barnard/v1/`: Barnard v1 JSON Schemas
- `schema/barnard/v2/`: Barnard v2 JSON Schemas for event streams, permissions, and shared types
- `schema/barnard/v2/b005-envelope-verifier.schema.json`: strict offline verifier CLI request and
  six-field V1 receipt; a success indicates radio self-verification, not registry confirmation
