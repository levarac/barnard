# Schema

This directory contains **language-agnostic** schemas for Barnard.

Goals
- Keep Dart / Swift / Kotlin / JS implementations consistent without sharing code across languages
- Define stable event/config/capabilities shapes for upper layers (Flutter/RN/etc.)
- Enable conformance testing via shared test vectors

Layout
- `schema/barnard/v1/`: Barnard v1 JSON Schemas
- `schema/barnard/v2/`: Barnard v2 JSON Schemas for event streams, permissions, and shared types
