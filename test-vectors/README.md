# Cross-language conformance vectors

This directory holds golden test vectors shared between Barnard's
per-platform implementations. Every value in every file here is computed
from the Swift `BarnardCore` reference implementation
(`packages/swift/barnard/Sources/BarnardCore`) and consumed byte-for-byte
by the test suites of every other implementation (starting with
`packages/android/barnard`'s Kotlin implementation).

## Why this exists

Some Barnard packages are C-ABI bindings to `BarnardCore` and inherit its
behavior automatically. Others, like `packages/android/barnard`, are
independent, hand-written implementations of the same protocol. An
independent implementation's own test suite can only prove
self-consistency: that its output matches what it itself computed as
"expected." It cannot prove the implementation agrees with the Swift
reference it is meant to mirror.

Files in this directory close that gap. Both the Swift test suite and every
other consuming test suite load the same vector file, run their own
implementation of each primitive against the vector's pinned inputs, and
assert the outputs match the vector's pinned expected values. A regression
or intentional-but-unsynchronized change in either implementation then
fails a test, rather than silently drifting.

See `specs/133-android-owner-key/spec.md` for the spec that introduced this
convention, and `specs/092-owner-key/spec.md` for the normative protocol
definitions the `owner-key-v1.txt` vectors pin.

## File format

Each vector file (e.g. `owner-key-v1.txt`) follows this format:

- Encoding: UTF-8, LF (`\n`) line endings only. No trailing CR anywhere.
- A blank line, or a line whose first character is `#`, is a comment and is
  ignored by parsers. Comments may appear anywhere and are used in these
  files to document which pinned Swift test (if any) a group of vectors was
  copied from, and what fixed inputs produced them.
- Every other line MUST be exactly one `key=value` pair:
  - `key` matches the regular expression `[A-Za-z0-9_]+` (ASCII letters,
    digits, and underscore only — no spaces, no dots).
  - `=` is the first `=` character on the line.
  - `value` is everything after that first `=`, to the end of the line
    (excluding the line's own trailing `\n`). A value MAY itself contain
    `=` characters; only the first `=` on the line is the key/value
    separator.
  - A line that does not match this shape (no `=`, or a key containing a
    character outside `[A-Za-z0-9_]`) is a malformed file; parsers should
    fail loudly rather than skip it silently.
- Two escape sequences are recognized in `value`, and no others:
  - `\n` (backslash, `n`) decodes to a single newline byte (`0x0a`).
  - `\\` (two backslashes) decodes to a single literal backslash byte
    (`0x5c`).
  - A backslash not immediately followed by `n` or `\` is malformed input.
    Barnard's vector values are hex strings, decimal integers, ASCII domain
    names, RFC 3339 timestamps, and canonical multi-line protocol text —
    none of which need any other escape sequence, so no other escape is
    defined.
- When *encoding* a value (producing a vector file from freshly computed
  values, e.g. when adding a new vector file), escape backslash first, then
  newline, in that order: `\` becomes `\\`, then every newline byte becomes
  `\n`. Doing it in this order, and decoding in the reverse order (`\n`
  before `\\`), keeps the two operations exact inverses of each other with
  no ambiguity about a literal `\n` two-character sequence in the original
  value versus an encoded newline.
- All hex-encoded values are lowercase with no `0x` prefix. Where a `0x`
  prefix appears inside a decoded value (for example inside a pinned
  canonical binding-text value), that `0x` is literal text content from the
  protocol's own wire/text format, not a vector-encoding artifact.

## Adding a new vector file

1. Name it `<primitive-family>-v<n>.txt` (e.g. `owner-key-v1.txt`). Bump
   `<n>` only if a later spec needs a second, incompatible generation of
   vectors for the same primitive family; otherwise add new keys to the
   existing file.
2. Compute every value by actually running the Swift `BarnardCore`
   reference implementation against fixed, documented inputs — never by
   hand-transcribing or hand-deriving a cryptographic output. Where a value
   is already pinned in an existing Swift test (e.g.
   `packages/swift/barnard/Tests/BarnardCoreTests/`), copy it verbatim and
   comment which test it came from; where it is not yet pinned anywhere,
   generate it with a throwaway `print()` in a scratch test, capture the
   output, and delete the scratch code before committing.
3. Document, in comments at the top of each vector group, which fixed
   inputs and (if applicable) which existing pinned Swift test the group's
   values were reused from, so a future contributor can regenerate or
   extend the group without guessing.
4. Add a consuming test in every implementation's test suite that loads the
   file, parses it per this format, and asserts its own primitive outputs
   against the vector's expected values.
