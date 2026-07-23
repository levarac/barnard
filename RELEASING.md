# Releasing Barnard

Barnard uses whole-monorepo semantic versions. A `vX.Y.Z` tag identifies the
same protocol semantics across the Swift, Kotlin, Dart, and React Native
packages.

After the release commit is merged into `main`, create and push the release tag:

```sh
git tag vX.Y.Z && git push origin vX.Y.Z
```

The first `v0.1.0` tag will be cut by the project lead after the root Swift
package manifest is merged.

Revisit whole-monorepo versioning if repository size grows enough to hurt
consumer fetches or if platforms genuinely need divergent versioning. At that
point, evaluate a CI-published distribution repository.
