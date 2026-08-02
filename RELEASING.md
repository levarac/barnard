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

## GitHub release notes

Two layers, split deliberately so no API key or paid inference dependency is
needed (GitHub Models, the original zero-config backend, was retired on
2026-07-30):

1. **Facts, automated.** Pushing a `vX.Y.Z` tag triggers the **Release Notes**
   workflow (`.github/workflows/release-notes.yml`), which creates the GitHub
   Release for that tag using only `GITHUB_TOKEN`: PRs, resolved issues, and
   `specs/` changes since the previous version tag, plus the changelog link.
   This always succeeds on its own and is the factual source of truth.
2. **Summary prose, drafted at release time.** Whoever drives the release —
   in practice the maintainer's agent session that pushes the tag — drafts a
   short summary (Highlights, protocol changes, what's new; breaking changes
   called out prominently when present) on top of the generated facts and
   applies it with `gh release edit vX.Y.Z --notes-file <file>`, keeping the
   generated facts in a collapsible details section and attributing the
   drafted summary in the body. The v0.1.0–v0.3.0 releases follow this shape;
   use them as the template.

To regenerate the factual notes for an existing tag (or backfill an old one),
run the workflow manually from the **Actions** tab: pick **Release Notes**,
enter the tag, and leave **dry run** on to preview first. **Warning:** a
non-dry re-run replaces the whole release body, including any drafted summary
— re-apply the summary afterwards. The summary is a draft, not an authority;
review it after each release.

## Publishing the Android library to Maven Central

After the release tag is pushed and the one Maven Central credential secret
(`MAVEN_CENTRAL_TOKEN_B64`, base64-encoded `username:password`) plus the two GPG
signing secrets are configured, open **Actions**, select **Publish Maven
Central**, choose that release tag in **Run workflow**, and run it. The workflow publishes
`org.levarac:barnard` using the version derived from the selected `vX.Y.Z` tag.

After the workflow succeeds, open [Maven Central](https://central.sonatype.com/)
and verify that the deployment contains the expected version, POM metadata, AAR,
sources JAR, javadoc JAR, and signatures. The workflow automatically releases
the validated deployment; no further Central Portal publish action is required.

For a local fallback, put `mavenCentralUsername`, `mavenCentralPassword`,
`signingInMemoryKey`, and `signingInMemoryKeyPassword` in
`~/.gradle/gradle.properties`. Then run the manual Maven Central publish command
from `packages/android/barnard`; it uses the same automatic release behavior.

Revisit whole-monorepo versioning if repository size grows enough to hurt
consumer fetches or if platforms genuinely need divergent versioning. At that
point, evaluate a CI-published distribution repository.
