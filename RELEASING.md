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

## GitHub release notes (automated)

Pushing a `vX.Y.Z` tag triggers the **Release Notes** workflow
(`.github/workflows/release-notes.yml`), which creates the GitHub Release for
that tag automatically: it collects the PRs, resolved issues, and `specs/`
changes since the previous version tag, drafts a summary with a GitHub Model,
and attaches the raw generated facts in a collapsible section. If the AI pass
is unavailable the release is still created with the raw notes.

To regenerate notes for an existing tag (or backfill an old one), run the
workflow manually from the **Actions** tab: pick **Release Notes**, enter the
tag, and leave **dry run** on to preview in the run summary first; re-run with
dry run off to create or update the release. Review the generated text after
each release — the AI summary is a draft, not an authority.

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
