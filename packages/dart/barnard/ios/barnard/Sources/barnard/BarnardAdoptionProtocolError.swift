// Use of this source code is governed by a BSD-style license.

/// Errors raised while decoding or binding the versioned AdoptionCredential
/// and SignedWindowCensus artifacts. These errors deliberately distinguish a
/// malformed/canonical wire artifact from an untrusted registry decision.
public enum BarnardAdoptionProtocolError: Error, Equatable {
  case invalidLength
  case unsupportedCredentialVersion
  case unsupportedCensusVersion
  case invalidAdmissionMode
  case invalidField
  case invalidValidityWindow
  case invalidCensusWindow
  case nonCanonicalSignature
  case invalidCredentialSignature
  case invalidCensusSignature
  case eventIdNotAnchored
  case nonCanonicalMerkleRoot
  case invalidCensusCounts
  case invalidB005V2
  case missingRequiredTlv
  case invalidDisplayName
  case credentialScopeMismatch
  case credentialDisplayNameMismatch
  case censusCredentialMismatch
}
