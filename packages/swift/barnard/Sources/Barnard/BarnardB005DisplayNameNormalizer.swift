// Use of this source code is governed by a BSD-style license.

import Foundation
import BarnardCore

/// The production `BarnardB005DisplayNameNormalizing` for `BarnardB005EnvelopeV2.verify`.
/// Lives here rather than in `BarnardCore` because NFC normalization needs Foundation's
/// Unicode tables, which `BarnardCore` deliberately does not depend on.
public struct BarnardB005NativeDisplayNameNormalizer: BarnardB005DisplayNameNormalizing {
  public init() {}
  public func isNormalizedNFC(_ value: String) -> Bool {
    // Swift's `String.==` compares Unicode canonical equivalence, so a byte-identity check is
    // required here: NFC-normalizing a decomposed string and comparing with `==` would always
    // report true (decomposed and precomposed forms are canonically equivalent), silently
    // accepting non-NFC input. Compare UTF-8 bytes instead to actually detect a difference.
    Array(value.precomposedStringWithCanonicalMapping.utf8) == Array(value.utf8)
  }
}
