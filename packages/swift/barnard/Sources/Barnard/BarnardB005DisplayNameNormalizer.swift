// Use of this source code is governed by a BSD-style license.

import Foundation
import BarnardCore

/// The production `BarnardB005DisplayNameNormalizing` for `BarnardB005EnvelopeV2.verify`.
/// Lives here rather than in `BarnardCore` because NFC normalization needs Foundation's
/// Unicode tables, which `BarnardCore` deliberately does not depend on.
public struct BarnardB005NativeDisplayNameNormalizer: BarnardB005DisplayNameNormalizing {
  public init() {}
  public func isNormalizedNFC(_ value: String) -> Bool {
    value.precomposedStringWithCanonicalMapping == value
  }
}
