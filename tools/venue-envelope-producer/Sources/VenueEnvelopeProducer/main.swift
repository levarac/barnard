// Use of this source code is governed by a BSD-style license.

import Foundation
import VenueEnvelopeProducerKit

/// Emits one real, signed B005 v2 envelope container from a JSON field descriptor.
///
/// This tool does not run a ceremony and does not generate keys -- see
/// `tools/venue-envelope-producer/README.md`. It runs exactly the four-call chain
/// `VenueEnvelopeProducer.produce` wraps, so its only job is turning already-decided fields and
/// an already-held private key into the bytes a venue device broadcasts.
func fail(_ message: String) -> Never {
  FileHandle.standardError.write(Data((message + "\n").utf8))
  exit(1)
}

let arguments = CommandLine.arguments
guard arguments.count == 2 else {
  fail("usage: venue-envelope-producer <input.json>\n\nSee tools/venue-envelope-producer/README.md for the JSON shape.")
}

let inputPath = arguments[1]
guard let inputData = FileManager.default.contents(atPath: inputPath) else {
  fail("could not read \(inputPath)")
}

let input: VenueEnvelopeProducerInput
do {
  input = try JSONDecoder().decode(VenueEnvelopeProducerInput.self, from: inputData)
} catch {
  fail("could not parse \(inputPath) as a VenueEnvelopeProducerInput: \(error)")
}

switch VenueEnvelopeProducer.produce(input) {
case .failure(let error):
  fail("refused: \(error)")
case .success(let output):
  print(output.container.map { String(format: "%02x", $0) }.joined())
  FileHandle.standardError.write(Data((
    "eventId=\(output.eventId.map { String(format: "%02x", $0) }.joined())\n"
    + "signerPublicKey=\(output.signerPublicKeyHex)\n"
    + "containerBytes=\(output.container.count)\n"
  ).utf8))
}
