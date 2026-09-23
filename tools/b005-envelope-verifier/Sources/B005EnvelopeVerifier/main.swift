import Foundation
import B005EnvelopeVerifierKit

func readBoundedStandardInput(limit: Int) -> Data? {
  var input = Data()
  while input.count <= limit {
    let remaining = limit + 1 - input.count
    guard let chunk = try? FileHandle.standardInput.read(upToCount: min(1_024, remaining)),
          !chunk.isEmpty
    else {
      return input
    }
    input.append(chunk)
  }
  return nil
}

let result = readBoundedStandardInput(limit: B005EnvelopeVerifier.maxInputBytes)
  .map(B005EnvelopeVerifier.run(input:))
  ?? B005EnvelopeVerifierResult(
    status: 1,
    stdout: "",
    stderr: B005EnvelopeVerifier.failureMessage + "\n"
  )
FileHandle.standardOutput.write(Data(result.stdout.utf8))
FileHandle.standardError.write(Data(result.stderr.utf8))
exit(result.status)
