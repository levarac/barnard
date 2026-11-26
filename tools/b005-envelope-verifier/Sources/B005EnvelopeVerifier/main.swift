import Foundation
import B005EnvelopeVerifierKit

func readBoundedStandardInput(limit: Int) -> Data? {
  var input = Data()
  while input.count <= limit {
    let remaining = limit + 1 - input.count
    do {
      guard let chunk = try FileHandle.standardInput.read(upToCount: min(1_024, remaining)),
            !chunk.isEmpty else { return input }
      input.append(chunk)
    } catch {
      return nil
    }
  }
  return nil
}

let arguments = Array(CommandLine.arguments.dropFirst())
let authorityOperation = arguments == ["authority-v1"]
let validOperation = authorityOperation || arguments.isEmpty || arguments == ["--verify-signed-envelope-stdin"]
let limit = authorityOperation ? B005AuthorityVerifier.maxInputBytes : B005EnvelopeVerifier.maxInputBytes
let result = (validOperation ? readBoundedStandardInput(limit: limit) : nil)
  .map { authorityOperation ? B005AuthorityVerifier.run(input: $0) : B005EnvelopeVerifier.run(input: $0) }
  ?? B005EnvelopeVerifierResult(
    status: 1, stdout: "",
    stderr: (authorityOperation ? B005AuthorityVerifier.ErrorCode.invalidAuthorizationContext.rawValue : B005EnvelopeVerifier.failureMessage) + "\n"
  )
FileHandle.standardOutput.write(Data(result.stdout.utf8))
FileHandle.standardError.write(Data(result.stderr.utf8))
exit(result.status)
