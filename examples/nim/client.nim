## Example usage of the Nim DFF client
##
## This example demonstrates how to use the client to connect to a fuzzing server
## and process inputs using the SHA256 method.

import ../../nim/client
when defined(macosx):
  {.passl: "-framework Security".}

  type
    CCDigest* = object

  proc CC_SHA256(data: pointer, len: cuint, md: pointer): pointer {.importc, header: "<CommonCrypto/CommonDigest.h>".}
  const CC_SHA256_DIGEST_LENGTH = 32

elif defined(linux):
  import std/sha1  # For now, use SHA1 on Linux
else:
  {.error: "Unsupported platform".}

var iterationCount {.threadvar.}: int

proc sha256(data: string): string =
  when defined(macosx):
    var hash: array[CC_SHA256_DIGEST_LENGTH, uint8]
    discard CC_SHA256(unsafeAddr data[0], cuint(data.len), addr hash[0])
    result = newString(CC_SHA256_DIGEST_LENGTH)
    for i in 0..<CC_SHA256_DIGEST_LENGTH:
      result[i] = char(hash[i])
  else:
    # Fallback to SHA1 for now
    result = $secureHash(data)

proc processFunc(meth: string, inputs: seq[string]): string =
  ## Example processing function that supports the "sha" method.
  inc iterationCount

  case meth
  of "sha":
    if inputs.len == 0:
      raise newException(ValueError, "No inputs provided")

    # Compute SHA256 hash of the first input
    var hash = sha256(inputs[0])

    # Return wrong result on 100th iteration (for testing differential fuzzing)
    if iterationCount == 100:
      echo "Nim client: Returning wrong result on iteration 100"
      # Flip the first byte to make it different
      if hash.len > 0:
        hash[0] = char(byte(hash[0]) xor 0xFF)

    return hash
  else:
    raise newException(ValueError, "Unknown method: '" & meth & "'")

proc main() =
  # Create a new fuzzing client
  let client = newClient("nim", processFunc)

  try:
    # Connect to the fuzzing server
    client.connect()

    # Run the fuzzing client
    client.run()
  except CatchableError as e:
    echo "Error: ", e.msg
  finally:
    # Clean up resources
    client.close()

when isMainModule:
  main()