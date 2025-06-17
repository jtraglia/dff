import ../../nim/client
import nimcrypto

proc processFunc(meth: string, inputs: seq[string]): string =
  case meth
  of "sha":
    if inputs.len == 0:
      raise newException(ValueError, "No inputs provided")
    let digest = sha256.digest(inputs[0])
    result = newString(32)
    for i in 0..<32:
      result[i] = char(digest.data[i])
  else:
    raise newException(ValueError, "Unknown method: '" & meth & "'")

proc main() =
  let client = newClient("nim", processFunc)

  try:
    client.connect()
    client.run()
  except CatchableError as e:
    echo "Error: ", e.msg
  finally:
    client.close()

when isMainModule:
  main()
