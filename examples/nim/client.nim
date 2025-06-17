import ../../nim/client
import std/hashes

proc processFunc(meth: string, inputs: seq[string]): string =
  case meth
  of "sha":
    if inputs.len == 0:
      raise newException(ValueError, "No inputs provided")
    let hashValue = hash(inputs[0])
    return $hashValue
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
