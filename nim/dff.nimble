# Package
version       = "0.1.0"
author        = "Justin Traglia"
description   = "Differential Fuzzing Framework"
license       = "MIT"
srcDir        = "."

# Dependencies
requires "nim >= 1.6.0"
requires "nimcrypto"

# Tasks
task example, "Run the example client":
  exec "nim c -r ../examples/nim/client.nim"
