## Differential Fuzzing Framework
##
## This module provides a client implementation for connecting to a fuzzing server
## and processing fuzzing inputs through a user-provided callback function.

import std/[net, strutils, endians, times, posix]

proc shmat(shmid: cint, shmaddr: pointer, shmflg: cint): pointer {.importc, header: "<sys/shm.h>".}
proc shmdt(shmaddr: pointer): cint {.importc, header: "<sys/shm.h>".}

const SocketPath = "/tmp/dff"

type
  ProcessFunc* = proc(meth: string, inputs: seq[string]): string

  Client* = ref object
    name*: string
    processFunc*: ProcessFunc
    conn: Socket
    inputShm: ptr byte
    outputShm: ptr byte
    inputShmId: cint
    outputShmId: cint
    fuzzMethod: string

proc newClient*(name: string, processFunc: ProcessFunc): Client =
  ## Creates a new Client with the given name and processing function.
  result = Client(
    name: name,
    processFunc: processFunc
  )

proc connect*(client: Client) =
  ## Establishes a connection to the fuzzing server.
  client.conn = newSocket(Domain.AF_UNIX, SockType.SOCK_STREAM, Protocol.IPPROTO_IP)
  client.conn.connectUnix(SocketPath)
  client.conn.send(client.name)

  let inputShmIdBytes = client.conn.recv(4)
  if inputShmIdBytes.len != 4:
    raise newException(IOError, "Failed to read input shm ID")

  var inputShmIdBE: uint32
  copyMem(addr inputShmIdBE, addr inputShmIdBytes[0], 4)
  var inputShmIdLE: uint32
  swapEndian32(addr inputShmIdLE, addr inputShmIdBE)
  client.inputShmId = cint(inputShmIdLE)

  client.inputShm = cast[ptr byte](shmat(client.inputShmId, nil, 0))
  if client.inputShm == cast[ptr byte](-1):
    raise newException(OSError, "Failed to attach to input shared memory")

  let outputShmIdBytes = client.conn.recv(4)
  if outputShmIdBytes.len != 4:
    raise newException(IOError, "Failed to read output shm ID")

  var outputShmIdBE: uint32
  copyMem(addr outputShmIdBE, addr outputShmIdBytes[0], 4)
  var outputShmIdLE: uint32
  swapEndian32(addr outputShmIdLE, addr outputShmIdBE)
  client.outputShmId = cint(outputShmIdLE)

  client.outputShm = cast[ptr byte](shmat(client.outputShmId, nil, 0))
  if client.outputShm == cast[ptr byte](-1):
    raise newException(OSError, "Failed to attach to output shared memory")

  var methodBuffer = ""
  for i in 0..<64:
    try:
      let singleByte = client.conn.recv(1, 100)
      if singleByte.len == 0:
        break
      if singleByte[0] == '\0':
        break
      methodBuffer.add(singleByte)
    except:
      break

  if methodBuffer.len == 0:
    raise newException(IOError, "Failed to read method name")
  client.fuzzMethod = methodBuffer

  echo "Connected with fuzzing method: ", client.fuzzMethod

var shutdownRequested = false

proc signalHandler(sig: cint) {.noconv.} =
  shutdownRequested = true
  echo "\nShutdown signal received."

proc run*(client: Client) =
  ## Runs the client fuzzing loop.
  echo "Client running... Press Ctrl+C to exit."

  signal(SIGINT, signalHandler)
  signal(SIGTERM, signalHandler)

  var iterationCount = 0
  var totalProcessingMs = 0.0
  var lastStatus = cpuTime()
  const statusInterval = 5.0
  while not shutdownRequested:
    try:
      var inputSizeData = ""
      let countData = client.conn.recv(4)
      if countData.len != 4:
        echo "Failed to read count"
        break
      inputSizeData = countData

      # Check for shutdown after reading input
      if shutdownRequested:
        var goodbyeBE: uint32
        var goodbyeLE: uint32 = 0xFFFFFFFF'u32
        swapEndian32(addr goodbyeBE, addr goodbyeLE)
        var goodbyeBuffer = newString(4)
        copyMem(addr goodbyeBuffer[0], addr goodbyeBE, 4)
        client.conn.send(goodbyeBuffer)
        discard client.conn.recv(4)  # Wait for server ack
        break

      var numInputsBE: uint32
      copyMem(addr numInputsBE, unsafeAddr countData[0], 4)
      var numInputsLE: uint32
      swapEndian32(addr numInputsLE, addr numInputsBE)
      let numInputs = int(numInputsLE)

      if numInputs > 0:
        let sizeData = client.conn.recv(numInputs * 4)
        inputSizeData = inputSizeData & sizeData

      let bytesReceived = inputSizeData.len

      if bytesReceived == 0:
        echo "Server closed connection"
        break
      if bytesReceived < 4:
        raise newException(IOError, "Invalid input sizes data received")

      inc iterationCount

      var inputs: seq[string] = @[]
      var inputOffset: uint32 = 0

      for i in 0..<numInputs:
        let start = 4 + i * 4
        if start + 4 > bytesReceived:
          raise newException(IOError, "Unexpected end of input sizes data")

        var inputSizeBE: uint32
        copyMem(addr inputSizeBE, addr inputSizeData[start], 4)
        var inputSizeLE: uint32
        swapEndian32(addr inputSizeLE, addr inputSizeBE)
        let inputSize = inputSizeLE

        var inputStr = newString(inputSize)
        let srcPtr = cast[ptr UncheckedArray[byte]](
          cast[int](client.inputShm) + int(inputOffset)
        )

        for j in 0..<int(inputSize):
          inputStr[j] = char(srcPtr[j])

        inputs.add(inputStr)
        inputOffset += inputSize

      let startTime = cpuTime()
      let result = client.processFunc(client.fuzzMethod, inputs)
      let elapsedTime = cpuTime() - startTime

      let outputPtr = cast[ptr UncheckedArray[byte]](client.outputShm)
      for i in 0..<result.len:
        outputPtr[i] = byte(result[i])

      totalProcessingMs += elapsedTime * 1000
      if cpuTime() - lastStatus >= statusInterval:
        let avgMs = totalProcessingMs / float(iterationCount)
        let totalSecs = int(totalProcessingMs / 1000)
        echo "Iterations: ", iterationCount, ", Total Processing: ", totalSecs, "s, Average: ", formatFloat(avgMs, ffDecimal, 2), "ms"
        lastStatus = cpuTime()

      var resultSizeLE = uint32(result.len)
      var resultSizeBE: uint32
      swapEndian32(addr resultSizeBE, addr resultSizeLE)
      var responseSizeBuffer = newString(4)
      copyMem(addr responseSizeBuffer[0], addr resultSizeBE, 4)
      client.conn.send(responseSizeBuffer)

    except CatchableError as e:
      echo "Error in client loop: ", e.msg
      break

proc close*(client: Client) =
  ## Cleans up all resources held by the client.
  if client.conn != nil:
    client.conn.close()

  if client.inputShm != nil and client.inputShm != cast[ptr byte](-1):
    discard shmdt(client.inputShm)
    client.inputShm = nil

  if client.outputShm != nil and client.outputShm != cast[ptr byte](-1):
    discard shmdt(client.outputShm)
    client.outputShm = nil
