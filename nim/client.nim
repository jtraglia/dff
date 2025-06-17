## Differential Fuzzing Framework
## 
## This module provides a synchronous client implementation for connecting to a fuzzing server
## and processing fuzzing inputs through a user-provided callback function.

import std/[net, strutils, endians, times, os]

# Declare System V shared memory functions
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
  ## Establishes a connection to the fuzzing server,
  ## sends the client name, attaches to the shared memory segments,
  ## and reads the fuzzing method from the server.
  
  # Connect to Unix socket
  client.conn = newSocket(AF_UNIX, SOCK_STREAM, IPPROTO_IP)
  client.conn.connectUnix(SocketPath)
  
  # Send client name
  client.conn.send(client.name)
  
  # Read input shared memory ID (4 bytes, big endian)
  let inputShmIdBytes = client.conn.recv(4)
  if inputShmIdBytes.len != 4:
    raise newException(IOError, "Failed to read 4 bytes for input shm ID, got " & $inputShmIdBytes.len)
  
  var inputShmIdBE: uint32
  copyMem(addr inputShmIdBE, addr inputShmIdBytes[0], 4)
  var inputShmIdLE: uint32
  swapEndian32(addr inputShmIdLE, addr inputShmIdBE)
  client.inputShmId = cint(inputShmIdLE)
  
  # Attach to input shared memory
  client.inputShm = cast[ptr byte](shmat(client.inputShmId, nil, 0))
  if client.inputShm == cast[ptr byte](-1):
    raise newException(OSError, "Failed to attach to input shared memory")
  
  # Read output shared memory ID (4 bytes, big endian)
  let outputShmIdBytes = client.conn.recv(4)
  if outputShmIdBytes.len != 4:
    raise newException(IOError, "Failed to read 4 bytes for output shm ID, got " & $outputShmIdBytes.len)
  
  var outputShmIdBE: uint32
  copyMem(addr outputShmIdBE, addr outputShmIdBytes[0], 4)
  var outputShmIdLE: uint32
  swapEndian32(addr outputShmIdLE, addr outputShmIdBE)
  client.outputShmId = cint(outputShmIdLE)
  
  # Attach to output shared memory
  client.outputShm = cast[ptr byte](shmat(client.outputShmId, nil, 0))
  if client.outputShm == cast[ptr byte](-1):
    raise newException(OSError, "Failed to attach to output shared memory")
  
  # Read method name (server sends the method string, typically "sha")
  # Try reading byte by byte with a timeout to avoid blocking
  var methodBuffer = ""
  for i in 0..<64:  # Try up to 64 bytes max
    try:
      let singleByte = client.conn.recv(1, 100)  # 100ms timeout per byte
      if singleByte.len == 0:
        break  # No more data
      methodBuffer.add(singleByte)
      # If we got "sha", that's probably the complete method name
      if methodBuffer == "sha":
        break
    except:
      break  # Timeout or error, stop reading
  
  if methodBuffer.len == 0:
    raise newException(IOError, "Failed to read method name")
  client.fuzzMethod = methodBuffer
  
  echo "Connected with fuzzing method: ", client.fuzzMethod
  
  # Give server a moment to set up
  sleep(100)  # 100ms delay

proc run*(client: Client) =
  ## Runs the client fuzzing loop. Waits for the server to send input sizes,
  ## extracts the corresponding slices from shared memory, processes the input
  ## via the provided processFunc, writes the result to output shared memory,
  ## and sends back the size of the result.
  
  echo "Client running... Press Ctrl+C to exit."
  
  var iterationCount = 0
  while true:
    try:
      # Read input sizes from server (up to 1024 bytes)
      # Waiting for data from server...
      # Try reading just a small amount first to match Go's behavior
      var inputSizeData = ""
      # First read 4 bytes for the count
      let countData = client.conn.recv(4)
      if countData.len != 4:
        echo "Failed to read count"
        break
      inputSizeData = countData
      
      # Parse the count to see how much more to read
      var numInputsBE: uint32
      copyMem(addr numInputsBE, unsafeAddr countData[0], 4)
      var numInputsLE: uint32
      swapEndian32(addr numInputsLE, addr numInputsBE)
      let numInputs = int(numInputsLE)
      
      # Read the input sizes (4 bytes per input)
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
      
      # We already parsed numInputs above, so use that value directly
      
      # Extract input sizes and create slices from shared memory
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
        
        # Input size: inputSize bytes, offset: inputOffset
        
        # Create a string from shared memory data
        var inputStr = newString(inputSize)
        let srcPtr = cast[ptr UncheckedArray[byte]](
          cast[int](client.inputShm) + int(inputOffset)
        )
        
        for j in 0..<int(inputSize):
          inputStr[j] = char(srcPtr[j])
        
        # Process input data from shared memory
        inputs.add(inputStr)
        inputOffset += inputSize
      
      # Process the inputs using the supplied processFunc
      let startTime = cpuTime()
      let result = client.processFunc(client.fuzzMethod, inputs)
      let elapsedTime = cpuTime() - startTime
      
      # Write the processed result into the output shared memory
      let outputPtr = cast[ptr UncheckedArray[byte]](client.outputShm)
      for i in 0..<result.len:
        outputPtr[i] = byte(result[i])
      
      echo "Processing time: ", formatFloat(elapsedTime * 1000, ffDecimal, 2), "ms"
      
      # Send the size of the processed result back to the server (4 bytes, big endian)
      var resultSizeLE = uint32(result.len)
      var resultSizeBE: uint32
      swapEndian32(addr resultSizeBE, addr resultSizeLE)
      var responseSizeBuffer = newString(4)
      copyMem(addr responseSizeBuffer[0], addr resultSizeBE, 4)
      client.conn.send(responseSizeBuffer)
      
    except CatchableError as e:
      echo "Error in client loop: ", e.msg
      if "timed out" in e.msg:
        echo "NOTE: Server is not sending test data. Check if:"
        echo "  1. Server has test inputs configured"
        echo "  2. Server is running its fuzzing loop"
        echo "  3. Other clients are connected and working"
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