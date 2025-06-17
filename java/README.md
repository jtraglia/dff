# DFF Java Client

Differential Fuzzing Framework client library for Java.

## Installation

Add to your Maven `pom.xml`:

```xml
<dependency>
    <groupId>com.github.jtraglia</groupId>
    <artifactId>dff</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage

```java
import com.github.jtraglia.dff.Client;
import com.github.jtraglia.dff.ProcessFunc;

ProcessFunc processFunc = (method, inputs) -> {
    // Your processing logic here
    return "result".getBytes();
};

Client client = new Client("my-client", processFunc);
client.connect();
client.run();
client.close();
```

## API

### Classes

- `Client` - Main client class for connecting to DFF server
- `ProcessFunc` - Functional interface for processing fuzzing inputs

### Methods

- `Client(String name, ProcessFunc processFunc)` - Create a new client
- `void connect()` - Connect to the DFF server
- `void run()` - Start the fuzzing loop
- `void close()` - Clean up resources

## Example

See `../examples/java/` for a complete SHA256 example.

## Requirements

- Java 11 or higher
- Unix/Linux system with System V shared memory support
- JNA library for native shared memory access

## Building

```bash
mvn clean compile
mvn package
```