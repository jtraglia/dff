.PHONY: build run clean

# Build the main library first, then the example
build:
	cd ../../java && mvn clean package -q
	mvn clean compile -q

# Run the example
run: build
	java -cp "target/classes:../../java/target/dff-0.1.1.jar:$(HOME)/.m2/repository/net/java/dev/jna/jna/5.13.0/jna-5.13.0.jar:$(HOME)/.m2/repository/net/java/dev/jna/jna-platform/5.13.0/jna-platform-5.13.0.jar" com.example.ExampleClient

# Clean build artifacts
clean:
	mvn clean -q
	cd ../../java && mvn clean -q
