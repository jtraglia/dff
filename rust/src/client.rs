use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::ptr;
use std::os::raw::{c_int, c_void};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::{Error, Result};

const SOCKET_PATH: &str = "/tmp/dff";

// System V shared memory functions via libc
extern "C" {
    fn shmat(shmid: c_int, shmaddr: *const c_void, shmflg: c_int) -> *mut c_void;
    fn shmdt(shmaddr: *const c_void) -> c_int;
}

/// Global shutdown flag set by signal handler.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn shutdown_handler(_sig: c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

pub type ProcessFunc = Arc<dyn Fn(&str, &[&[u8]]) -> Result<Vec<u8>> + Send + Sync>;

pub struct Client {
    name: String,
    process_func: ProcessFunc,
    conn: Option<UnixStream>,
    input_shm: Option<*mut u8>,
    output_shm: Option<*mut u8>,
    method: String,
}

unsafe impl Send for Client {}
unsafe impl Sync for Client {}

impl Client {
    pub fn new(name: String, process_func: ProcessFunc) -> Self {
        Client {
            name,
            process_func,
            conn: None,
            input_shm: None,
            output_shm: None,
            method: String::new(),
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        // Retry connection to handle server startup timing
        let mut stream = None;
        for attempt in 0..10 {
            match UnixStream::connect(SOCKET_PATH).await {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => {
                    if attempt == 9 {
                        return Err(Error::Connection(format!("Failed to connect after 10 attempts: {}", e)));
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }

        let mut stream = stream.unwrap();

        // Send client name (no length prefix, just the name)
        stream.write_all(self.name.as_bytes()).await?;

        // Read input shared memory ID (4 bytes, big-endian)
        let mut input_shm_id_bytes = [0u8; 4];
        stream.read_exact(&mut input_shm_id_bytes).await?;
        let input_shm_id = u32::from_be_bytes(input_shm_id_bytes) as c_int;

        // Attach to input shared memory
        let input_shm_ptr = unsafe { shmat(input_shm_id, ptr::null(), 0) };
        if input_shm_ptr == (-1isize as *mut c_void) {
            return Err(Error::Client("Failed to attach to input shared memory".to_string()));
        }
        self.input_shm = Some(input_shm_ptr as *mut u8);

        // Read output shared memory ID (4 bytes, big-endian)
        let mut output_shm_id_bytes = [0u8; 4];
        stream.read_exact(&mut output_shm_id_bytes).await?;
        let output_shm_id = u32::from_be_bytes(output_shm_id_bytes) as c_int;

        // Attach to output shared memory
        let output_shm_ptr = unsafe { shmat(output_shm_id, ptr::null(), 0) };
        if output_shm_ptr == (-1isize as *mut c_void) {
            return Err(Error::Client("Failed to attach to output shared memory".to_string()));
        }
        self.output_shm = Some(output_shm_ptr as *mut u8);

        // Read method name (up to 64 bytes)
        let mut method_bytes = [0u8; 64];
        let method_length = stream.read(&mut method_bytes).await?;
        self.method = String::from_utf8_lossy(&method_bytes[..method_length]).to_string();

        log::info!("Connected with fuzzing method: {}", self.method);

        self.conn = Some(stream);
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        let stream = self.conn.as_mut()
            .ok_or_else(|| Error::Client("Not connected".to_string()))?;
        let input_shm = self.input_shm
            .ok_or_else(|| Error::Client("Input shared memory not attached".to_string()))?;
        let output_shm = self.output_shm
            .ok_or_else(|| Error::Client("Output shared memory not attached".to_string()))?;

        log::info!("Client {} started processing", self.name);
        println!("Client running... Press Ctrl+C to exit.");

        let mut iteration_count: u64 = 0;
        let mut total_processing = Duration::ZERO;
        let mut last_status = Instant::now();
        const STATUS_INTERVAL: Duration = Duration::from_secs(5);

        // Register signal handlers (replaces default terminate behavior)
        unsafe {
            libc::signal(libc::SIGTERM, shutdown_handler as libc::sighandler_t);
            libc::signal(libc::SIGINT, shutdown_handler as libc::sighandler_t);
        }

        loop {
            // Check for shutdown signal
            if SHUTDOWN.load(Ordering::Relaxed) {
                println!("Shutdown signal received. Exiting client.");
                let goodbye = 0xFFFFFFFFu32.to_be_bytes();
                let _ = stream.write_all(&goodbye).await;
                let mut ack = [0u8; 4];
                let _ = stream.read_exact(&mut ack).await;
                break;
            }

            // Read input sizes from server with timeout so we can check SHUTDOWN periodically
            let mut input_size_buffer = [0u8; 1024];
            let bytes_read = match tokio::time::timeout(
                Duration::from_millis(100),
                stream.read(&mut input_size_buffer),
            ).await {
                Ok(Ok(0)) => break,        // Server closed connection
                Ok(Ok(n)) => n,            // Got data
                Ok(Err(_)) => break,       // Read error
                Err(_) => continue,        // Timeout — loop back and check SHUTDOWN
            };

            if bytes_read < 4 {
                log::error!("Invalid input sizes data received");
                break;
            }

            let num_inputs = u32::from_be_bytes([
                input_size_buffer[0],
                input_size_buffer[1],
                input_size_buffer[2],
                input_size_buffer[3]
            ]) as usize;

            let mut inputs = Vec::new();
            let mut input_offset = 0usize;

            // Extract input sizes and create slices from shared memory
            for i in 0..num_inputs {
                let start = 4 + i * 4;
                if start + 4 > bytes_read {
                    log::error!("Unexpected end of input sizes data");
                    break;
                }

                let input_size = u32::from_be_bytes([
                    input_size_buffer[start],
                    input_size_buffer[start + 1],
                    input_size_buffer[start + 2],
                    input_size_buffer[start + 3]
                ]) as usize;

                unsafe {
                    let input_slice = std::slice::from_raw_parts(
                        input_shm.add(input_offset),
                        input_size
                    );
                    inputs.push(input_slice);
                    input_offset += input_size;
                }
            }

            // Process inputs
            let input_refs: Vec<&[u8]> = inputs.iter().map(|&s| s).collect();
            let start_time = std::time::Instant::now();

            match (self.process_func)(&self.method, &input_refs) {
                Ok(output) => {
                    // Write output to shared memory
                    unsafe {
                        ptr::copy_nonoverlapping(
                            output.as_ptr(),
                            output_shm,
                            output.len()
                        );
                    }

                    let elapsed = start_time.elapsed();
                    iteration_count += 1;
                    total_processing += elapsed;

                    if last_status.elapsed() >= STATUS_INTERVAL {
                        let avg_ms = total_processing.as_secs_f64() * 1000.0 / iteration_count as f64;
                        let total_secs = total_processing.as_secs();
                        println!(
                            "Iterations: {}, Total Processing: {}s, Average: {:.2}ms",
                            iteration_count, total_secs, avg_ms
                        );
                        last_status = Instant::now();
                    }

                    // Send output size back to server (4 bytes, big-endian)
                    let output_size = (output.len() as u32).to_be_bytes();
                    if let Err(e) = stream.write_all(&output_size).await {
                        log::error!("Failed to send output size: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    log::error!("Processing error: {}", e);
                    // Send zero size to indicate error
                    let zero_size = 0u32.to_be_bytes();
                    if let Err(e) = stream.write_all(&zero_size).await {
                        log::error!("Failed to send error response: {}", e);
                    }
                }
            }
        }

        // Clean shutdown
        println!("Client shutting down gracefully.");
        Ok(())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(input_shm) = self.input_shm {
            unsafe {
                shmdt(input_shm as *const c_void);
            }
        }
        if let Some(output_shm) = self.output_shm {
            unsafe {
                shmdt(output_shm as *const c_void);
            }
        }
    }
}
