use crate::Result;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::Hasher;
use std::os::raw::{c_int, c_void};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio::time;

const SOCKET_PATH: &str = "/tmp/dff";
const DEFAULT_INPUT_SHM_KEY: c_int = 1000;
const DEFAULT_SHM_MAX_SIZE: usize = 100 * 1024 * 1024; // 100 MiB
const DEFAULT_SHM_PERM: c_int = 0o666;
const IPC_CREAT: c_int = 0o1000;
const IPC_EXCL: c_int = 0o2000;
const IPC_RMID: c_int = 0;

// System V shared memory functions via libc
extern "C" {
    fn shmget(key: c_int, size: usize, shmflg: c_int) -> c_int;
    fn shmat(shmid: c_int, shmaddr: *const c_void, shmflg: c_int) -> *mut c_void;
    fn shmdt(shmaddr: *const c_void) -> c_int;
    fn shmctl(shmid: c_int, cmd: c_int, buf: *mut c_void) -> c_int;
}

struct ClientEntry {
    _name: String,
    conn: UnixStream,
    _shm_id: c_int,
    shm_buffer: Vec<u8>,
    _method: String,
}

pub struct Server {
    method: String,
    input_shm_key: c_int,
    shm_max_size: usize,
    shm_perm: c_int,
    clients: Arc<Mutex<HashMap<String, ClientEntry>>>,
    shutdown: Arc<tokio::sync::Notify>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
    iteration_count: Arc<Mutex<u64>>,
    total_duration: Arc<Mutex<Duration>>,
}

impl Server {
    pub fn new(method: String) -> Result<Self> {
        Ok(Server {
            method,
            input_shm_key: DEFAULT_INPUT_SHM_KEY,
            shm_max_size: DEFAULT_SHM_MAX_SIZE,
            shm_perm: DEFAULT_SHM_PERM,
            clients: Arc::new(Mutex::new(HashMap::new())),
            shutdown: Arc::new(tokio::sync::Notify::new()),
            stopping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            iteration_count: Arc::new(Mutex::new(0)),
            total_duration: Arc::new(Mutex::new(Duration::from_secs(0))),
        })
    }

    pub async fn run<F>(self, provider: F) -> Result<()>
    where
        F: Fn() -> Vec<Vec<u8>> + Send + Sync + 'static,
    {
        let provider = Arc::new(provider);

        // Clean up any existing input shared memory
        let existing_input_shm_id = unsafe { shmget(self.input_shm_key, 0, 0) };
        if existing_input_shm_id != -1 {
            log::info!("Removing existing input shared memory segment with key {}", self.input_shm_key);
            unsafe {
                shmctl(existing_input_shm_id, IPC_RMID, std::ptr::null_mut());
            }
        }

        // Create input shared memory
        let input_shm_id = unsafe {
            shmget(
                self.input_shm_key,
                self.shm_max_size,
                self.shm_perm | IPC_CREAT | IPC_EXCL,
            )
        };

        if input_shm_id == -1 {
            log::error!("Failed to create input shared memory with key {}", self.input_shm_key);
            return Err(crate::Error::Client("Failed to create input shared memory".to_string()));
        }

        log::info!("Created input shared memory with key {} and ID {}", self.input_shm_key, input_shm_id);

        let input_shm_buffer = unsafe { shmat(input_shm_id, std::ptr::null(), 0) };
        if input_shm_buffer == (-1isize as *mut c_void) {
            unsafe {
                shmctl(input_shm_id, IPC_RMID, std::ptr::null_mut());
            }
            return Err(crate::Error::Client("Failed to attach to input shared memory".to_string()));
        }

        // Remove existing socket file and create Unix domain socket
        let _ = std::fs::remove_file(SOCKET_PATH);
        let listener = UnixListener::bind(SOCKET_PATH)?;
        log::info!("Server listening on: {}", SOCKET_PATH);

        let server = Arc::new(self);

        // Start client acceptance task
        let accept_handle = {
            let server = server.clone();
            tokio::spawn(async move {
                server.accept_clients(listener, input_shm_id).await
            })
        };

        // Start fuzzing loop task
        let fuzz_handle = {
            let server = server.clone();
            let input_shm_buffer_addr = input_shm_buffer as usize;
            tokio::spawn(async move {
                server.fuzzing_loop(provider, input_shm_buffer_addr).await
            })
        };

        // Start status updates task
        let status_handle = {
            let server = server.clone();
            tokio::spawn(async move {
                server.status_updates().await
            })
        };

        // Wait for interrupt signal
        tokio::signal::ctrl_c().await?;
        log::info!("Received interrupt signal, shutting down...");

        server.stopping.store(true, std::sync::atomic::Ordering::SeqCst);
        server.shutdown.notify_waiters();

        // Wait for tasks to complete
        let _ = tokio::join!(accept_handle, fuzz_handle, status_handle);

        // Cleanup input shared memory and all client segments
        unsafe {
            shmdt(input_shm_buffer);
            shmctl(input_shm_id, IPC_RMID, std::ptr::null_mut());
        }

        // Clean up all client output shared memory segments
        {
            let clients = server.clients.lock().await;
            for (client_name, client) in clients.iter() {
                log::info!("Cleaning up shared memory for client: {}", client_name);
                unsafe {
                    shmctl(client._shm_id, IPC_RMID, std::ptr::null_mut());
                }
            }
        }

        let _ = std::fs::remove_file(SOCKET_PATH);

        log::info!("Server shutdown complete");
        Ok(())
    }

    async fn accept_clients(self: Arc<Self>, listener: UnixListener, input_shm_id: c_int) {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            let server = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = server.handle_client_registration(
                                    stream,
                                    input_shm_id,
                                ).await {
                                    log::error!("Failed to handle client registration: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            log::error!("Failed to accept client connection: {}", e);
                        }
                    }
                }
                _ = self.shutdown.notified() => break,
            }
        }
    }

    async fn handle_client_registration(
        self: Arc<Self>,
        mut stream: UnixStream,
        input_shm_id: c_int,
    ) -> Result<()> {
        // Read client name (up to 32 bytes)
        let mut name_buffer = [0u8; 32];
        let name_len = stream.read(&mut name_buffer).await?;
        let client_name = String::from_utf8_lossy(&name_buffer[..name_len]).to_string();

        log::info!("Client registration request from: {}", client_name);

        // Validate client name
        if client_name == "method" || client_name == "input" {
            log::warn!("Invalid client name: {} (reserved name)", client_name);
            return Err(crate::Error::Client(format!(
                "Invalid client name: {} (reserved name)",
                client_name
            )));
        }

        // Check if client already exists
        {
            let clients = self.clients.lock().await;
            if clients.contains_key(&client_name) {
                log::warn!("Client {} already registered (duplicate name)", client_name);
                return Err(crate::Error::Client(format!(
                    "Client {} already registered (duplicate name)",
                    client_name
                )));
            }
        }

        // Create output shared memory for this client
        let mut hasher = DefaultHasher::new();
        hasher.write(client_name.as_bytes());
        let name_hash = hasher.finish();
        let output_shm_key = self.input_shm_key + 1 + ((name_hash % 1000) as c_int);
        log::info!("Creating output shared memory for client '{}' with key {}", client_name, output_shm_key);

        // First try to get existing segment, if it exists remove it
        let existing_shm_id = unsafe { shmget(output_shm_key, 0, 0) };
        if existing_shm_id != -1 {
            log::info!("Removing existing shared memory segment with key {}", output_shm_key);
            unsafe {
                shmctl(existing_shm_id, IPC_RMID, std::ptr::null_mut());
            }
        }

        let output_shm_id = unsafe {
            shmget(
                output_shm_key,
                self.shm_max_size,
                self.shm_perm | IPC_CREAT | IPC_EXCL,
            )
        };

        if output_shm_id == -1 {
            log::error!("Failed to create output shared memory for client {} with key {}", client_name, output_shm_key);
            return Err(crate::Error::Client("Failed to create output shared memory".to_string()));
        }

        log::info!("Created output shared memory for client {} with key {} and ID {}", client_name, output_shm_key, output_shm_id);

        let output_shm_buffer = unsafe { shmat(output_shm_id, std::ptr::null(), 0) };
        if output_shm_buffer == (-1isize as *mut c_void) {
            log::error!("Failed to attach to output shared memory for client {}", client_name);
            unsafe {
                shmctl(output_shm_id, IPC_RMID, std::ptr::null_mut());
            }
            return Err(crate::Error::Client("Failed to attach to output shared memory".to_string()));
        }

        // Create a safe Vec from the shared memory
        let shm_buffer = unsafe {
            std::slice::from_raw_parts_mut(output_shm_buffer as *mut u8, self.shm_max_size)
        }.to_vec();

        // Detach immediately after copying to Vec
        unsafe {
            shmdt(output_shm_buffer);
        }

        // Send shared memory IDs to client
        log::info!("Sending input_shm_id: {} and output_shm_id: {} to client {}",
                  input_shm_id, output_shm_id, client_name);
        stream.write_all(&(input_shm_id as u32).to_be_bytes()).await?;
        stream.write_all(&(output_shm_id as u32).to_be_bytes()).await?;

        // Send method name
        stream.write_all(self.method.as_bytes()).await?;

        log::info!("Client {} registered successfully", client_name);

        // Store client entry
        let client_entry = ClientEntry {
            _name: client_name.clone(),
            conn: stream,
            _shm_id: output_shm_id,
            shm_buffer,
            _method: self.method.clone(),
        };

        {
            let mut clients = self.clients.lock().await;
            clients.insert(client_name.clone(), client_entry);
        }

        println!("Registered new client: {}", client_name);

        Ok(())
    }


    async fn fuzzing_loop<F>(self: Arc<Self>, provider: Arc<F>, input_shm_buffer_addr: usize)
    where
        F: Fn() -> Vec<Vec<u8>> + Send + Sync + 'static,
    {
        loop {
            // Check for shutdown signal
            tokio::select! {
                _ = self.shutdown.notified() => break,
                _ = async {} => {} // Continue immediately like Go's default case
            }

            let start = std::time::Instant::now();
            let clients = self.clients.lock().await;

            if clients.is_empty() {
                drop(clients);
                println!("Waiting for a client...");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(1)) => continue,
                    _ = self.shutdown.notified() => break,
                }
            }

            // Generate inputs
            let inputs = provider();
            if inputs.is_empty() {
                drop(clients);
                continue;
            }

                    // Write inputs to shared memory
                    let mut offset = 0usize;
                    for input in &inputs {
                        if offset + input.len() >= self.shm_max_size {
                            log::warn!("Input too large for shared memory, skipping");
                            break;
                        }
                        unsafe {
                            let input_shm_buffer_ptr = input_shm_buffer_addr as *mut u8;
                            std::ptr::copy_nonoverlapping(
                                input.as_ptr(),
                                input_shm_buffer_ptr.add(offset),
                                input.len()
                            );
                        }
                        offset += input.len();
                    }

                    // Copy clients to avoid holding lock during communication
                    let client_names: Vec<String> = clients.keys().cloned().collect();
                    drop(clients);

                    // Process all clients concurrently like Go does
                    let mut tasks = Vec::new();

                    for client_name in &client_names {
                        let client_name = client_name.clone();
                        let inputs = inputs.clone();
                        let clients = self.clients.clone();
                        let task = tokio::spawn(async move {
                            let mut clients = clients.lock().await;
                            if let Some(client) = clients.get_mut(&client_name) {
                                // Build message: count (4 bytes) + sizes (4 bytes each)
                                let mut message = Vec::new();
                                message.extend_from_slice(&(inputs.len() as u32).to_be_bytes());
                                for input in &inputs {
                                    message.extend_from_slice(&(input.len() as u32).to_be_bytes());
                                }

                                // Send message to client
                                if let Err(e) = client.conn.write_all(&message).await {
                                    if e.to_string().contains("Broken pipe") {
                                        println!("client disconnected: {}", client_name);
                                    } else {
                                        println!("Error writing to client {}: {}", client_name, e);
                                    }
                                    // Clean up client's shared memory segment
                                    unsafe {
                                        shmctl(client._shm_id, IPC_RMID, std::ptr::null_mut());
                                    }
                                    clients.remove(&client_name);
                                    return None;
                                }

                                // Read response (output size)
                                let mut response = [0u8; 4];
                                if let Err(e) = client.conn.read_exact(&mut response).await {
                                    if !e.to_string().contains("EOF") {
                                        println!("Error reading response from client {}: {}", client_name, e);
                                    }
                                    // Clean up client's shared memory segment
                                    unsafe {
                                        shmctl(client._shm_id, IPC_RMID, std::ptr::null_mut());
                                    }
                                    clients.remove(&client_name);
                                    return None;
                                }

                                let output_size = u32::from_be_bytes(response);

                                // Check for goodbye sentinel
                                if output_size == 0xFFFFFFFF {
                                    let _ = client.conn.write_all(&0xFFFFFFFFu32.to_be_bytes()).await;
                                    println!("Client {} disconnected gracefully", client_name);
                                    clients.remove(&client_name);
                                    return Some((client_name.clone(), b"GOODBYE".to_vec()));
                                }

                                let output_size = output_size as usize;
                                if output_size > 0 && output_size <= client.shm_buffer.len() {
                                    // The client.shm_buffer is just a copy from registration time
                                    // We need to read from the actual shared memory segment
                                    let result = unsafe {
                                        let shm_ptr = shmat(client._shm_id, std::ptr::null(), 0);
                                        if shm_ptr == (-1isize as *mut c_void) {
                                            println!("Failed to attach to client {} shared memory for reading", client_name);
                                            return None;
                                        }
                                        let slice = std::slice::from_raw_parts(shm_ptr as *const u8, output_size);
                                        let result = slice.to_vec();
                                        shmdt(shm_ptr);
                                        result
                                    };
                                    return Some((client_name.clone(), result));
                                } else if output_size > 0 {
                                    println!("Client {} returned invalid output size: {}", client_name, output_size);
                                }
                            }
                            None
                        });
                        tasks.push(task);
                    }

            // Wait for all client tasks to complete (like WaitGroup in Go)
            let results = tokio::select! {
                results = futures::future::join_all(tasks) => results,
                _ = self.shutdown.notified() => break,
            };

            // Collect successful results for comparison
            let mut client_results = std::collections::HashMap::new();
            let mut crashed_clients = Vec::new();
            let mut graceful_disconnects = Vec::new();
            for result in results {
                if let Ok(Some((client_name, output))) = result {
                    if output == b"GOODBYE" {
                        graceful_disconnects.push(client_name);
                    } else {
                        client_results.insert(client_name, output);
                    }
                }
            }

            // Detect crashed clients by comparing against original client list
            for name in &client_names {
                if !client_results.contains_key(name) && !graceful_disconnects.contains(name) {
                    crashed_clients.push(name.clone());
                }
            }

            // Treat client crashes as findings (but not during shutdown)
            if !crashed_clients.is_empty() && !self.stopping.load(std::sync::atomic::Ordering::SeqCst) {
                println!("Client(s) crashed: {}", crashed_clients.join(", "));
                for name in &crashed_clients {
                    client_results.insert(name.clone(), b"CRASHED".to_vec());
                }

                let iteration_num = {
                    let count = self.iteration_count.lock().await;
                    *count
                };

                if let Err(e) = self.save_finding(iteration_num, &inputs, &client_results).await {
                    log::error!("Failed to save crash finding: {}", e);
                }
            // Check for differences
            } else if client_results.len() > 1 {
                let mut first_result: Option<&Vec<u8>> = None;
                let mut same = true;

                for (_, result) in &client_results {
                    match first_result {
                        None => first_result = Some(result),
                        Some(first) => {
                            if first != result {
                                same = false;
                                break;
                            }
                        }
                    }
                }

                if !same {
                    println!("Values are different:");
                    for (client_name, result) in &client_results {
                        println!("Key: {}, Value: {}", client_name, hex::encode(result));
                    }

                    // Save finding to disk
                    let iteration_num = {
                        let count = self.iteration_count.lock().await;
                        *count
                    };

                    if let Err(e) = self.save_finding(iteration_num, &inputs, &client_results).await {
                        log::error!("Failed to save finding: {}", e);
                    }
                }
            }

            // Update statistics
            let duration = start.elapsed();
            {
                let mut count = self.iteration_count.lock().await;
                *count += 1;
            }
            {
                let mut total = self.total_duration.lock().await;
                *total += duration;
            }
        }
    }

    async fn status_updates(self: Arc<Self>) {
        let mut interval = time::interval(Duration::from_secs(5));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let count = *self.iteration_count.lock().await;
                    let total = *self.total_duration.lock().await;
                    let clients = self.clients.lock().await;

                    if count > 0 && !clients.is_empty() {
                        let average = total / count as u32;
                        let mut client_names: Vec<String> = clients.keys().cloned().collect();
                        client_names.sort();
                        let joined_names = client_names.join(",");

                        println!("Fuzzing Time: {:?}, Iterations: {}, Average Iteration: {:?}, Clients: {}",
                                total, count, average, joined_names);
                    }
                }
                _ = self.shutdown.notified() => break,
            }
        }
    }

    async fn save_finding(
        &self,
        iteration: u64,
        inputs: &[Vec<u8>],
        client_results: &std::collections::HashMap<String, Vec<u8>>,
    ) -> Result<()> {
        let findings_dir = format!("findings/{}", iteration);
        std::fs::create_dir_all(&findings_dir).map_err(|e| {
            crate::Error::Client(format!("Failed to create findings directory: {}", e))
        })?;

        // Save each input separately
        for (i, input) in inputs.iter().enumerate() {
            let input_path = format!("{}/input_{}", findings_dir, i);
            std::fs::write(&input_path, input).map_err(|e| {
                crate::Error::Client(format!("Failed to write input_{}: {}", i, e))
            })?;
        }

        // Save method name
        let method_path = format!("{}/method", findings_dir);
        std::fs::write(&method_path, &self.method).map_err(|e| {
            crate::Error::Client(format!("Failed to write method file: {}", e))
        })?;

        // Save each client's output
        for (client_name, output) in client_results {
            let output_path = format!("{}/{}", findings_dir, client_name);
            std::fs::write(&output_path, output).map_err(|e| {
                crate::Error::Client(format!("Failed to write {} output: {}", client_name, e))
            })?;
        }

        println!("Finding saved to: {}", findings_dir);
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(SOCKET_PATH);
    }
}