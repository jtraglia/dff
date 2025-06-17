use dff::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    
    let server = Server::new("sha".to_string())
        .map_err(|e| anyhow::anyhow!("Failed to create server: {}", e))?;
    
    let provider = || {
        use rand::RngCore;
        
        const MIN_SIZE: usize = 1 * 1024 * 1024; // 1 MB
        const MAX_SIZE: usize = 4 * 1024 * 1024; // 4 MB
        
        let mut rng = rand::thread_rng();
        let size = rng.next_u32() as usize % (MAX_SIZE - MIN_SIZE + 1) + MIN_SIZE;
        
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        vec![data]
    };
    
    server.run(provider).await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))
}