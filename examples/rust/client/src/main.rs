use dff::Client;
use ring::digest;
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let name = std::env::args().nth(1).unwrap_or_else(|| "rust".to_string());

    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        let process_func = Arc::new(|method: &str, inputs: &[&[u8]]| -> dff::Result<Vec<u8>> {
            if method != "sha" {
                return Err(dff::Error::Client(format!("Unknown method: {}", method)));
            }

            // For SHA method, concatenate all inputs and hash them using ring (BoringSSL)
            let mut context = digest::Context::new(&digest::SHA256);
            for input in inputs {
                context.update(input);
            }
            let digest = context.finish();
            Ok(digest.as_ref().to_vec())
        });

        let mut client = Client::new(name, process_func);
        client.connect().await
            .map_err(|e| anyhow::anyhow!("Failed to connect: {}", e))?;
        client.run().await
            .map_err(|e| anyhow::anyhow!("Client error: {}", e))
    })
}
