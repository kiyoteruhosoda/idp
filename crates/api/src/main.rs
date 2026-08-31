#[tokio::main]
async fn main() -> anyhow::Result<()> {
    assay_api::run().await
}
