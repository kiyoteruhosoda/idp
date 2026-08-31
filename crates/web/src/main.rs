#[tokio::main]
async fn main() -> anyhow::Result<()> {
    assay_web::run().await
}
