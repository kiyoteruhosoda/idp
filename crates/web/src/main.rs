#[tokio::main]
async fn main() -> anyhow::Result<()> {
    idp_web::run().await
}
