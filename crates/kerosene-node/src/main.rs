#[tokio::main]
async fn main() -> anyhow::Result<()> {
    kerosene_node::run().await
}
