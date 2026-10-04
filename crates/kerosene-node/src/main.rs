mod health_probe;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments.len() == 2 && arguments[1] == "--health-probe" {
        return health_probe::run()
            .await
            .map_err(|()| anyhow::anyhow!("node local readiness probe failed"));
    }
    if arguments.len() != 1 {
        anyhow::bail!("unsupported argument");
    }
    kerosene_node::run().await
}
