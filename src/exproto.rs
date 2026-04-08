#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() {
    exproto::engine::run().await;
}
