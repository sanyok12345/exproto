pub mod resolve;
pub mod addr;
pub mod fetch;
pub mod cache;
pub mod health;

pub use resolve::resolve_dc;
pub use fetch::TelegramConfig;
pub use cache::TelegramConfigCache;
pub use health::check_all_dcs;
