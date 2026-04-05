pub mod resolve;
pub mod addr;
pub mod fetch;
pub mod health;

pub use resolve::resolve_dc;
pub use fetch::{fetch_telegram_config, TelegramConfig};
pub use health::check_all_dcs;
