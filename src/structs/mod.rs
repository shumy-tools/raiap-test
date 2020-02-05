pub mod identity;
pub mod anchor;
pub mod stream;

use serde::{Serialize, Deserialize};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum OType { SET, DEL }

pub type Result<T> = std::result::Result<T, String>;