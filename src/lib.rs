extern crate num_traits;
#[macro_use]
extern crate num_derive;
extern crate byteorder;
extern crate p8n_types;
extern crate p8n_rreil_macro;

mod common;
pub use common::Mode;

mod tables;
mod decoder;
mod semantics;

mod architecture;
pub use architecture::Amd64;
