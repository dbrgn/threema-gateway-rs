extern crate url;
extern crate hyper;
extern crate sodiumoxide;
extern crate data_encoding;
extern crate rand;
#[macro_use] extern crate quick_error;

pub mod crypto;
pub mod connection;
pub mod errors;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
