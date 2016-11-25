use std::io::Error as IoError;
use hyper::error::Error as HyperError;

quick_error! {
    #[derive(Debug)]
    pub enum ApiError {
        /// API identity or secret is incorrect
        BadCredentials {}

        /// Target ID not found
        BadId {}

        /// Internal server error
        ServerError {}

        /// Error when sending request
        RequestError(err: HyperError) {
            from()
        }

        /// Error when reading response
        IoError(err: IoError) {
            from()
        }

        /// Other
        Other(msg: String) {
            from()
        }
    }
}
