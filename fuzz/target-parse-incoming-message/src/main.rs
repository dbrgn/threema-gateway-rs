use afl::fuzz;

use threema_gateway::IncomingMessage;

const API_SECRET: &str = "nevergonnagiveyouup";

fn main() {
    fuzz!(|data: &[u8]| {
        let _parsed = IncomingMessage::from_urlencoded_bytes(data, API_SECRET);
    });
}
