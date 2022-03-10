use std::net::TcpStream;
use tungstenite::{
    connect,
    protocol::{Message, WebSocket},
    stream::MaybeTlsStream,
};

pub struct NymClient {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
}

impl NymClient {
    pub fn new() -> Result<Self, tungstenite::Error> {
        let (socket, _) = connect("ws://localhost:43615")?;
        Ok(NymClient { socket })
    }
    pub fn await_message(&mut self) -> Result<Vec<u8>, tungstenite::Error> {
        Ok(self.socket.read_message()?.into_data())
    }
    pub fn send_message(&mut self, msg: Vec<u8>) -> Result<(), tungstenite::Error> {
        self.socket.write_message(Message::Binary(msg))
    }
    pub fn close(mut self) -> Result<(), tungstenite::Error> {
        self.socket.close(None)
    }
}
