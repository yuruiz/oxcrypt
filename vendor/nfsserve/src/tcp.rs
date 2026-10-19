use crate::context::RPCContext;
use crate::rpcwire::*;
use crate::vfs::NFSFileSystem;
use anyhow;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{io, net::IpAddr};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, info};

/// A NFS Tcp Connection Handler
pub struct NFSTcpListener<T: NFSFileSystem + Send + Sync + 'static> {
    listener: TcpListener,
    request_slots: Arc<Semaphore>,
    port: u16,
    arcfs: Arc<T>,
    mount_signal: Option<mpsc::Sender<bool>>,
}

pub fn generate_host_ip(hostnum: u16) -> String {
    format!(
        "127.88.{}.{}",
        ((hostnum >> 8) & 0xFF) as u8,
        (hostnum & 0xFF) as u8
    )
}

/// Cancels socket pumps on disconnect or when the listener shuts down. Already
/// dispatched filesystem requests retain their budget until they finish.
struct SocketPumps(Vec<tokio::task::AbortHandle>);
impl Drop for SocketPumps {
    fn drop(&mut self) {
        for task in &self.0 { task.abort(); }
    }
}

async fn process_socket(
    socket: tokio::net::TcpStream,
    context: RPCContext,
) -> Result<(), anyhow::Error> {
    let (mut handler, mut input, mut replies) = SocketMessageHandler::new(&context);
    socket.set_nodelay(true)?;
    let (mut reader, mut writer) = socket.into_split();
    let receiver = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut reader, &mut input).await;
    });
    let dispatcher = tokio::spawn(async move {
        loop {
            if let Err(error) = handler.read().await {
                debug!("Message loop closed: {:?}", error);
                break;
            }
        }
    });
    let _pumps = SocketPumps(vec![receiver.abort_handle(), dispatcher.abort_handle()]);
    while let Some((reply, _budget)) = replies.recv().await {
        let reply = reply?;
        if reply.len() > crate::limits::MAX_RPC_BYTES {
            return Err(anyhow::anyhow!("RPC reply exceeds byte budget"));
        }
        // The request permit stays held through the socket write, bounding
        // queued replies even when a client stops reading.
        use tokio::io::AsyncWriteExt;
        let length = u32::try_from(reply.len())?;
        writer.write_u32(length | (1 << 31)).await?;
        writer.write_all(&reply).await?;
    }
    Ok(())
}

#[async_trait]
pub trait NFSTcp: Send + Sync {
    /// Gets the true listening port. Useful if the bound port number is 0
    fn get_listen_port(&self) -> u16;

    /// Gets the true listening IP. Useful on windows when the IP may be random
    fn get_listen_ip(&self) -> IpAddr;

    /// Sets a mount listener. A "true" signal will be sent on a mount
    /// and a "false" will be sent on an unmount
    fn set_mount_listener(&mut self, signal: mpsc::Sender<bool>);

    /// Loops forever and never returns handling all incoming connections.
    async fn handle_forever(&self) -> io::Result<()>;
}

impl<T: NFSFileSystem + Send + Sync + 'static> NFSTcpListener<T> {
    /// Binds to a ipstr of the form [ip address]:port. For instance
    /// "127.0.0.1:12000". fs is an instance of an implementation
    /// of NFSFileSystem.
    pub async fn bind(ipstr: &str, fs: T) -> io::Result<NFSTcpListener<T>> {
        let (ip, port) = ipstr.split_once(':').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "IP Address must be of form ip:port",
            )
        })?;
        let port = port.parse::<u16>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "Port not in range 0..=65535",
            )
        })?;

        let arcfs: Arc<T> = Arc::new(fs);

        if ip == "auto" {
            let mut num_tries_left = 32;

            for try_ip in 1u16.. {
                let ip = generate_host_ip(try_ip);

                let result = NFSTcpListener::bind_internal(&ip, port, arcfs.clone()).await;

                match &result {
                    Err(_) => {
                        if num_tries_left == 0 {
                            return result;
                        } else {
                            num_tries_left -= 1;
                            continue;
                        }
                    }
                    Ok(_) => {
                        return result;
                    }
                }
            }
            unreachable!(); // Does not detect automatically that loop above never terminates.
        } else {
            // Otherwise, try this.
            NFSTcpListener::bind_internal(ip, port, arcfs).await
        }
    }

    async fn bind_internal(ip: &str, port: u16, arcfs: Arc<T>) -> io::Result<NFSTcpListener<T>> {
        let ipstr = format!("{ip}:{port}");
        let listener = TcpListener::bind(&ipstr).await?;
        info!("Listening on {:?}", &ipstr);

        let port = match listener.local_addr().unwrap() {
            SocketAddr::V4(s) => s.port(),
            SocketAddr::V6(s) => s.port(),
        };
        Ok(NFSTcpListener {
            listener,
            request_slots: Arc::new(Semaphore::new(crate::limits::MAX_REQUESTS)),
            port,
            arcfs,
            mount_signal: None,
        })
    }
}

#[async_trait]
impl<T: NFSFileSystem + Send + Sync + 'static> NFSTcp for NFSTcpListener<T> {
    /// Gets the true listening port. Useful if the bound port number is 0
    fn get_listen_port(&self) -> u16 {
        let addr = self.listener.local_addr().unwrap();
        addr.port()
    }

    fn get_listen_ip(&self) -> IpAddr {
        let addr = self.listener.local_addr().unwrap();
        addr.ip()
    }

    /// Sets a mount listener. A "true" signal will be sent on a mount
    /// and a "false" will be sent on an unmount
    fn set_mount_listener(&mut self, signal: mpsc::Sender<bool>) {
        self.mount_signal = Some(signal);
    }

    /// Loops forever and never returns handling all incoming connections.
    async fn handle_forever(&self) -> io::Result<()> {
        let connections = Arc::new(Semaphore::new(crate::limits::MAX_CONNECTIONS));
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let connection = Arc::clone(&connections).acquire_owned().await
                .map_err(io::Error::other)?;
            let (socket, _) = self.listener.accept().await?;
            let context = RPCContext {
                request_slots: Arc::clone(&self.request_slots),
                local_port: self.port,
                client_addr: socket.peer_addr().unwrap().to_string(),
                auth: crate::rpc::auth_unix::default(),
                vfs: self.arcfs.clone(),
                mount_signal: self.mount_signal.clone(),
            };
            info!("Accepting connection from {}", context.client_addr);
            debug!("Accepting socket {:?} {:?}", socket, context);
            tasks.spawn(async move {
                let _connection = connection;
                let _ = process_socket(socket, context).await;
            });
            while tasks.try_join_next().is_some() {}
        }
    }
}
