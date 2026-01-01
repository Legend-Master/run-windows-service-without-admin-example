use argh::FromArgs;
use ipc_channel::ipc::IpcOneShotServer;
use windows_service::{define_windows_service, service_dispatcher};

use crate::service::{
    SERVICE_NAME, ToAppMessages, ToServiceMessages, install_service, service_main, start_service,
    uninstall_service,
};

pub mod service;

/// A simple app for show casing how to launch a Windows service and communicate with it without admin in Rust
#[derive(FromArgs)]
struct Cli {
    /// run the service
    #[argh(switch)]
    run_service: bool,
    /// install service
    #[argh(switch)]
    install_service: bool,
    /// uninstall service
    #[argh(switch)]
    uninstall_service: bool,
}

define_windows_service!(ffi_service_main, service_main);

fn main() {
    let cli: Cli = argh::from_env();

    if cli.install_service {
        install_service().unwrap();
        return;
    }
    if cli.uninstall_service {
        uninstall_service().unwrap();
        return;
    }
    if cli.run_service {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main).unwrap();
        return;
    }

    // App logic

    let (server, ipc_server_name) = IpcOneShotServer::<ToAppMessages>::new().unwrap();

    start_service(ipc_server_name).unwrap();

    let (receiver, message) = server.accept().unwrap();
    let ToAppMessages::SetToServiceSender(to_service_sender) = message else {
        panic!("The initial message sent from service is not a `ToAppMessages::SetToServiceSender`")
    };

    dbg!(receiver.recv().unwrap());
    to_service_sender.send(ToServiceMessages::Stop).unwrap();

    // stop_service(true).unwrap();
}
