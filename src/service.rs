use argh::FromArgs;
use ipc_channel::{ipc::IpcSender, router::ROUTER};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{OsStr, OsString},
    sync::mpsc::channel,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, FALSE, GENERIC_READ, HANDLE, HLOCAL, LocalFree},
        Security::{
            ACL,
            Authorization::{
                EXPLICIT_ACCESS_W, SE_SERVICE, SET_ACCESS, SetEntriesInAclW, SetSecurityInfo,
                TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
            },
            CreateWellKnownSid, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
            NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID, SECURITY_MAX_SID_SIZE, WinInteractiveSid,
        },
        System::Services::{QueryServiceObjectSecurity, SC_HANDLE, SERVICE_START, SERVICE_STOP},
    },
    core::PWSTR,
};
use windows_service::{
    service::{
        Service, ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
        ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_manager::{ServiceManager, ServiceManagerAccess},
};

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
pub const SERVICE_NAME: &str = "Launch Windows Service Without Admin Example";

/// Message sent from the service to app
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ToAppMessages {
    /// IPC sender for the app to send messages to service,
    /// this will be the first message sent to the app once connected
    SetToServiceSender(IpcSender<ToServiceMessages>),
    TestMessage,
}

/// Message sent from the app to service
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ToServiceMessages {
    /// Log something to `{current_exe}/../test.log`
    LogSomething,
    /// Stop the service
    Stop,
}

/// Signal shutdown when dropped,
/// this is used for when we lose the connection with our host app
struct IpcChannelDropGuard(std::sync::mpsc::Sender<()>);

impl Drop for IpcChannelDropGuard {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

/// Service arguments
#[derive(FromArgs)]
struct ServiceArguments {
    /// IPC server (the app) name to connect to
    #[argh(option)]
    ipc_server_name: String,
}

pub fn service_main(arguments: Vec<OsString>) {
    let args: Vec<&str> = arguments
        .iter()
        .map(|s| {
            s.to_str().unwrap_or_else(|| {
                // log::error!("Invalid utf8: {}", s.to_string_lossy());
                // std::process::exit(1)
                panic!("Invalid utf8: {}", s.to_string_lossy());
            })
        })
        .collect();
    service_main_internal(ServiceArguments::from_args(&[args[0]], &args[1..]).unwrap()).unwrap();
}

fn service_main_internal(service_arguments: ServiceArguments) -> anyhow::Result<()> {
    let (shutdown_tx, shutdown_rx) = channel();
    let shutdown_tx_service_stop = shutdown_tx.clone();

    let status_handle = service_control_handler::register(
        SERVICE_NAME,
        move |event| -> ServiceControlHandlerResult {
            match event {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop | ServiceControl::Preshutdown | ServiceControl::Shutdown => {
                    let _ = shutdown_tx_service_stop.send(());
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        },
    )?;
    on_service_start(&status_handle)?;

    let (to_service_sender, receiver) = ipc_channel::ipc::channel::<ToServiceMessages>().unwrap();
    let to_app_sender = IpcSender::connect(service_arguments.ipc_server_name).unwrap();
    to_app_sender
        .send(ToAppMessages::SetToServiceSender(to_service_sender))
        .unwrap();
    to_app_sender.send(ToAppMessages::TestMessage).unwrap();

    let ipc_channel_drop_guard = IpcChannelDropGuard(shutdown_tx.clone());
    ROUTER.add_typed_route(
        receiver,
        Box::new(move |message| {
            // This closure will be dropped on `receiver` disconnect (e.g. app side shutdown),
            // we capture a drop guard here to signal us to shutdown in this case
            let _ = &ipc_channel_drop_guard;
            match message {
                Ok(message) => {
                    match message {
                        ToServiceMessages::LogSomething => {
                            let path = std::env::current_exe()
                                .unwrap()
                                .parent()
                                .unwrap()
                                .join("test.log");
                            std::fs::write(path, "Hello from service!").unwrap();
                        }
                        ToServiceMessages::Stop => {
                            let _ = shutdown_tx.send(());
                        }
                    };
                }
                _ => {}
            };
        }),
    );

    let _ = shutdown_rx.recv();

    on_service_stop(&status_handle)?;

    Ok(())
}

pub fn on_service_start(status_handle: &ServiceStatusHandle) -> windows_service::Result<()> {
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    Ok(())
}

fn on_service_stop(status_handle: &ServiceStatusHandle) -> windows_service::Result<()> {
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    Ok(())
}

pub fn install_service() -> anyhow::Result<()> {
    let service_manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("Launch Windows Service Without Admin Example"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec!["--run-service".into()],
        dependencies: Vec::new(),
        account_name: None, // run as System
        account_password: None,
    };
    let service_access =
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::READ_CONTROL | ServiceAccess::WRITE_DAC;
    let service = match service_manager.open_service(SERVICE_NAME, service_access) {
        Ok(service) => {
            service.change_config(&service_info)?;
            // Maybe restart the service?
            service
        }
        Err(_) => service_manager.create_service(&service_info, service_access)?,
    };
    service.set_description(
        "Show casing how to launch a Windows service and communicate with it without admin in Rust",
    )?;
    set_service_dacl(&service)?;

    Ok(())
}

/// Set access control list for normal user to start/stop the service.
/// Some related resources:
/// https://wiki.mozilla.org/Windows_Service_Silent_Update
/// https://searchfox.org/mozilla-central/source/toolkit/components/maintenanceservice/serviceinstall.cpp
fn set_service_dacl(service: &Service) -> windows::core::Result<()> {
    let mut bytes_needed = 0;
    match unsafe {
        QueryServiceObjectSecurity(
            SC_HANDLE(service.raw_handle()),
            DACL_SECURITY_INFORMATION.0,
            None,
            0,
            &mut bytes_needed,
        )
    } {
        Ok(_) => unreachable!(),
        Err(error) => {
            if error != ERROR_INSUFFICIENT_BUFFER.into() {
                return Err(error.into());
            }
        }
    };
    let mut security_descriptor_memory: Vec<u8> = vec![0; bytes_needed as usize];
    let p_security_descriptor = PSECURITY_DESCRIPTOR(security_descriptor_memory.as_mut_ptr() as _);
    unsafe {
        QueryServiceObjectSecurity(
            SC_HANDLE(service.raw_handle()),
            DACL_SECURITY_INFORMATION.0,
            Some(p_security_descriptor),
            bytes_needed,
            &mut bytes_needed,
        )?
    };
    let mut is_dacl_present = FALSE;
    let mut is_dacl_defaulted = FALSE;
    let mut old_acl_ptr: *mut ACL = std::ptr::null_mut();
    unsafe {
        GetSecurityDescriptorDacl(
            p_security_descriptor,
            &mut is_dacl_present,
            &mut old_acl_ptr,
            &mut is_dacl_defaulted,
        )?
    };

    let mut sid_size = SECURITY_MAX_SID_SIZE;
    let mut interactive_sid_memory = [0; SECURITY_MAX_SID_SIZE as usize];
    let interactive_sid = PSID(interactive_sid_memory.as_mut_ptr() as _);
    unsafe {
        CreateWellKnownSid(
            WinInteractiveSid,
            None,
            Some(interactive_sid),
            &mut sid_size,
        )
    }?;
    let mut new_acl_ptr: *mut ACL = std::ptr::null_mut();
    unsafe {
        SetEntriesInAclW(
            Some(&[EXPLICIT_ACCESS_W {
                Trustee: TRUSTEE_W {
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                    ptstrName: PWSTR(interactive_sid.0 as _),
                    ..Default::default()
                },
                grfAccessMode: SET_ACCESS,
                grfAccessPermissions: SERVICE_START | SERVICE_STOP | GENERIC_READ.0,
                grfInheritance: NO_INHERITANCE,
            }]),
            Some(old_acl_ptr),
            &mut new_acl_ptr,
        )
        .ok()?
    };

    let result = unsafe {
        SetSecurityInfo(
            HANDLE(service.raw_handle()),
            SE_SERVICE,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_acl_ptr),
            None,
        )
    };
    unsafe { LocalFree(Some(HLOCAL(new_acl_ptr as _))) };
    // Delay return so we always free new_acl_ptr
    result.ok()?;

    Ok(())
}

pub fn uninstall_service() -> anyhow::Result<()> {
    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = service_manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    stop_service_internal(&service, true)?;
    service.delete()?;
    Ok(())
}

/// Restart the service if it's already running
pub fn start_service(ipc_server_name: String) -> anyhow::Result<()> {
    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = service_manager.open_service(
        SERVICE_NAME,
        ServiceAccess::START | ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
    )?;

    let service_status = service.query_status()?;
    if service_status.current_state != ServiceState::Stopped {
        stop_service_internal(&service, true)?;
    }

    service.start(&[
        OsStr::new("--ipc-server-name"),
        OsStr::new(&ipc_server_name),
    ])?;
    Ok(())
}

pub fn stop_service(wait: bool) -> anyhow::Result<()> {
    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = service_manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
    )?;
    stop_service_internal(&service, wait)
}

fn stop_service_internal(service: &Service, wait: bool) -> anyhow::Result<()> {
    let service_status = service.query_status()?;
    if service_status.current_state == ServiceState::Stopped {
        return Ok(());
    }

    service.stop()?;

    if !wait {
        return Ok(());
    }

    let start = Instant::now();
    let timeout = Duration::from_secs(10);
    while start.elapsed() < timeout {
        if service.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    Err(anyhow::anyhow!("Timeout while waiting for service to stop"))
}
