# How To Register A Windows Service That Can Be Launched Without UAC Prompt In Rust

This example app show cased how you can register a Windows service that can be started by a non-elevated process without UAC prompt, and connect them with `ipc-channel` to communicate with each other

This is often used by updaters so the update can be installed without a UAC prompt, in fact, the code is heavily inspired by the [Firefox Updater](https://wiki.mozilla.org/Windows_Service_Silent_Update)

> Note: you need to be elevated to install the service, this is not a guide to bypass that, and this can be usually done by the installer when user installs you app

## Usage

1. Use `cargo build` to build the app
2. In an elevated shell, run `./target/debug/run_windows_service_without_admin_example.exe --install-service` to install the service
3. In n non-elevated shell, run the app `./target/debug/run_windows_service_without_admin_example.exe` and see the message passed back from the service
4. In an elevated shell, run `./target/debug/run_windows_service_without_admin_example.exe --uninstall-service` to uninstall the service

## Security

Since the method allows any app to start the service and communicate with it, you must be very careful with what the service can do. In case of using it to do an update, make sure to verify the installer (you should do that anyways)
