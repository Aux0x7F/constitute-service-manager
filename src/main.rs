use anyhow::{Result, anyhow};
use constitute_protocol::{
    SERVICE_MANAGER_OPERATION_STATE_BLOCKED, SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED,
};
use constitute_service_manager::{
    blocked_operation_fixture, build_operation_posture, service_manager_lifecycle_fixture,
};

const DEFAULT_NOW: u64 = 1_700_000_000;

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(());
    }

    match args.first().map(String::as_str) {
        None | Some("fixture") => {
            let profile = args.get(1).map(String::as_str).unwrap_or("lifecycle");
            if profile != "lifecycle" {
                return Err(anyhow!("unsupported fixture profile"));
            }
            let fixture = service_manager_lifecycle_fixture(DEFAULT_NOW)?;
            println!("{}", serde_json::to_string_pretty(&fixture)?);
        }
        Some("operation") => {
            let operation = read_option(&args, "--operation").unwrap_or("restart");
            let state =
                read_option(&args, "--state").unwrap_or(SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED);
            if state == SERVICE_MANAGER_OPERATION_STATE_BLOCKED {
                let reason = read_option(&args, "--blocked").unwrap_or("blocked:operator-request");
                let fixture = blocked_operation_fixture(operation, reason, DEFAULT_NOW)?;
                println!("{}", serde_json::to_string_pretty(&fixture)?);
            } else {
                let record = build_operation_posture(operation, state, DEFAULT_NOW, vec![])?;
                println!("{}", serde_json::to_string_pretty(&record)?);
            }
        }
        Some(command) => return Err(anyhow!("unsupported command: {command}")),
    }

    Ok(())
}

fn read_option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|window| window[0] == name)
        .map(|window| window[1].as_str())
}

fn print_help() {
    println!(
        "constitute-service-manager\n\nCommands:\n  fixture lifecycle\n  operation --operation <name> --state <state> [--blocked <reason>]\n"
    );
}
