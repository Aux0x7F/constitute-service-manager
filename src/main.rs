use anyhow::{Result, anyhow};
use constitute_protocol::{
    SERVICE_MANAGER_OPERATION_STATE_BLOCKED, SERVICE_MANAGER_OPERATION_STATE_SUCCEEDED,
};
use constitute_service_manager::{
    ServiceOperationRequest, apply_service_operation, blocked_operation_fixture,
    build_operation_posture, default_manager_state, fabric_transition_fixture,
    lab_linux_target_fixture, load_manager_state, save_manager_state,
    service_manager_lifecycle_fixture, service_manager_status,
};

const DEFAULT_NOW: u64 = 1_700_000_000;
const DEFAULT_STATE_PATH: &str = "service-manager-state.json";

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(());
    }

    match args.first().map(String::as_str) {
        None | Some("fixture") => {
            let profile = args.get(1).map(String::as_str).unwrap_or("lifecycle");
            match profile {
                "lifecycle" => {
                    let fixture = service_manager_lifecycle_fixture(DEFAULT_NOW)?;
                    println!("{}", serde_json::to_string_pretty(&fixture)?);
                }
                "lab-target" | "lab-linux-target" => {
                    let fixture = lab_linux_target_fixture(DEFAULT_NOW)?;
                    println!("{}", serde_json::to_string_pretty(&fixture)?);
                }
                "fabric-transition" => {
                    let fixture = fabric_transition_fixture(DEFAULT_NOW)?;
                    println!("{}", serde_json::to_string_pretty(&fixture)?);
                }
                _ => return Err(anyhow!("unsupported fixture profile")),
            }
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
        Some("init") => {
            let path = read_option(&args, "--state").unwrap_or(DEFAULT_STATE_PATH);
            let issued_at = read_u64_option(&args, "--at").unwrap_or(DEFAULT_NOW);
            let mut state = default_manager_state(issued_at);
            let posture = service_manager_status(&state, "lab-service", issued_at)?;
            state.posture = Some(posture);
            save_manager_state(path, &state)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Some("run") => {
            let path = read_option(&args, "--state").unwrap_or(DEFAULT_STATE_PATH);
            let service_id = read_option(&args, "--service").unwrap_or("lab-service");
            let operation = read_option(&args, "--operation").unwrap_or("healthCheck");
            let requested_at = read_u64_option(&args, "--at").unwrap_or(DEFAULT_NOW);
            let mut state = load_manager_state(path, requested_at)?;
            let request = ServiceOperationRequest {
                service_id: service_id.to_string(),
                operation: operation.to_string(),
                requested_at,
                dry_run: !args.iter().any(|arg| arg == "--execute"),
                blocked_reason: read_option(&args, "--blocked").map(str::to_string),
                fabric_control_role: read_option(&args, "--fabric-control-role")
                    .or_else(|| read_option(&args, "--control-role"))
                    .map(str::to_string),
            };
            let outcome = apply_service_operation(&mut state, request)?;
            save_manager_state(path, &state)?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        Some("status") => {
            let path = read_option(&args, "--state").unwrap_or(DEFAULT_STATE_PATH);
            let service_id = read_option(&args, "--service").unwrap_or("lab-service");
            let issued_at = read_u64_option(&args, "--at").unwrap_or(DEFAULT_NOW);
            let state = load_manager_state(path, issued_at)?;
            let posture = service_manager_status(&state, service_id, issued_at)?;
            println!("{}", serde_json::to_string_pretty(&posture)?);
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

fn read_u64_option(args: &[String], name: &str) -> Option<u64> {
    read_option(args, name).and_then(|value| value.parse::<u64>().ok())
}

fn print_help() {
    println!(
        "constitute-service-manager\n\nCommands:\n  fixture lifecycle\n  fixture lab-target\n  fixture fabric-transition\n  operation --operation <name> --state <state> [--blocked <reason>]\n  init --state <path> [--at <time>]\n  run --state <path> --operation <name> [--service <id>] [--at <time>] [--blocked <reason>] [--fabric-control-role <role>] [--execute]\n  status --state <path> [--service <id>] [--at <time>]\n"
    );
}
