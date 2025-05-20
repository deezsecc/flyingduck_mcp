import os
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

def run(repo_path=".", scan_all=False, sca=False, sast=False, secrets=False, json_output=False):
    fd_api_key = os.environ.get("FD_API_KEY")
    if not fd_api_key:
        error = {
            "status": "error",
            "error": "Missing FD_API_KEY environment variable."
        }
        if json_output:
            return error
        else:
            console.print(Panel("[red]Missing FD_API_KEY environment variable.[/red]", title="Error"))
            return

    # Build flags
    flags = []
    if scan_all or (not sca and not sast and not secrets):
        flags = ["--sca", "--secrets", "--sast"]
    else:
        if sca:
            flags.append("--sca")
        if sast:
            flags.append("--sast")
        if secrets:
            flags.append("--secrets")

    docker_cmd = [
        "docker", "run",
        "-e", f"FD_API_KEY={fd_api_key}",
        "-v", f"{os.path.abspath(repo_path)}:/src",
        "--entrypoint", "/bin/bash",
        "flyingduckio/duckdefender:latest",
        "-c", f"duckdefender pre-commit {' '.join(flags)}"
    ]

    try:
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=600
        )
        output = result.stdout
        error = result.stderr
        status = "success" if result.returncode == 0 else "error"
        data = {
            "status": status,
            "command": "pre-commit",
            "docker_cmd": " ".join(docker_cmd),
            "output": output,
            "error": error,
            "returncode": result.returncode
        }
        if json_output:
            return data
        else:
            _display_rich_output(output, error, result.returncode)
            return
    except Exception as e:
        if json_output:
            return {
                "status": "error",
                "command": "pre-commit",
                "error": str(e)
            }
        else:
            console.print(Panel(f"[red]{str(e)}[/red]", title="Error"))
            return

def _display_rich_output(output, error, returncode):
    # Print scan summary and findings using Rich
    console.rule("[bold blue]Flyingduck Pre-Commit Scan Results")
    if output:
        # Try to parse and highlight vulnerabilities
        _print_findings(output)
    if error:
        console.print(Panel(error, title="[yellow]Docker/Agent Info[/yellow]"))
    if returncode == 0:
        console.print(Panel("[green]No vulnerabilities found. Commit is safe![/green]", title="Result"))
    else:
        console.print(Panel("[red]Vulnerabilities or issues detected! See above for details.[/red]", title="Result"))

def _print_findings(output):
    # Heuristic: print lines with 'detected', 'issue', 'vulnerab', 'secret', 'error', 'warning', etc.
    lines = output.splitlines()
    findings = []
    for line in lines:
        if any(word in line.lower() for word in ["detected", "issue", "vulnerab", "secret", "error", "warning"]):
            findings.append(line)
    if findings:
        table = Table(title="Potential Findings", show_lines=True)
        table.add_column("Details", style="red")
        for finding in findings:
            table.add_row(finding)
        console.print(table)
    else:
        console.print(Panel("[green]No findings reported in scan output.[/green]")) 