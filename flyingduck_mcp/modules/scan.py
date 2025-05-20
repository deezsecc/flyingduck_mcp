import os
import subprocess
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
import requests
import re

console = Console()

FD_API_URL = "https://api.flyingduck.io/assets/v3/getVulnDetailsByName"

def run(repo_path=".", scan_all=False, sca=False, sast=False, secrets=False, json_output=False, verbose=False):
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

    # If SCA is requested, check dependencies/versions first
    if sca or scan_all:
        valid, error_msg = _check_sca_dependencies(repo_path, verbose)
        if not valid:
            console.print(Panel(f"[red]{error_msg}[/red]", title="SCA Error"))
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
            "command": "scan",
            "docker_cmd": " ".join(docker_cmd),
            "output": output,
            "error": error,
            "returncode": result.returncode
        }
        if sca and (scan_all or sca):
            # Only do SCA vuln lookup if --sca or --scan-all
            _handle_sca_vulns(repo_path, json_output, verbose)
        if json_output:
            return data
        else:
            _display_rich_output(output, error, result.returncode)
            return
    except Exception as e:
        if json_output:
            return {
                "status": "error",
                "command": "scan",
                "error": str(e)
            }
        else:
            console.print(Panel(f"[red]{str(e)}[/red]", title="Error"))
            return

def _check_sca_dependencies(repo_path, verbose):
    # Recursively find requirements.txt, package.json, and package-lock.json
    found_files = []
    for root, dirs, files in os.walk(repo_path):
        for fname in files:
            if fname in ("requirements.txt", "package.json", "package-lock.json", "go.mod"):
                found_files.append(os.path.join(root, fname))
    if verbose:
        console.print(Panel(f"[bold]Dependency files found:[/bold]\n" + "\n".join(found_files), title="Verbose: Files Found"))
    seen = set()
    for fpath in found_files:
        if fpath.endswith("requirements.txt"):
            try:
                with open(fpath) as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        line = re.sub(r"\[.*\]", "", line)
                        match = re.match(r"^([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-]+)$", line)
                        if match:
                            name, version = match.groups()
                            key = (name.strip(), version.strip(), "pypi")
                            if key not in seen:
                                seen.add(key)
                        elif "==" in line:
                            return False, f"No version info is found for line: '{line}'. Unable to continue."
                        elif re.match(r"^[A-Za-z0-9_.\-]+$", line):
                            return False, f"No version info is found for line: '{line}'. Unable to continue."
            except Exception as e:
                if verbose:
                    console.print(Panel(f"[yellow]Failed to parse {fpath}: {e}[/yellow]", title="Verbose"))
        elif fpath.endswith("package.json"):
            try:
                with open(fpath) as f:
                    pkg = json.load(f)
                for dep_type in ["dependencies", "devDependencies"]:
                    for name, version in pkg.get(dep_type, {}).items():
                        key = (name.strip(), version.strip().lstrip("^~"), "npm")
                        if not version or version.strip() == "":
                            return False, f"No version info is found for package: '{name}'. Unable to continue."
                        if key not in seen:
                            seen.add(key)
            except Exception as e:
                if verbose:
                    console.print(Panel(f"[yellow]Failed to parse {fpath}: {e}[/yellow]", title="Verbose"))
        elif fpath.endswith("package-lock.json"):
            try:
                with open(fpath) as f:
                    lock = json.load(f)
                for name, meta in lock.get("dependencies", {}).items():
                    version = meta.get("version", "")
                    key = (name.strip(), version.strip(), "npm")
                    if not version or version.strip() == "":
                        return False, f"No version info is found for package: '{name}' in package-lock.json. Unable to continue."
                    if key not in seen:
                        seen.add(key)
            except Exception as e:
                if verbose:
                    console.print(Panel(f"[yellow]Failed to parse {fpath}: {e}[/yellow]", title="Verbose"))
        elif fpath.endswith("go.mod"):
            try:
                with open(fpath) as f:
                    in_require_block = False
                    for line in f:
                        line = line.strip()
                        if line.startswith("require ("):
                            in_require_block = True
                            continue
                        if in_require_block and line == ")":
                            in_require_block = False
                            continue
                        if in_require_block or line.startswith("require "):
                            # Remove 'require' if present
                            if line.startswith("require "):
                                line = line[len("require "):].strip()
                            # Remove comments
                            line = line.split("//")[0].strip()
                            if not line:
                                continue
                            parts = line.split()
                            if len(parts) >= 2:
                                name, version = parts[0], parts[1]
                                key = (name.strip(), version.strip(), "go")
                                if not version or version.strip() == "":
                                    return False, f"No version info is found for Go module: '{name}'. Unable to continue."
                                if key not in seen:
                                    seen.add(key)
            except Exception as e:
                if verbose:
                    console.print(Panel(f"[yellow]Failed to parse {fpath}: {e}[/yellow]", title="Verbose"))
    # At the end, print the accurate count of unique dependencies (for debug/verbose)
    if verbose:
        console.print(Panel(f"[bold green]Total unique dependencies detected: {len(seen)}[/bold green]", title="Dependency Count"))
    return True, None

def _handle_sca_vulns(repo_path, json_output, verbose):
    # Recursively find requirements.txt, package.json, and package-lock.json
    found_files = []
    for root, dirs, files in os.walk(repo_path):
        for fname in files:
            if fname in ("requirements.txt", "package.json", "package-lock.json", "go.mod"):
                found_files.append(os.path.join(root, fname))
    if verbose:
        console.print(Panel(f"[bold]Dependency files found:[/bold]\n" + "\n".join(found_files), title="Verbose: Files Found"))
    # Parse all found files
    libraries = []
    seen = set()  # (name, version, type)
    for fpath in found_files:
        if fpath.endswith("requirements.txt"):
            try:
                with open(fpath) as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        line = re.sub(r"\[.*\]", "", line)
                        match = re.match(r"^([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-]+)$", line)
                        if match:
                            name, version = match.groups()
                            key = (name.strip(), version.strip(), "pypi")
                            if key not in seen:
                                libraries.append({
                                    "library_name": name.strip(),
                                    "version": version.strip(),
                                    "type": "pypi"
                                })
                                seen.add(key)
            except Exception as e:
                if verbose:
                    console.print(Panel(f"[yellow]Failed to parse {fpath}: {e}[/yellow]", title="Verbose"))
        elif fpath.endswith("package.json"):
            try:
                with open(fpath) as f:
                    pkg = json.load(f)
                for dep_type in ["dependencies", "devDependencies"]:
                    for name, version in pkg.get(dep_type, {}).items():
                        key = (name.strip(), version.strip().lstrip("^~"), "npm")
                        if key not in seen:
                            libraries.append({
                                "library_name": name.strip(),
                                "version": version.strip().lstrip("^~"),
                                "type": "npm"
                            })
                            seen.add(key)
            except Exception as e:
                if verbose:
                    console.print(Panel(f"[yellow]Failed to parse {fpath}: {e}[/yellow]", title="Verbose"))
        elif fpath.endswith("package-lock.json"):
            try:
                with open(fpath) as f:
                    lock = json.load(f)
                for name, meta in lock.get("dependencies", {}).items():
                    version = meta.get("version", "")
                    key = (name.strip(), version.strip(), "npm")
                    if key not in seen:
                        libraries.append({
                            "library_name": name.strip(),
                            "version": version.strip(),
                            "type": "npm"
                        })
                        seen.add(key)
            except Exception as e:
                if verbose:
                    console.print(Panel(f"[yellow]Failed to parse {fpath}: {e}[/yellow]", title="Verbose"))
        elif fpath.endswith("go.mod"):
            try:
                with open(fpath) as f:
                    in_require_block = False
                    for line in f:
                        line = line.strip()
                        if line.startswith("require ("):
                            in_require_block = True
                            continue
                        if in_require_block and line == ")":
                            in_require_block = False
                            continue
                        if in_require_block or line.startswith("require "):
                            # Remove 'require' if present
                            if line.startswith("require "):
                                line = line[len("require "):].strip()
                            # Remove comments
                            line = line.split("//")[0].strip()
                            if not line:
                                continue
                            parts = line.split()
                            if len(parts) >= 2:
                                name, version = parts[0], parts[1]
                                key = (name.strip(), version.strip(), "go")
                                if key not in seen:
                                    libraries.append({
                                        "library_name": name.strip(),
                                        "version": version.strip(),
                                        "type": "go"
                                    })
                                    seen.add(key)
            except Exception as e:
                if verbose:
                    console.print(Panel(f"[yellow]Failed to parse {fpath}: {e}[/yellow]", title="Verbose"))
    # Show detected libraries in a Rich table
    if libraries:
        table = Table(title="Detected Libraries", show_lines=True)
        table.add_column("Library", style="cyan")
        table.add_column("Version", style="magenta")
        table.add_column("Type", style="yellow")
        for lib in libraries:
            table.add_row(lib["library_name"], lib["version"], lib["type"])
        console.print(table)
        # Print the accurate count of unique dependencies
        console.print(Panel(f"[bold green]Total unique dependencies detected: {len(libraries)}[/bold green]", title="Dependency Count"))
    else:
        console.print(Panel("[yellow]No libraries detected in requirements.txt, package.json, or package-lock.json (including subfolders).[/yellow]", title="SCA Libraries"))
        return
    # Verbose: show the libraries as JSON
    if verbose:
        payload = {"libraries": libraries}
        console.print(Panel(f"[bold]Detected libraries (JSON):[/bold]\n{json.dumps(payload, indent=2)}", title="Verbose: Libraries JSON"))
    # Read Bearer token from .git/hooks/duckdefender
    token_path = os.path.join(repo_path, ".git", "hooks", "duckdefender")
    if not os.path.exists(token_path):
        console.print(Panel("[red]duckdefender token file not found. Please login first.[/red]", title="Auth Error"))
        return
    with open(token_path, "r") as f:
        token_data = json.load(f)
    access_token = token_data.get("access")
    if not access_token:
        console.print(Panel("[red]Access token not found in duckdefender file.[/red]", title="Auth Error"))
        return
    # Build API request
    payload = {"libraries": libraries}
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    if verbose:
        console.print(Panel(f"[bold]SCA API Payload:[/bold]\n{json.dumps(payload, indent=2)}", title="Verbose: API Payload"))
        console.print(Panel("[bold yellow]Sending SCA API request...[/bold yellow]", title="Verbose: API Call"))
    try:
        resp = requests.post(FD_API_URL, headers=headers, json=payload, timeout=30)
        if verbose:
            console.print(Panel(f"[bold]SCA API Response:[/bold]\n{resp.text}", title="Verbose: API Response"))
        if resp.status_code == 200:
            vuln_data = resp.json()
            _display_sca_vulns(vuln_data)
        else:
            console.print(Panel(f"[red]API error: {resp.status_code} {resp.text}[/red]", title="SCA API Error"))
    except Exception as e:
        console.print(Panel(f"[red]API request failed: {e}[/red]", title="SCA API Error"))

def _display_sca_vulns(vuln_data):
    # Display vulnerabilities in a Rich table
    if not vuln_data or not vuln_data.get("data"):
        console.print(Panel("[green]No SCA vulnerabilities found![/green]", title="SCA Vulnerabilities"))
        return
    table = Table(title="SCA Vulnerabilities", show_lines=True)
    table.add_column("Library", style="cyan")
    table.add_column("Version", style="magenta")
    table.add_column("Type", style="yellow")
    table.add_column("CVE", style="red")
    table.add_column("Severity", style="bold red")
    table.add_column("Description", style="white")
    for item in vuln_data["data"]:
        lib = item.get("library_name", "?")
        ver = item.get("version", "?")
        typ = item.get("type", "?")
        for vuln in item.get("vulnerabilities", []):
            cve = vuln.get("cve_id", "?")
            sev = vuln.get("severity", "?")
            desc = vuln.get("description", "?")
            table.add_row(lib, ver, typ, cve, sev, desc)
    console.print(table)

def _display_rich_output(output, error, returncode):
    console.rule("[bold blue]Flyingduck Security Scan Results")
    if output:
        console.print(Panel(output, title="[cyan]Scan Output[/cyan]", expand=False))
    if error:
        console.print(Panel(error, title="[yellow]Docker/Agent Info[/yellow]", expand=False))
    if returncode == 0:
        console.print(Panel("[green]No vulnerabilities found. Project is safe![/green]", title="Result"))
    else:
        console.print(Panel("[red]Vulnerabilities or issues detected! See above for details.[/red]", title="Result")) 