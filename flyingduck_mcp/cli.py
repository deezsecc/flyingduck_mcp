import typer
import json
from flyingduck_mcp.modules import scan, fix, cleanup, fetch_repositories, fetch_dependencies, status
from flyingduck_mcp.utils.api_check import api_check

app = typer.Typer(help="Flyingduck-MCP: Modular Security Scanner CLI for LLM and Cursor integration.")

@app.command("scan")
def scan_cmd(
    scan_all: bool = typer.Option(False, help="Run all scans (SCA, SAST, Secrets)"),
    sca: bool = typer.Option(False, help="Run SCA scan only"),
    sast: bool = typer.Option(False, help="Run SAST scan only"),
    secrets: bool = typer.Option(False, help="Run secrets scan only"),
    repo_path: str = typer.Option(".", help="Path to the git repository to scan"),
    json_output: bool = typer.Option(False, help="Output raw JSON instead of pretty Rich output"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show verbose output for debugging and details.")
):
    """Run security scan with selected scan types."""
    api_check()
    result = scan.run(
        repo_path=repo_path,
        scan_all=scan_all,
        sca=sca,
        sast=sast,
        secrets=secrets,
        json_output=json_output,
        verbose=verbose
    )
    if json_output:
        typer.echo(json.dumps(result))
    else:
        # Rich output is handled in the module
        pass

@app.command()
def fix_cmd():
    """Attempt to auto-fix detected vulnerabilities."""
    api_check()
    result = fix.run()
    typer.echo(json.dumps(result))

@app.command()
def cleanup_cmd():
    """Clean up temporary scan artifacts."""
    api_check()
    result = cleanup.run()
    typer.echo(json.dumps(result))

@app.command()
def fetch_repositories_cmd():
    """Fetch all available repositories for scanning."""
    api_check()
    result = fetch_repositories.run()
    typer.echo(json.dumps(result))

@app.command()
def fetch_dependencies_cmd():
    """Catalog third-party dependencies for SCA."""
    api_check()
    result = fetch_dependencies.run()
    typer.echo(json.dumps(result))

@app.command()
def check_status_cmd():
    """Check scanner and tool status."""
    api_check()
    result = status.run()
    typer.echo(json.dumps(result))

if __name__ == "__main__":
    app() 