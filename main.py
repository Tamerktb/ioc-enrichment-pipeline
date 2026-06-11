#!/usr/bin/env python3
"""
IOC Enrichment Pipeline — CLI Entry Point

Usage:
    python main.py enrich --type ip --value 8.8.8.8
    python main.py enrich --file tests/sample_iocs.csv
    python main.py enrich --type ip --value 185.130.5.173 --format splunk
    python main.py enrich --type ip --value 185.130.5.173 --llm-summary
    python main.py tools
    python main.py cache-stats
    python main.py cache-clear
"""

import argparse
import sys
import os
import logging
from pathlib import Path

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import yaml
    from dotenv import load_dotenv
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
except ImportError:
    print("Missing dependencies. Run: pip install -r requirements.txt")
    sys.exit(1)

from pipeline.orchestrator import PipelineOrchestrator
from pipeline.ioc_parser import IOCParser

console = Console()
logger = logging.getLogger(__name__)


def load_config(config_path: str = "config.yaml") -> dict:
    """Load configuration from YAML file."""
    config = {}
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            config = yaml.safe_load(f) or {}
    return config


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_enrich(args, config: dict):
    """Enrich one or more IOCs."""
    orchestrator = PipelineOrchestrator(config)

    iocs = []

    if args.file:
        # Parse from file
        try:
            iocs = IOCParser.parse_file(args.file)
            console.print(f"[cyan]Parsed {len(iocs)} IOCs from {args.file}[/cyan]")
        except Exception as e:
            console.print(f"[red]Error parsing file: {e}[/red]")
            sys.exit(1)
    elif args.type and args.value:
        # Single IOC from CLI args
        try:
            ioc = IOCParser.parse_single(args.value, args.type)
            iocs = [ioc]
        except Exception as e:
            console.print(f"[red]Error parsing IOC: {e}[/red]")
            sys.exit(1)
    else:
        console.print("[yellow]Provide either --type + --value or --file[/yellow]")
        sys.exit(1)

    output_format = args.format or config.get("output", {}).get("default_format", "json")
    use_llm = args.llm_summary

    results = orchestrator.process_iocs(iocs, use_llm=use_llm, output_format=output_format)

    # Display results
    for result in results:
        if output_format == "table":
            # Rich-rendered table
            console.print(Panel(result["output"], title=f"IOC: {result['ioc'].value}", border_style="blue"))
        else:
            # JSON or Splunk — print raw
            print(result["output"])

        # Print summary line for each IOC
        score = result["score"]
        severity_colors = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "green",
            "none": "white",
        }
        color = severity_colors.get(score.get("severity", "none"), "white")
        cache_tag = "[dim](cached)[/dim]" if result["was_cached"] else ""
        console.print(
            f"  {result['ioc'].type.upper()} {result['ioc'].value} "
            f"→ Score: [bold {color}]{score.get('score', 'N/A')}/10 ({score.get('severity', 'N/A').upper()})[/bold {color}] "
            f"Latency: {result['elapsed']}s {cache_tag}"
        )

    # Summary
    stats = orchestrator.get_stats()
    console.print()
    console.print(f"[dim]Processed {stats['iocs_processed']} IOC(s) in {stats.get('total_time', 0):.2f}s[/dim]")
    console.print(f"[dim]Cache: {stats['cache_stats']['hits']} hits, {stats['cache_stats']['misses']} misses[/dim]")

    # Save to file if requested
    if args.save:
        timestamp = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"enrichment_report_{timestamp}.{output_format}"
        content = "\n".join(r["output"] for r in results)
        filepath = orchestrator.output.save_report(filename, content)
        console.print(f"[green]Report saved to: {filepath}[/green]")


def cmd_tools(args, config: dict):
    """List available enrichment tools."""
    orchestrator = PipelineOrchestrator(config)
    tools = orchestrator.manager.available_tools

    table = Table(title="Available Enrichment Tools", border_style="cyan")
    table.add_column("Tool", style="bold green")
    table.add_column("Description")
    table.add_column("Status")

    for name, desc in tools.items():
        # Check if the tool needs API keys
        needs_key = name in ("virustotal", "abuseipdb")
        if needs_key:
            import os as _os
            key_name = f"{name.upper()}_API_KEY"
            has_key = bool(_os.getenv(key_name, ""))
            status = "[green]✓ Ready[/green]" if has_key else "[yellow]No API key (limited)[/yellow]"
        else:
            status = "[green]✓ Ready[/green]"
        table.add_row(name, desc, status)

    console.print(table)
    console.print()
    console.print("[dim]Tip: Tools without API keys will still execute with limited data.[/dim]")
    console.print("[dim]Set API keys in .env file.[/dim]")


def cmd_cache_stats(args, config: dict):
    """Show cache statistics."""
    orchestrator = PipelineOrchestrator(config)
    stats = orchestrator.cache.stats()

    table = Table(title="Cache Statistics", border_style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Total entries", str(stats["total_entries"]))
    table.add_row("Expired entries", str(stats["expired_entries"]))
    table.add_row("Hits (this session)", str(stats["hits"]))
    table.add_row("Misses (this session)", str(stats["misses"]))
    table.add_row("Stale (expired, cleaned)", str(stats["stale"]))
    table.add_row("Hit rate", f"{stats['hit_rate']:.1%}")
    table.add_row("Database path", stats["db_path"])

    console.print(table)


def cmd_cache_clear(args, config: dict):
    """Clear the enrichment cache."""
    confirm = input("Clear all cache entries? [y/N]: ")
    if confirm.lower() in ("y", "yes"):
        orchestrator = PipelineOrchestrator(config)
        orchestrator.cache.clear()
        console.print("[green]Cache cleared.[/green]")
    else:
        console.print("[yellow]Cancelled.[/yellow]")


def main():
    parser = argparse.ArgumentParser(
        description="IOC Enrichment Pipeline — Automated threat intel enrichment for SOC analysts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py enrich --type ip --value 8.8.8.8
  python main.py enrich --file tests/sample_iocs.csv --format splunk
  python main.py enrich --type ip --value 185.130.5.173 --llm-summary
  python main.py tools
  python main.py cache-stats
        """,
    )
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Enrich command
    enrich_parser = subparsers.add_parser("enrich", help="Enrich one or more IOCs")
    enrich_parser.add_argument("--type", "-t", choices=["ip", "domain", "hash", "url", "email"],
                               help="IOC type (auto-detected if omitted with --file)")
    enrich_parser.add_argument("--value", "-v", help="IOC value")
    enrich_parser.add_argument("--file", "-f", help="Input file (.csv, .json, .txt)")
    enrich_parser.add_argument("--format", choices=["json", "splunk", "table"], default=None,
                               help="Output format (default: config setting)")
    enrich_parser.add_argument("--llm-summary", action="store_true",
                               help="Generate LLM threat summary (requires API key)")
    enrich_parser.add_argument("--save", action="store_true",
                               help="Save report to file")

    # Tools command
    subparsers.add_parser("tools", help="List available enrichment tools")

    # Cache commands
    subparsers.add_parser("cache-stats", help="Show cache statistics")
    subparsers.add_parser("cache-clear", help="Clear all cache entries")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Load .env and config
    load_dotenv()
    config = load_config(args.config)
    setup_logging(args.verbose)

    # Route commands
    commands = {
        "enrich": cmd_enrich,
        "tools": cmd_tools,
        "cache-stats": cmd_cache_stats,
        "cache-clear": cmd_cache_clear,
    }

    cmd_fn = commands.get(args.command)
    if cmd_fn:
        cmd_fn(args, config)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()