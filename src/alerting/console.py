"""Rich-formatted console alerter for local runs and screenshots."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


_SEV_COLOR = {"low": "cyan", "medium": "yellow", "high": "red", "critical": "bold red"}


class ConsoleAlerter:
    def __init__(self) -> None:
        self.console = Console()

    def send(self, alert: dict) -> None:
        sev = alert.get("severity", "medium")
        color = _SEV_COLOR.get(sev, "white")

        table = Table.grid(padding=(0, 1))
        table.add_row("[bold]Rule[/bold]", str(alert.get("rule_name")))
        table.add_row("[bold]Severity[/bold]", f"[{color}]{sev.upper()}[/{color}]")
        table.add_row("[bold]MITRE[/bold]", str(alert.get("mitre")))
        table.add_row("[bold]Source IP[/bold]", str(alert.get("source_ip")))
        table.add_row("[bold]User[/bold]", str(alert.get("user")))
        table.add_row("[bold]Count[/bold]", str(alert.get("match_count")))
        table.add_row("[bold]When[/bold]", str(alert.get("timestamp")))
        if alert.get("enrichment"):
            e = alert["enrichment"]
            table.add_row(
                "[bold]Abuse score[/bold]",
                f"{e.get('abuse_confidence_score')} ({e.get('country_code')} / {e.get('isp')})",
            )

        self.console.print(
            Panel(
                table,
                title=f"[{color}]ALERT: {alert.get('rule_id')}[/{color}]",
                border_style=color,
            )
        )
