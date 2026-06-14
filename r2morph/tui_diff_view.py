"""Standalone diff view for the TUI."""

from __future__ import annotations

from r2morph import tui_diff_helpers as _helpers
from r2morph.tui_models import TUIMutation
from r2morph.tui_rendering import RICH_AVAILABLE, Console, Table

build_disasm_diff_rows = _helpers.build_disasm_diff_rows
count_byte_differences = _helpers.count_byte_differences
count_disasm_changed_lines = _helpers.count_disasm_changed_lines


class DiffView:
    """
    Display before/after diff view for mutations.

    Shows disassembly changes with syntax highlighting.
    """

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self._mutations: list[TUIMutation] = []
        self._current_idx: int = 0

    def set_mutations(self, mutations: list[TUIMutation]) -> None:
        """Set mutations to display."""
        self._mutations = mutations
        self._current_idx = 0

    def next(self) -> bool:
        """Go to next mutation. Returns True if successful."""
        if self._current_idx < len(self._mutations) - 1:
            self._current_idx += 1
            return True
        return False

    def previous(self) -> bool:
        """Go to previous mutation. Returns True if successful."""
        if self._current_idx > 0:
            self._current_idx -= 1
            return True
        return False

    def current(self) -> TUIMutation | None:
        """Get current mutation."""
        if 0 <= self._current_idx < len(self._mutations):
            return self._mutations[self._current_idx]
        return None

    def render(self) -> None:
        """Render the diff view."""
        if RICH_AVAILABLE:
            self._render_rich()
        else:
            self._render_basic()

    def _render_rich(self) -> None:
        """Render diff view with rich formatting."""
        if not self._mutations:
            self.console.print("[yellow]No mutations to display[/yellow]")
            return

        mutation = self._mutations[self._current_idx]

        self.console.print(f"\n[bold]Mutation {self._current_idx + 1} of {len(self._mutations)}[/bold]")
        self.console.print(f"[cyan]Function:[/cyan] {mutation.function or 'unknown'}")
        self.console.print(f"[cyan]Address:[/cyan] 0x{mutation.address:x}")
        self.console.print(f"[cyan]Pass:[/cyan] {mutation.pass_name}")

        if mutation.description:
            self.console.print(f"[dim]{mutation.description}[/dim]")

        orig_hex = mutation.original_bytes.hex() if mutation.original_bytes else "N/A"
        mut_hex = mutation.mutated_bytes.hex() if mutation.mutated_bytes else "N/A"

        table = Table(title="Bytes Diff", show_header=True)
        table.add_column("Type", style="cyan")
        table.add_column("Bytes", style="green")

        table.add_row("Original", orig_hex)
        table.add_row("Mutated", mut_hex)

        self.console.print(table)

        if mutation.original_bytes and mutation.mutated_bytes:
            diff_table = Table(title="Byte Differences", show_header=True)
            diff_table.add_column("Offset", style="dim")
            diff_table.add_column("Original", style="red")
            diff_table.add_column("Mutated", style="green")
            diff_table.add_column("Status", style="yellow")

            max_len = max(len(mutation.original_bytes), len(mutation.mutated_bytes))
            for i in range(min(max_len, 16)):
                orig_byte = mutation.original_bytes[i : i + 1].hex() if i < len(mutation.original_bytes) else "--"
                mut_byte = mutation.mutated_bytes[i : i + 1].hex() if i < len(mutation.mutated_bytes) else "--"

                status = "changed" if orig_byte != mut_byte else "same"
                diff_table.add_row(f"0x{i:x}", orig_byte, mut_byte, status)

            self.console.print(diff_table)

        self.console.print("\n[dim]n: next | p: previous | q: quit[/dim]")

    def _render_basic(self) -> None:
        """Render diff view with basic formatting."""
        if not self._mutations:
            print("No mutations to display")
            return

        mutation = self._mutations[self._current_idx]

        print(f"\nMutation {self._current_idx + 1} of {len(self._mutations)}")
        print(f"Function: {mutation.function or 'unknown'}")
        print(f"Address: 0x{mutation.address:x}")
        print(f"Pass: {mutation.pass_name}")

        if mutation.description:
            print(f"  {mutation.description}")

        orig_hex = mutation.original_bytes.hex() if mutation.original_bytes else "N/A"
        mut_hex = mutation.mutated_bytes.hex() if mutation.mutated_bytes else "N/A"

        print(f"\nOriginal: {orig_hex}")
        print(f"Mutated:  {mut_hex}")
        print("\nn: next | p: previous | q: quit")

    def render_summary(self) -> None:
        """Render summary of all mutations."""
        if not self._mutations:
            self.console.print("[yellow]No mutations to summarize[/yellow]")
            return

        if RICH_AVAILABLE:
            table = Table(title="Mutation Summary")
            table.add_column("#", style="dim")
            table.add_column("Address", style="cyan")
            table.add_column("Function", style="green")
            table.add_column("Pass", style="yellow")
            table.add_column("Size", style="magenta")

            for i, mut in enumerate(self._mutations):
                table.add_row(
                    str(i + 1),
                    f"0x{mut.address:x}",
                    mut.function or "unknown",
                    mut.pass_name,
                    str(len(mut.mutated_bytes)) if mut.mutated_bytes else "0",
                )

            self.console.print(table)
        else:
            print("\nMutation Summary:")
            for i, mut in enumerate(self._mutations):
                print(f"  {i + 1}. 0x{mut.address:x} - {mut.function or 'unknown'} - {mut.pass_name}")

    def render_disasm_diff(self) -> None:
        """Render disassembly diff view with side-by-side comparison."""
        if not self._mutations:
            self.console.print("[yellow]No mutations to display[/yellow]")
            return

        mutation = self._mutations[self._current_idx]

        if RICH_AVAILABLE:
            self._render_disasm_rich(mutation)
        else:
            self._render_disasm_basic(mutation)

    def _render_disasm_rich(self, mutation: TUIMutation) -> None:
        """Render disassembly diff with rich formatting."""
        self.console.print(
            f"\n[bold]Disassembly Diff - Mutation {self._current_idx + 1} of {len(self._mutations)}[/bold]"
        )
        self.console.print(f"[cyan]Function:[/cyan] {mutation.function or 'unknown'}")
        self.console.print(f"[cyan]Address:[/cyan] 0x{mutation.address:x}")
        self.console.print(f"[cyan]Pass:[/cyan] {mutation.pass_name}")

        if mutation.description:
            self.console.print(f"[dim]{mutation.description}[/dim]")

        orig_lines = mutation.original_disasm or []
        mut_lines = mutation.mutated_disasm or []

        if not orig_lines and not mut_lines:
            self.console.print("[yellow]No disassembly available[/yellow]")
            self._render_rich()
            return

        table = Table(title="Disassembly Comparison", show_header=True, expand=True)
        table.add_column("#", style="dim", width=3)
        table.add_column("Original", style="red", ratio=1)
        table.add_column("Mutated", style="green", ratio=1)
        table.add_column("Status", style="yellow", width=8)

        for row in build_disasm_diff_rows(orig_lines, mut_lines, limit=50, display_width=50):
            table.add_row(str(row.index), row.original, row.mutated, row.status)

        self.console.print(table)

        changed_count = count_disasm_changed_lines(orig_lines, mut_lines)
        self.console.print(f"\n[bold]Stats:[/bold] {changed_count} lines changed")

        self._render_byte_diff_summary(mutation)

    def _render_byte_diff_summary(self, mutation: TUIMutation) -> None:
        """Render a summary of byte-level differences."""
        orig_bytes = mutation.original_bytes or b""
        mut_bytes = mutation.mutated_bytes or b""

        if orig_bytes == mut_bytes:
            return

        diff_count, total = count_byte_differences(orig_bytes, mut_bytes)

        if diff_count > 0:
            self.console.print(f"[dim]Byte changes: {diff_count} / {total} bytes[/dim]")

    def _render_disasm_basic(self, mutation: TUIMutation) -> None:
        """Render disassembly diff with basic formatting."""
        print(f"\nDisassembly Diff - Mutation {self._current_idx + 1} of {len(self._mutations)}")
        print(f"Function: {mutation.function or 'unknown'}")
        print(f"Address: 0x{mutation.address:x}")
        print(f"Pass: {mutation.pass_name}")

        if mutation.description:
            print(f"  {mutation.description}")

        orig_lines = mutation.original_disasm or []
        mut_lines = mutation.mutated_disasm or []

        print("\nOriginal:")
        for line in orig_lines[:20]:
            print(f"  {line}")

        print("\nMutated:")
        for line in mut_lines[:20]:
            print(f"  {line}")

        changed_count = count_disasm_changed_lines(orig_lines, mut_lines)
        print(f"\nStats: {changed_count} lines changed")
