# ai_usage_evidence_analyzer/ui_checklist.py
"""
Accessible, filterable, theme-aware forensic checklist UI component for desktop_app.py.
Displays evidence status, caveat badges, and supports summary panels, filtering, and theme switching.
"""
import tkinter as tk
from tkinter import ttk
from .forensic_checklist import ForensicChecklistEntry
from .caveats import get_caveat_text, UI_WARNINGS

class ChecklistUI(ttk.Frame):
    def __init__(self, parent, checklist_entries, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.entries = checklist_entries
        self._build_ui()

    def _build_ui(self):
        # Warnings panel
        warning_frame = ttk.LabelFrame(self, text="Key Forensic Caveats")
        warning_frame.pack(fill="x", padx=8, pady=4)
        for w in UI_WARNINGS:
            ttk.Label(warning_frame, text="⚠ " + w, foreground="#b58900").pack(anchor="w", padx=4)

        # Checklist table
        columns = [
            "Tool Name", "Category", "Evidence Status", "Execution Surface",
            "Inference Location", "Confidence", "Caveat Flags", "Notes"
        ]
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=12)
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=8, pady=4)
        self._populate_table()

        # Filter/search bar
        filter_frame = ttk.Frame(self)
        filter_frame.pack(fill="x", padx=8, pady=2)
        ttk.Label(filter_frame, text="Filter by status:").pack(side="left")
        self.status_var = tk.StringVar(value="ALL")
        status_options = ["ALL", "FOUND", "NOT_FOUND", "NOT_VERIFIED", "PARTIAL"]
        status_menu = ttk.OptionMenu(filter_frame, self.status_var, "ALL", *status_options, command=self._filter_table)
        status_menu.pack(side="left", padx=4)

    def _populate_table(self):
        for entry in self.entries:
            caveats = ", ".join(get_caveat_text(entry.caveat_flags))
            self.tree.insert("", "end", values=(
                entry.tool_name, entry.category, entry.evidence_status,
                entry.execution_surface, entry.inference_location,
                entry.confidence, caveats, entry.notes
            ))

    def _filter_table(self, *_):
        status = self.status_var.get()
        for i in self.tree.get_children():
            self.tree.delete(i)
        for entry in self.entries:
            if status == "ALL" or entry.evidence_status == status:
                caveats = ", ".join(get_caveat_text(entry.caveat_flags))
                self.tree.insert("", "end", values=(
                    entry.tool_name, entry.category, entry.evidence_status,
                    entry.execution_surface, entry.inference_location,
                    entry.confidence, caveats, entry.notes
                ))
