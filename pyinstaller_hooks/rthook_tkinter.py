"""Configure Tcl/Tk paths for the frozen TRACE-AI-FR desktop app."""
import os
import sys
from pathlib import Path


base_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
tcl_dir = base_dir / "tcl"
tcl_library = tcl_dir / "tcl8.6"
tk_library = tcl_dir / "tk8.6"

if tcl_library.exists():
    os.environ.setdefault("TCL_LIBRARY", str(tcl_library))
if tk_library.exists():
    os.environ.setdefault("TK_LIBRARY", str(tk_library))
