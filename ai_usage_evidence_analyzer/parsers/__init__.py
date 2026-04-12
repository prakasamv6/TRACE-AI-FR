"""
Artifact parsers package.

Importing this package will register all parsers with the global ParserRegistry.
"""

from . import browser_parsers
from . import windows_parsers
from . import macos_parsers
from . import iphone_parsers
from . import android_parsers
from . import content_parsers
from . import plugin_parsers
from . import antiforensics_parsers
from . import c2pa_parser
from . import chatgpt_export_parser
from . import memory_pcap_parser
from . import recovery_parsers
