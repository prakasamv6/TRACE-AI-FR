"""
Parser registry and base parser interface.

All artifact parsers implement the BaseParser interface and register
themselves with the ParserRegistry for automatic discovery and execution.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Type

from .models import (
    ArtifactRecord,
    OSPlatform,
    ParserResult,
    ParserStatus,
    ProcessingLog,
)

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """
    Abstract base class for all artifact parsers.

    Each parser:
    - Declares what OS platforms it supports
    - Declares what artifact types it targets
    - Accepts an evidence root path and user profile
    - Returns a ParserResult containing found artifacts and logs
    """

    # Subclasses must set these
    PARSER_NAME: str = "BaseParser"
    PARSER_VERSION: str = "1.0.0"
    SUPPORTED_OS: List[OSPlatform] = []
    ARTIFACT_FAMILY: str = "Unknown"
    IS_STUB: bool = False  # Set True for scaffold-only parsers

    def __init__(self, evidence_root: str, user_profile: str = "",
                 case_id: str = "", evidence_item_id: str = "",
                 source_image: str = ""):
        self.evidence_root = evidence_root
        self.user_profile = user_profile
        self.case_id = case_id
        self.evidence_item_id = evidence_item_id
        self.source_image = source_image
        self.logs: List[ProcessingLog] = []

    @abstractmethod
    def parse(self) -> ParserResult:
        """Execute the parser and return results."""
        ...

    def supports_os(self, os_platform: OSPlatform) -> bool:
        """Check if this parser supports the given OS."""
        return os_platform in self.SUPPORTED_OS

    def _make_result(
        self,
        status: ParserStatus = ParserStatus.SUCCESS,
        artifacts: Optional[List[ArtifactRecord]] = None,
        errors: Optional[List[str]] = None,
        warnings: Optional[List[str]] = None,
        paths_searched: Optional[List[str]] = None,
        paths_found: Optional[List[str]] = None,
        paths_missing: Optional[List[str]] = None,
        elapsed_ms: float = 0.0,
        notes: str = "",
        artifact_coverage: Optional[List['ArtifactCoverageRecord']] = None,
        coverage_gaps: Optional[List['CoverageGapRecord']] = None,
        parse_failures: Optional[List['ParseFailureRecord']] = None,
        unsupported_artifacts: Optional[List['UnsupportedArtifactRecord']] = None,
    ) -> ParserResult:
        return ParserResult(
            parser_name=self.PARSER_NAME,
            parser_version=self.PARSER_VERSION,
            status=status,
            artifacts_found=artifacts or [],
            errors=errors or [],
            warnings=warnings or [],
            processing_time_ms=elapsed_ms,
            artifact_paths_searched=paths_searched or [],
            artifact_paths_found=paths_found or [],
            artifact_paths_missing=paths_missing or [],
            notes=notes,
            artifact_coverage=artifact_coverage or [],
            coverage_gaps=coverage_gaps or [],
            parse_failures=parse_failures or [],
            unsupported_artifacts=unsupported_artifacts or [],
        )

    def _log(self, level: str, message: str):
        entry = ProcessingLog(
            timestamp=datetime.utcnow(),
            level=level,
            module=self.PARSER_NAME,
            message=message,
        )
        self.logs.append(entry)
        log_func = getattr(logger, level.lower(), logger.info)
        log_func(f"[{self.PARSER_NAME}] {message}")

    def _stub_result(self) -> ParserResult:
        """Return a stub result for unimplemented parsers."""
        return self._make_result(
            status=ParserStatus.STUB,
            notes=f"Parser '{self.PARSER_NAME}' is a scaffold/stub in the MVP. "
                  f"No actual parsing was performed.",
        )


class ParserRegistry:
    """
    Central registry for all available parsers.
    Supports automatic discovery and filtered execution.
    """

    def __init__(self):
        self._parsers: Dict[str, Type[BaseParser]] = {}

    def register(self, parser_cls: Type[BaseParser]):
        """Register a parser class."""
        self._parsers[parser_cls.PARSER_NAME] = parser_cls
        logger.debug(f"Registered parser: {parser_cls.PARSER_NAME}")

    def get_parser(self, name: str) -> Optional[Type[BaseParser]]:
        return self._parsers.get(name)

    def get_all(self) -> Dict[str, Type[BaseParser]]:
        return dict(self._parsers)

    def get_for_os(self, os_platform: OSPlatform) -> List[Type[BaseParser]]:
        """Get all parsers that support a given OS platform."""
        return [
            cls for cls in self._parsers.values()
            if os_platform in cls.SUPPORTED_OS
        ]

    def execute_all(
        self,
        os_platform: OSPlatform,
        evidence_root: str,
        user_profile: str = "",
        case_id: str = "",
        evidence_item_id: str = "",
        source_image: str = "",
    ) -> List[ParserResult]:
        """Execute all applicable parsers and collect results."""
        results = []
        applicable = self.get_for_os(os_platform)

        logger.info(
            f"Executing {len(applicable)} parser(s) for {os_platform.value} "
            f"(user_profile={user_profile})"
        )

        for parser_cls in applicable:
            start = time.time()
            try:
                parser = parser_cls(
                    evidence_root=evidence_root,
                    user_profile=user_profile,
                    case_id=case_id,
                    evidence_item_id=evidence_item_id,
                    source_image=source_image,
                )
                result = parser.parse()
                elapsed = (time.time() - start) * 1000
                result.processing_time_ms = elapsed
                results.append(result)
                logger.info(
                    f"  [{parser_cls.PARSER_NAME}] {result.status.value}: "
                    f"{len(result.artifacts_found)} artifacts, {elapsed:.1f}ms"
                )
            except Exception as exc:
                elapsed = (time.time() - start) * 1000
                err_result = ParserResult(
                    parser_name=parser_cls.PARSER_NAME,
                    parser_version=parser_cls.PARSER_VERSION,
                    status=ParserStatus.FAILED,
                    errors=[f"Unhandled exception: {exc}"],
                    processing_time_ms=elapsed,
                )
                results.append(err_result)
                logger.error(f"  [{parser_cls.PARSER_NAME}] FAILED: {exc}")

        return results


# Global registry instance
registry = ParserRegistry()


def register_parser(cls: Type[BaseParser]) -> Type[BaseParser]:
    """Decorator to register a parser class with the global registry."""
    registry.register(cls)
    return cls
