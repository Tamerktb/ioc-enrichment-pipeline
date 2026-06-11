"""
Enrichment Manager — orchestrates parallel enrichment across all available tools.

Demonstrates:
- System Design (manages tool lifecycle, parallelism, error isolation)
- Reliability Engineering (one tool failing doesn't break others)
- Tool & Contract Design (verifies schemas before calling)
"""

import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from .base import BaseTool
from .ipinfo import IPInfoTool
from .abuseipdb import AbuseIPDBTool
from .virustotal import VirusTotalTool

logger = logging.getLogger(__name__)


class EnrichmentManager:
    """
    Manages enrichment tools and executes them in parallel against IOCs.

    Features:
    - Auto-discovers available tools
    - Validates parameters against tool schemas before execution
    - Runs tools in parallel via ThreadPoolExecutor
    - Isolates failures — one tool error doesn't affect others
    - Tracks per-tool latency and error counts
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 15)
        self.max_retries = self.config.get("max_retries", 3)
        self.parallel = self.config.get("parallel", True)
        self._tools: dict[str, BaseTool] = {}
        self._stats = {"total_calls": 0, "errors": 0, "tool_stats": {}}
        self._register_tools()

    def _register_tools(self):
        """Register all available enrichment tools."""
        tool_classes = [IPInfoTool, AbuseIPDBTool, VirusTotalTool]
        tool_config = {
            "timeout": self.timeout,
            "max_retries": self.max_retries,
        }

        for cls in tool_classes:
            try:
                tool = cls(tool_config)
                self._tools[tool.name] = tool
                self._stats["tool_stats"][tool.name] = {"calls": 0, "errors": 0, "total_latency": 0.0}
                logger.debug(f"Registered tool: {tool.name}")
            except Exception as e:
                logger.warning(f"Failed to register tool {cls.__name__}: {e}")

    @property
    def available_tools(self) -> dict[str, str]:
        """Get available tools as {name: description}."""
        return {name: tool.description for name, tool in self._tools.items()}

    def validate_call(self, tool_name: str, **kwargs) -> list[str]:
        """Validate parameters against a specific tool's schema."""
        tool = self._tools.get(tool_name)
        if not tool:
            return [f"Unknown tool '{tool_name}'. Available: {list(self._tools.keys())}"]
        return tool.validate(**kwargs)

    def enrich_single(self, tool_name: str, ioc_type: str, ioc_value: str, **kwargs) -> dict:
        """
        Enrich an IOC using a specific tool.
        Returns the tool's result dict.
        """
        tool = self._tools.get(tool_name)
        if not tool:
            return {
                "tool": tool_name,
                "success": False,
                "data": {},
                "error": f"Unknown tool '{tool_name}'",
                "latency": 0,
            }

        # Validate before calling
        errors = tool.validate(ioc_type=ioc_type, ioc_value=ioc_value, **kwargs)
        if errors:
            return {
                "tool": tool_name,
                "success": False,
                "data": {},
                "error": f"Validation failed: {'; '.join(errors)}",
                "latency": 0,
            }

        # Execute
        start = time.time()
        try:
            result = tool.execute(ioc_type=ioc_type, ioc_value=ioc_value, **kwargs)
            self._update_stats(tool_name, result["success"], time.time() - start)
            return result
        except Exception as e:
            self._update_stats(tool_name, False, time.time() - start)
            return {
                "tool": tool_name,
                "success": False,
                "data": {},
                "error": str(e),
                "latency": round(time.time() - start, 3),
            }

    def enrich_all(self, ioc_type: str, ioc_value: str) -> dict[str, dict]:
        """
        Enrich an IOC using ALL available tools.
        Runs in parallel when self.parallel is True.
        Returns a dict of {tool_name: result}.
        """
        self._stats["total_calls"] += 1
        results = {}

        if self.parallel and len(self._tools) > 1:
            # Parallel execution
            with ThreadPoolExecutor(max_workers=len(self._tools)) as executor:
                future_map = {}
                for name, tool in self._tools.items():
                    future = executor.submit(self.enrich_single, name, ioc_type, ioc_value)
                    future_map[future] = name

                for future in as_completed(future_map):
                    name = future_map[future]
                    try:
                        results[name] = future.result()
                    except Exception as e:
                        results[name] = {
                            "tool": name,
                            "success": False,
                            "data": {},
                            "error": str(e),
                            "latency": 0,
                        }
        else:
            # Sequential execution
            for name in self._tools:
                results[name] = self.enrich_single(name, ioc_type, ioc_value)

        return results

    def _update_stats(self, tool_name: str, success: bool, latency: float):
        """Update per-tool and global statistics."""
        if tool_name in self._stats["tool_stats"]:
            self._stats["tool_stats"][tool_name]["calls"] += 1
            self._stats["tool_stats"][tool_name]["total_latency"] += latency
            if not success:
                self._stats["tool_stats"][tool_name]["errors"] += 1
                self._stats["errors"] += 1

    def get_stats(self) -> dict:
        """Get enrichment statistics."""
        stats = dict(self._stats)
        # Calculate average latency per tool
        for name, tstats in stats["tool_stats"].items():
            if tstats["calls"] > 0:
                tstats["avg_latency"] = round(tstats["total_latency"] / tstats["calls"], 3)
            else:
                tstats["avg_latency"] = 0.0
        return stats

    def get_enabled_tool_names(self) -> list[str]:
        """Get list of registered tool names."""
        return list(self._tools.keys())