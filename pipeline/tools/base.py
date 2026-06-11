"""
Base Tool — abstract enrichment tool with typed input schema.

This is the heart of "Tool & Contract Design" — each tool defines:
- A unique name
- A description of what it does
- An input_schema specifying exactly what parameters it expects (types, required, defaults)
- A validate() method that enforces the schema before execution
- An execute() method that performs the enrichment

No tool is ever called with invalid parameters — the schema guarantees it.
"""

from typing import Any
import time
import requests
import logging

logger = logging.getLogger(__name__)


class ToolSchema:
    """
    Defines the contract for a tool's input parameters.
    Mirrors the function-calling schema pattern used in LLM agent frameworks.
    """

    def __init__(self, properties: dict[str, dict]):
        """
        properties: dict of parameter_name -> {
            "type": str (e.g., "string", "integer", "boolean"),
            "description": str,
            "required": bool (default True),
            "default": Any (optional),
            "enum": list (optional, for constrained values),
            "pattern": str (optional, regex pattern)
        }
        """
        self.properties = properties

    def validate(self, **kwargs) -> list[str]:
        """
        Validate input parameters against the schema.
        Returns a list of error messages (empty if valid).
        """
        errors = []

        # Check for unknown parameters
        for key in kwargs:
            if key not in self.properties:
                errors.append(f"Unknown parameter '{key}'. Valid parameters: {list(self.properties.keys())}")

        # Check required parameters and types
        for name, spec in self.properties.items():
            required = spec.get("required", True)
            value = kwargs.get(name)

            if required and value is None:
                errors.append(f"Missing required parameter '{name}'")
                continue

            if value is None and "default" in spec:
                continue  # Will use default

            if value is not None:
                expected_type = spec.get("type", "string")
                type_ok = self._check_type(value, expected_type)
                if not type_ok:
                    errors.append(
                        f"Parameter '{name}' expected type '{expected_type}', "
                        f"got '{type(value).__name__}' (value: {value!r})"
                    )

                # Enum check
                if "enum" in spec and value not in spec["enum"]:
                    errors.append(
                        f"Parameter '{name}' must be one of {spec['enum']}, got '{value}'"
                    )

                # Pattern check (string values only)
                if "pattern" in spec and isinstance(value, str):
                    import re
                    if not re.match(spec["pattern"], value):
                        errors.append(
                            f"Parameter '{name}' does not match pattern '{spec['pattern']}'"
                        )

        return errors

    @staticmethod
    def _check_type(value: Any, expected_type: str) -> bool:
        """Check if a value matches an expected type."""
        type_map = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "array": list,
            "object": dict,
        }
        py_type = type_map.get(expected_type)
        if py_type is None:
            return True  # Unknown type — skip validation
        return isinstance(value, py_type)

    def get_defaults(self) -> dict:
        """Get default values for all parameters that have them."""
        return {
            name: spec["default"]
            for name, spec in self.properties.items()
            if "default" in spec
        }


class BaseTool:
    """
    Abstract base class for enrichment tools.
    Every enrichment tool inherits from this and provides:
    - name: unique tool identifier
    - description: what the tool does
    - input_schema: ToolSchema defining valid parameters
    """

    name: str = ""
    description: str = ""
    input_schema: ToolSchema = None

    def __init__(self, config: dict = None):
        self.config = config or {}
        self._session = requests.Session()
        # Default headers — subclasses can override
        self._session.headers.update({
            "User-Agent": "IOC-Enrichment-Pipeline/1.0",
            "Accept": "application/json",
        })
        self.timeout = self.config.get("timeout", 15)
        self.max_retries = self.config.get("max_retries", 3)
        self.retry_base_delay = self.config.get("retry_base_delay", 2.0)

    def validate(self, **kwargs) -> list[str]:
        """Validate parameters against this tool's schema."""
        if self.input_schema is None:
            return []
        return self.input_schema.validate(**kwargs)

    def execute(self, ioc_type: str, ioc_value: str, **kwargs) -> dict:
        """
        Execute enrichment. Must return a dict with at least:
        {
            "tool": self.name,
            "success": bool,
            "data": {...},  # enrichment results
            "error": None or str,
            "latency": float (seconds)
        }
        """
        raise NotImplementedError("Subclasses must implement execute()")

    def _request_with_retry(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Make an HTTP request with retry + exponential backoff.

        Demonstrates Reliability Engineering: retry logic for transient API failures.
        """
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                response = self._session.request(method, url, timeout=self.timeout, **kwargs)
                # Don't retry client errors (4xx) — those are our fault
                if response.status_code < 500:
                    return response
                # Server error — retry
                logger.warning(f"[{self.name}] HTTP {response.status_code} on attempt {attempt + 1}/{self.max_retries}")
            except requests.Timeout:
                logger.warning(f"[{self.name}] Timeout on attempt {attempt + 1}/{self.max_retries}")
                last_exception = "timeout"
            except requests.ConnectionError:
                logger.warning(f"[{self.name}] Connection error on attempt {attempt + 1}/{self.max_retries}")
                last_exception = "connection_error"
            except Exception as e:
                logger.warning(f"[{self.name}] Error on attempt {attempt + 1}/{self.max_retries}: {e}")
                last_exception = str(e)

            if attempt < self.max_retries - 1:
                delay = self.retry_base_delay * (2 ** attempt)  # Exponential backoff
                time.sleep(delay)

        # All retries exhausted
        raise RuntimeError(f"[{self.name}] All {self.max_retries} retries exhausted. Last error: {last_exception}")

    def result_success(self, data: dict, latency: float) -> dict:
        """Standard success result format."""
        return {
            "tool": self.name,
            "success": True,
            "data": data,
            "error": None,
            "latency": round(latency, 3),
        }

    def result_error(self, error: str, latency: float) -> dict:
        """Standard error result format."""
        return {
            "tool": self.name,
            "success": False,
            "data": {},
            "error": str(error),
            "latency": round(latency, 3),
        }