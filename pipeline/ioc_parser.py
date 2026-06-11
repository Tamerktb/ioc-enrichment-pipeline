"""
IOC Parser — parse and validate indicators of compromise from multiple input formats.

Demonstrates:
- Input validation (Security & Safety)
- Structured data handling
- Type coercion with error reporting
"""

import re
import ipaddress
from typing import Optional
from pydantic import BaseModel, field_validator


class IOC(BaseModel):
    """A validated indicator of compromise with type classification."""
    type: str  # ip, domain, hash, url
    value: str
    source: str = "manual"       # Where this IOC came from
    context: str = ""             # Optional: alert context / notes
    confidence: float = 1.0      # Confidence in the IOC itself (0-1)

    @field_validator('type')
    @classmethod
    def validate_type(cls, v):
        v = v.lower().strip()
        if v not in ('ip', 'domain', 'hash', 'url', 'email'):
            raise ValueError(f"Unsupported IOC type: {v}. Must be one of: ip, domain, hash, url, email")
        return v

    @field_validator('value')
    @classmethod
    def validate_value(cls, v, info):
        v = v.strip()
        if not v:
            raise ValueError("IOC value cannot be empty")
        return v

    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v):
        if not 0 <= v <= 1:
            raise ValueError("Confidence must be between 0 and 1")
        return v


class IOCParser:
    """Parse IOCs from various input formats with format detection."""

    @staticmethod
    def detect_type(value: str) -> str:
        """
        Auto-detect the IOC type from its value format.
        Returns one of: ip, domain, hash, url, email
        """
        value = value.strip()

        # URL detection
        if value.startswith(('http://', 'https://', 'ftp://')):
            return 'url'

        # Email
        if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', value):
            return 'email'

        # IP address (IPv4 or IPv6)
        try:
            ipaddress.ip_address(value)
            return 'ip'
        except ValueError:
            pass

        # File hash (MD5=32, SHA1=40, SHA256=64 hex chars)
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return 'hash'  # MD5
        if re.match(r'^[a-fA-F0-9]{40}$', value):
            return 'hash'  # SHA1
        if re.match(r'^[a-fA-F0-9]{64}$', value):
            return 'hash'  # SHA256

        # Domain (has at least one dot, no spaces, valid chars)
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', value):
            return 'domain'

        raise ValueError(f"Cannot auto-detect IOC type for: {value!r}")

    @staticmethod
    def parse_single(value: str, ioc_type: Optional[str] = None, **kwargs) -> IOC:
        """Parse a single IOC value, optionally with an explicit type."""
        if ioc_type:
            return IOC(type=ioc_type, value=value.strip(), **kwargs)
        detected = IOCParser.detect_type(value)
        return IOC(type=detected, value=value.strip(), **kwargs)

    @staticmethod
    def parse_csv_line(line: str, has_header: bool = True) -> Optional[IOC]:
        """
        Parse a single CSV line.
        Expected format: type,value,source,context
        Or if no header: value (auto-detect type), or type,value
        """
        line = line.strip()
        if not line or line.startswith('#'):
            return None

        parts = [p.strip() for p in line.split(',')]

        if len(parts) >= 4:
            return IOC(type=parts[0], value=parts[1], source=parts[2], context=parts[3])
        elif len(parts) == 3:
            return IOC(type=parts[0], value=parts[1], source=parts[2])
        elif len(parts) == 2:
            return IOC(type=parts[0], value=parts[1])
        elif len(parts) == 1 and parts[0]:
            detected = IOCParser.detect_type(parts[0])
            return IOC(type=detected, value=parts[0])
        return None

    @staticmethod
    def parse_csv(text: str, skip_header: bool = True) -> list[IOC]:
        """Parse a full CSV text into a list of IOCs."""
        lines = text.strip().split('\n')
        results = []
        for i, line in enumerate(lines):
            if skip_header and i == 0:
                continue
            ioc = IOCParser.parse_csv_line(line)
            if ioc:
                results.append(ioc)
        return results

    @staticmethod
    def parse_json(data: list[dict]) -> list[IOC]:
        """Parse a list of dicts into IOCs. Each dict must have at least 'value'."""
        results = []
        for item in data:
            value = item.get('value', '').strip()
            if not value:
                continue
            ioc_type = item.get('type', None)
            try:
                if ioc_type:
                    ioc = IOC(
                        type=ioc_type,
                        value=value,
                        source=item.get('source', 'json'),
                        context=item.get('context', ''),
                        confidence=item.get('confidence', 1.0)
                    )
                else:
                    ioc = IOCParser.parse_single(
                        value,
                        source=item.get('source', 'json'),
                        context=item.get('context', '')
                    )
                results.append(ioc)
            except (ValueError, Exception):
                continue
        return results

    @staticmethod
    def parse_file(filepath: str) -> list[IOC]:
        """Auto-detect file format and parse IOCs from it."""
        import os
        ext = os.path.splitext(filepath)[1].lower()

        with open(filepath, 'r') as f:
            content = f.read()

        if ext == '.csv':
            return IOCParser.parse_csv(content)
        elif ext == '.json':
            import json
            data = json.loads(content)
            if isinstance(data, list):
                return IOCParser.parse_json(data)
            elif isinstance(data, dict) and 'iocs' in data:
                return IOCParser.parse_json(data['iocs'])
            raise ValueError("JSON must be a list of IOC objects or {'iocs': [...]}")
        elif ext == '.txt':
            # One IOC per line, auto-detect type
            results = []
            for line in content.strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    ioc = IOCParser.parse_single(line)
                    results.append(ioc)
                except ValueError:
                    continue
            return results
        else:
            raise ValueError(f"Unsupported file format: {ext}. Use .csv, .json, or .txt")