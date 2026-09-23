#!/usr/bin/env python3
"""Compatibility entry point for the AgenticVulHunter Harbor adapter."""

from avh_harbor import AgenticVulHunterResearchAgent, main

__all__ = ["AgenticVulHunterResearchAgent", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
