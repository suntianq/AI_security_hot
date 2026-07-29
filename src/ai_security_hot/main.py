"""Process entry point — delegates to the Typer CLI."""

from __future__ import annotations

from ai_security_hot.cli import main

__all__ = ["main"]


if __name__ == "__main__":
    main()
