from __future__ import annotations

from os import path

from sphinx.builders.html import StandaloneHTMLBuilder
from sphinx.highlighting import PygmentsBridge

from .highlighting import AwesomePygmentsBridge


class HTMLBuilder(StandaloneHTMLBuilder):
    """HTML builder that overrides a few methods related to handling CSS for Pygments."""

    def init_highlighter(self: HTMLBuilder) -> None:
        """Initialize Pygments highlighters."""
        # ``pygments_style`` from config
        if self.config.pygments_style is not None:
            if isinstance(self.config.pygments_style, dict):
                style = self.config.pygments_style.get("default", "sphinx")
            else:
                style = self.config.pygments_style
        else:
            style = "sphinx"

        self.highlighter = AwesomePygmentsBridge("html", style)

        if self.config.pygments_style_dark is not None:
            if isinstance(self.config.pygments_style_dark, dict):
                dark_style = self.config.pygments_style_dark.get("default", None)
            else:
                dark_style = self.config.pygments_style_dark
        elif self.theme:
            try:
                dark_style = self.theme.pygments_style_dark
            except AttributeError:
                dark_style = self.theme.get_config("theme", "pygments_dark_style", None)
        else:
            dark_style = None

        self.dark_highlighter: AwesomePygmentsBridge | PygmentsBridge | None
        if dark_style is not None:
            self.dark_highlighter = AwesomePygmentsBridge("html", dark_style)
        else:
            self.dark_highlighter = None

    def create_pygments_style_file(self: HTMLBuilder) -> None:
        """Create CSS file for Pygments."""
        stylesheet = self.highlighter.get_stylesheet()
        with open(
            path.join(self.outdir, "_static", "pygments.css"), "w", encoding="utf-8"
        ) as f:
            f.write(stylesheet)
