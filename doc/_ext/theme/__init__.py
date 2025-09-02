from __future__ import annotations

import os
import posixpath
import sass
import shutil

from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, TypedDict

from docutils.nodes import Node
from docutils.parsers.rst import directives
from sphinx.application import Sphinx
from sphinx.builders.html import StandaloneHTMLBuilder
from sphinx.util import logging
from sphinxcontrib.serializinghtml import JSONHTMLBuilder

from . import json
from .builder import HTMLBuilder
from .code import CodeBlock
from .hero import setup_hero
from .slider import setup_slider
from .calendar import setup_calendar

logger = logging.getLogger(__name__)

try:
    # obtain version from `pyproject.toml` via `importlib.metadata.version()`
    __version__ = version(__name__)
except PackageNotFoundError:  # pragma: no cover
    __version__ = "unknown"


class LinkIcon(TypedDict):
    """A link to an external resource, represented by an icon."""

    link: str
    """The absolute URL to an external resource."""
    icon: str
    """An SVG icon as a string."""


@dataclass
class ThemeOptions:
    """Helper class for configuring the Awesome Theme.

    Each attribute becomes a key in the :confval:`sphinx:html_theme_options` dictionary.
    """

    show_prev_next: bool = True
    """If true, the theme includes links to the previous and next pages in the hierarchy."""

    show_scrolltop: bool = False
    """If true, the theme shows a button that scrolls to the top of the page when clicked."""

    awesome_external_links: bool = False
    """If true, the theme includes an icon after external links and adds ``rel="nofollow noopener"`` to the links' attributes."""

    globaltoc_includehidden: bool = True
    """If true, the theme includes entries from *hidden*
    :sphinxdocs:`toctree <usage/restructuredtext/directives.html#directive-toctree>` directives in the sidebar.

    The ``toctree`` directive generates a list of links on the page where you include it,
    unless you set the ``:hidden:`` option.

    This option is inherited from the ``basic`` theme.
    """
        
def setup(app: Sphinx) -> dict[str, Any]:
    """Register the theme and its extensions wih Sphinx."""
    here = Path(__file__).parent.resolve()

    directives.register_directive("code-block", CodeBlock)
    app.add_config_value("pygments_style_dark", None, "html", [str])
    
    # Setup directives
    setup_calendar(app)
    setup_slider(app)
    setup_hero(app)

    # Monkey-patch galore
    StandaloneHTMLBuilder.init_highlighter = HTMLBuilder.init_highlighter # type: ignore
    StandaloneHTMLBuilder.create_pygments_style_file = ( # type: ignore
        HTMLBuilder.create_pygments_style_file
    )

    app.add_html_theme(name="theme", theme_path=str(here))
    
    app.add_css_file("pygments.css", priority="900", condition=None)
    app.add_css_file("main.css", priority="900", condition=None)

    # The theme is set up _after_ extensions are set up,
    # so I can't use internal extensions.
    # For the same reason, I also can't call the `config-inited` event
    app.connect("html-page-context", setup_jinja)
    app.connect("html-page-context", setup_sass)

    JSONHTMLBuilder.out_suffix = ".json"
    JSONHTMLBuilder.implementation = json
    JSONHTMLBuilder.indexer_format = json

    return {
        "version": __version__,
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }

def setup_jinja(
    app: Sphinx,
    pagename: str,
    templatename: str,
    context: dict[str, Any],
    doctree: Node,
) -> None:
    """Register a function as a Jinja2 filter."""
    # must override `pageurl` for directory builder
    if app.builder.name == "dirhtml" and app.config.html_baseurl:
        context["pageurl"] = lambda: (
            (lambda canonical: canonical if canonical.endswith("/") else canonical + "/")(
                posixpath.join(app.config.html_baseurl, pagename.replace("index", ""))
            )
        )

def setup_sass(
    app: Sphinx,
    pagename: str,
    templatename: str,
    context: dict[str, Any],
    doctree: Node,
) -> None:
    """Compile SCSS files to CSS."""
    # Only compile once per build
    if hasattr(app.env, 'theme_css_compiled'):
        return
    
    # Setup static path in output directory
    static_path = Path(app.outdir) / "_static"
    static_path.mkdir(exist_ok=True)
    
    # Compile SCSS to CSS
    scss_path = Path(__file__).parent.resolve() / "styles" / "main.scss"
    css_content = sass.compile(filename=str(scss_path))
    
    # Write CSS to _static directory
    css_path = static_path / "main.css"
    css_path.write_text(css_content, encoding='utf-8')
    
    # Mark as compiled to avoid recompiling on each page
    app.env.theme_css_compiled = True