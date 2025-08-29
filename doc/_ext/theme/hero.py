"""Hero directive for Sphinx.

This directive allows creating a hero section in documentation.

:copyright: Copyright Kai Welke.
:license: MIT, see LICENSE for details.
"""

from __future__ import annotations

from docutils import nodes
from docutils.parsers.rst import directives
from sphinx.util.docutils import SphinxDirective
from sphinx.util import logging

logger = logging.getLogger(__name__)


class HeroNode(nodes.General, nodes.Element):
    """A node for hero sections."""

    pass


class HeroDirective(SphinxDirective):
    """A directive for creating hero sections.

    Usage:
        .. hero::
           :title: From Notebook to Production in One Platform
           :subtitle: Clearly is a platform for building and deploying apps at scale.
    """

    name = "hero"
    node_class = HeroNode
    has_content = False
    required_arguments = 0
    optional_arguments = 0
    final_argument_whitespace = False

    option_spec = {
        "title": directives.unchanged,
        "subtitle": directives.unchanged,
        "command": directives.unchanged,
    }

    def run(self) -> list[nodes.Node]:
        """Create the Hero node."""
        node = self.node_class()
        
        # Validate required title parameter
        if "title" not in self.options:
            raise self.error("The 'title' option is required for the hero directive.")

        # Set attributes from options
        node["title"] = self.options["title"]
        node["subtitle"] = self.options.get("subtitle", "")
        node["command"] = self.options.get("command", "")

        return [node]


def visit_hero_node(self, node: HeroNode) -> None:
    """Visit a Hero node and generate HTML."""
    # Generate the HTML for the Hero section
    html = f"""
    <div class="hero">
        <h1>{node['title']}</h1>
        <p>{node['subtitle']}</p>
        {f"<pre><code>{node['command']}</code></pre>" if node['command'] else ""}
    </div>
    """
    
    self.body.append(html)


def depart_hero_node(self, node: HeroNode) -> None:
    """Depart from a Hero node."""
    pass


def setup_hero(app) -> None:
    """Set up the Hero directive."""
    app.add_node(
        HeroNode,
        html=(visit_hero_node, depart_hero_node),
        latex=(lambda self, node: None, lambda self, node: None),
        man=(lambda self, node: None, lambda self, node: None),
        texinfo=(lambda self, node: None, lambda self, node: None),
        text=(lambda self, node: None, lambda self, node: None),
    )
    
    app.add_directive("hero", HeroDirective)
