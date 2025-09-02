from __future__ import annotations

import ast
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
           :subtitle: The All-in-One Platform to Build, Package, and Deploy AI at Any Scale
           :buttons: |
              [ 
                {"text": "Book a Demo", "link": "index.html#calendar"},
                {"text": "Install", "link": "/install"}
              ]
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
        "buttons": directives.unchanged,
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
        node["buttons"] = self.options.get("buttons", "")

        return [node]


def visit_hero_node(self, node: HeroNode) -> None:
    """Visit a Hero node and generate HTML."""
    # Generate the HTML for the Hero section
    buttons = ast.literal_eval(node['buttons'].strip()[1:])
    html = f"""
    <div class="hero">
        <h1>{node['title']}</h1>
        <p>{node['subtitle']}</p>
        <nav>
            {''.join(f"<a href='{button['link']}'>{button['text']}</a>" for button in buttons)}
        </nav>
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
