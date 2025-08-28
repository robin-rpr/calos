"""Spline directive for Sphinx.

This directive allows embedding Spline 3D scenes in documentation.

:copyright: Copyright Kai Welke.
:license: MIT, see LICENSE for details.
"""

from __future__ import annotations

from docutils import nodes
from docutils.parsers.rst import directives
from sphinx.util.docutils import SphinxDirective
from sphinx.util import logging

logger = logging.getLogger(__name__)


class SplineNode(nodes.General, nodes.Element):
    """A node for Spline scenes."""

    pass


class SplineDirective(SphinxDirective):
    """A directive for embedding Spline 3D scenes.

    Usage:
        .. spline::
           :url: https://prod.spline.design/Cn5e9s1vHTrcGHpG/scene.splinecode
           :width: 100%
           :height: 400px
           :loading: lazy
    """

    name = "spline"
    node_class = SplineNode
    has_content = False
    required_arguments = 0
    optional_arguments = 0
    final_argument_whitespace = False

    option_spec = {
        "url": directives.uri,
        "width": directives.unchanged,
        "height": directives.unchanged,
        "loading": directives.unchanged,
        "class": directives.unchanged,
    }

    def run(self) -> list[nodes.Node]:
        """Create the Spline node."""
        node = self.node_class()
        
        # Validate required URL parameter
        if "url" not in self.options:
            raise self.error("The 'url' option is required for the spline directive.")
        
        # Set attributes from options
        node["url"] = self.options["url"]
        node["width"] = self.options.get("width", "100%")
        node["height"] = self.options.get("height", "400px")
        node["loading"] = self.options.get("loading", "lazy")
        node["class"] = self.options.get("class", "")
        
        return [node]


def visit_spline_node(self, node: SplineNode) -> None:
    """Visit a Spline node and generate HTML."""
    # Generate the HTML for the Spline viewer
    html = f"""
    <div class="spline {node.get('class', '')}" style="width: {node['width']}; height: {node['height']}; margin: 1rem 0;">
        <script type="module" src="https://unpkg.com/@splinetool/viewer@1.10.52/build/spline-viewer.js"></script>
        <spline-viewer url="{node['url']}" loading="{node['loading']}"></spline-viewer>
    </div>
    """
    
    self.body.append(html)


def depart_spline_node(self, node: SplineNode) -> None:
    """Depart from a Spline node."""
    pass


def setup_spline(app) -> None:
    """Set up the Spline directive."""
    app.add_node(
        SplineNode,
        html=(visit_spline_node, depart_spline_node),
        latex=(lambda self, node: None, lambda self, node: None),
        man=(lambda self, node: None, lambda self, node: None),
        texinfo=(lambda self, node: None, lambda self, node: None),
        text=(lambda self, node: None, lambda self, node: None),
    )
    
    app.add_directive("spline", SplineDirective)
