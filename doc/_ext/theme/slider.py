from __future__ import annotations

from docutils import nodes
from docutils.parsers.rst import directives
from sphinx.util.docutils import SphinxDirective
from sphinx.util import logging

import ast

logger = logging.getLogger(__name__)


class SliderNode(nodes.General, nodes.Element):
    """A node for Image Slider."""

    pass


class SliderDirective(SphinxDirective):
    """A directive for embedding Image Slider.

    Usage:
        .. slider::
           :steps:
              - title: "Step 1"
                image: https://picsum.photos/200/300
              - title: "Step 2"
                image: https://picsum.photos/200/300
    """

    name = "slider"
    node_class = SliderNode
    has_content = False
    required_arguments = 0
    optional_arguments = 0
    final_argument_whitespace = False

    option_spec = {
        "steps": directives.unchanged,
    }

    def run(self) -> list[nodes.Node]:
        """Create the Slider node."""
        node = self.node_class()
        
        # Validate required steps parameter
        if "steps" not in self.options:
            raise self.error("The 'steps' option is required for the slider directive.")
        
        # Set attributes from options
        node["steps"] = self.options["steps"]
        
        return [node]


def visit_slider_node(self, node: SliderNode) -> None:
    """Visit a Slider node and generate HTML."""

    # Parse the steps string into a Python list of dicts
    try:
        steps = ast.literal_eval(node['steps'])
    except Exception:
        steps = []

    # Generate the slider HTML and JS
    slider_id = f"slider-{id(node)}"
    steps_titles = [step.get("title", f"Step {i+1}") for i, step in enumerate(steps)]
    steps_images = [step.get("image", "") for step in steps]

    # Build the step selectors
    selectors_html = ""
    for idx, title in enumerate(steps_titles):
        selectors_html += (
            f'<button type="button" class="slider__selector" '
            f'data-step="{idx}" aria-label="Select {title}">'
            f'{title}</button>'
        )

    # Build the slides
    slides_html = ""
    for idx, (title, image) in enumerate(zip(steps_titles, steps_images)):
        slides_html += (
            f'<div class="slider__slide" data-step="{idx}" style="display:{"block" if idx==0 else "none"}">'
            f'<img src="{image}" alt="{title}" />'
            f'<div class="slider__caption">{title}</div>'
            f'</div>'
        )

    html = f"""
    <div class="slider" id="{slider_id}">
        <div class="slider__slides">
            {slides_html}
        </div>
        <div class="slider__steps">
            {selectors_html}
        </div>
    </div>
    <script>
    (function() {{
        var slider = document.getElementById("{slider_id}");
        if (!slider) return;
        var slides = slider.querySelectorAll('.slider__slide');
        var selectors = slider.querySelectorAll('.slider__selector');
        var current = 0;
        var timer = null;
        function showSlide(idx) {{
            slides.forEach(function(slide, i) {{
                slide.style.display = (i === idx) ? "block" : "none";
            }});
            selectors.forEach(function(btn, i) {{
                btn.classList.toggle("active", i === idx);
            }});
            current = idx;
        }}
        selectors.forEach(function(btn, idx) {{
            btn.addEventListener("click", function() {{
                clearInterval(timer);
                showSlide(idx);
                autoAdvance();
            }});
        }});
        function autoAdvance() {{
            timer = setInterval(function() {{
                var next = (current + 1) % slides.length;
                showSlide(next);
            }}, 3000);
        }}
        showSlide(0);
        autoAdvance();
    }})();
    </script>
    """
    
    self.body.append(html)


def depart_slider_node(self, node: SliderNode) -> None:
    """Depart from a Slider node."""
    pass


def setup_slider(app) -> None:
    """Set up the Slider directive."""
    app.add_node(
        SliderNode,
        html=(visit_slider_node, depart_slider_node),
        latex=(lambda self, node: None, lambda self, node: None),
        man=(lambda self, node: None, lambda self, node: None),
        texinfo=(lambda self, node: None, lambda self, node: None),
        text=(lambda self, node: None, lambda self, node: None),
    )
    
    app.add_directive("slider", SliderDirective)
