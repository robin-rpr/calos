from __future__ import annotations

from docutils import nodes
from docutils.parsers.rst import directives
from sphinx.util.docutils import SphinxDirective
from sphinx.util import logging

logger = logging.getLogger(__name__)


class CalendarNode(nodes.General, nodes.Element):
    """A node for calendar sections."""

    pass


class CalendarDirective(SphinxDirective):
    """A directive for creating calendar sections.

    Usage:
        .. calendar::
           :link: clearly-inc/demo
    """

    name = "calendar"
    node_class = CalendarNode
    has_content = False
    required_arguments = 0
    optional_arguments = 0
    final_argument_whitespace = False

    option_spec = {
        "link": directives.unchanged,
    }

    def run(self) -> list[nodes.Node]:
        """Create the Calendar node."""
        node = self.node_class()
        
        # Validate required link parameter
        if "link" not in self.options:
            raise self.error("The 'link' option is required for the calendar directive.")

        # Set attributes from options
        node["link"] = self.options["link"]

        return [node]


def visit_calendar_node(self, node: CalendarNode) -> None:
    """Visit a Calendar node and generate HTML."""
    # Generate the HTML for the Hero section
    javascript = """(function (C, A, L) { let p = function (a, ar) { a.q.push(ar); }; let d = C.document; C.Cal = C.Cal || function () { let cal = C.Cal; let ar = arguments; if (!cal.loaded) { cal.ns = {}; cal.q = cal.q || []; d.head.appendChild(d.createElement("script")).src = A; cal.loaded = true; } if (ar[0] === L) { const api = function () { p(api, arguments); }; const namespace = ar[1]; api.q = api.q || []; if(typeof namespace === "string"){cal.ns[namespace] = cal.ns[namespace] || api;p(cal.ns[namespace], ar);p(cal, ["initNamespace", namespace]);} else p(cal, ar); return;} p(cal, ar); }; })(window, "https://app.cal.com/embed/embed.js", "init");"""
    html = f"""
    <div id="calendar" class="calendar"></div>
    <script type="text/javascript">
    {javascript}
    Cal("init", "demo", {{origin:"https://app.cal.com"}});
    Cal.ns.demo("inline", {{
        elementOrSelector:"#calendar",
        config: {{"layout":"month_view"}},
        calLink: "{node['link']}",
    }});
    Cal.ns.demo("ui", {{
        "hideEventTypeDetails":false,
        "layout":"month_view",
        "cssVarsPerTheme":{{
            "light": {{
                "cal-text": "rgb(20, 20, 20)",
                "cal-brand": "rgb(20, 20, 20)",
                "cal-bg-emphasis": "rgba(237, 237, 237, 0.8)",
                "cal-bg-subtle": "rgba(237, 237, 237, 0.72)",
                "cal-border-subtle": "rgba(64, 64, 64, 0.1)"
            }}
        }}
    }});
    </script>
    """
    
    self.body.append(html)


def depart_calendar_node(self, node: CalendarNode) -> None:
    """Depart from a Calendar node."""
    pass


def setup_calendar(app) -> None:
    """Set up the Calendar directive."""
    app.add_node(
        CalendarNode,
        html=(visit_calendar_node, depart_calendar_node),
        latex=(lambda self, node: None, lambda self, node: None),
        man=(lambda self, node: None, lambda self, node: None),
        texinfo=(lambda self, node: None, lambda self, node: None),
        text=(lambda self, node: None, lambda self, node: None),
    )
    
    app.add_directive("calendar", CalendarDirective)
