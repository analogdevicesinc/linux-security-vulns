from docutils.parsers.rst import Directive, directives
from docutils.parsers.rst.roles import set_classes
from docutils import nodes

import re

class DirectiveStats(Directive):
    """
    Creates the entry-point for dynamic cards.
    """
    option_spec = {
        'class': directives.class_option,
    }
    has_content = False
    final_argument_whitespace = False

    required_arguments = 0
    optional_arguments = 0

    def run(self):
        set_classes(self.options)
        section = nodes.section(ids=["stats"])
        content = nodes.paragraph(text=self.content)
        section += content

        return [section]

def BuilderInited(app):
    if app.builder.format == 'html':
        app.add_js_file("custom.umd.js", priority=500, loading_method="async")
        app.add_css_file("custom.min.css")

def setup(app):
    app.add_directive('stats', DirectiveStats)

    app.connect("builder-inited", BuilderInited)

    return {
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }

