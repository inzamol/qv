# pyright: reportMissingImports=false
"""Example application using a vulnerable dependency (DEP-006)."""

import jinja2


def render_template(content: str) -> str:
    template = jinja2.Template(content)
    return template.render(name="World")


if __name__ == "__main__":
    print(render_template("Hello {{ name }}!"))
