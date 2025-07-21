from jinja2 import Environment, FileSystemLoader

def generate_html_report(data, template_path, output_path):
    """
    Generates an HTML report from a template.

    Args:
        data: A dictionary containing the data to be included in the report.
        template_path: The path to the Jinja2 template.
        output_path: The path to save the generated report.
    """
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template(template_path)
    html = template.render(data)

    with open(output_path, "w") as f:
        f.write(html)
