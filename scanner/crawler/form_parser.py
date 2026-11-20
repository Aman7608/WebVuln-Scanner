"""
Form Parser - finds HTML forms and their input fields.

Forms are important because they are one of the main ways a user sends data
to a website, so they are a common place for XSS and SQL injection bugs.
"""

from dataclasses import dataclass, field
from urllib.parse import urljoin

# Input types that do not take free text, so we do not inject into them
NON_TEXT_INPUT_TYPES = {"submit", "button", "image", "reset", "file"}

# Submit buttons with these words are never "clicked" by the scanner
DANGEROUS_BUTTON_WORDS = ("clear", "delete", "remove", "reset", "drop", "erase", "logout", "cancel")


@dataclass
class FormField:
    name: str
    field_type: str      # text, password, hidden, textarea, select ...
    value: str           # the default value written in the HTML


@dataclass
class Form:
    page_url: str        # the page where we found the form
    action: str          # full URL the form is sent to
    method: str          # "GET" or "POST"
    fields: list = field(default_factory=list)

    def default_values(self):
        """Return {field name: default value} for every field in the form."""
        return {f.name: f.value for f in self.fields}

    def text_fields(self):
        """Names of the fields we can put test input into."""
        return [f.name for f in self.fields if f.field_type not in NON_TEXT_INPUT_TYPES]


def parse_forms(soup, page_url):
    """Return a list of Form objects found in a parsed page."""
    forms = []
    for form_tag in soup.find_all("form"):
        # An empty or missing action means "send the form to this same page"
        action = urljoin(page_url, form_tag.get("action") or page_url)
        method = (form_tag.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"

        fields = []
        submit_buttons = []
        for tag in form_tag.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue  # fields without a name are never sent to the server

            if tag.name == "textarea":
                fields.append(FormField(name, "textarea", tag.get_text()))
            elif tag.name == "select":
                # Use the selected option, or else the first option
                option = tag.find("option", selected=True) or tag.find("option")
                value = ""
                if option is not None:
                    value = option.get("value", option.get_text())
                fields.append(FormField(name, "select", value))
            else:
                input_type = (tag.get("type") or "text").lower()
                default = tag.get("value", "")
                if input_type in NON_TEXT_INPUT_TYPES and input_type != "submit":
                    continue
                if input_type == "submit":
                    submit_buttons.append(FormField(name, input_type, default))
                    continue
                if input_type in ("checkbox", "radio") and not default:
                    default = "on"
                fields.append(FormField(name, input_type, default))

        # A browser only sends the ONE button that was clicked. Sending every
        # button could also "click" a Clear or Delete button by accident.
        button = choose_submit_button(submit_buttons)
        if button is not None:
            fields.append(button)

        forms.append(Form(page_url=page_url, action=action, method=method, fields=fields))
    return forms


def choose_submit_button(buttons):
    """Pick the first submit button that does not sound dangerous."""
    for button in buttons:
        text = f"{button.name} {button.value}".lower()
        if not any(word in text for word in DANGEROUS_BUTTON_WORDS):
            return button
    return None  # only dangerous buttons: send none at all
