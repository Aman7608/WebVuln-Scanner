"""
Settings the admin can change on the Admin > Settings page, without a restart.

The starting values come from config/settings.py (and the .env file). When the
admin saves a new value it is stored in the app_settings table and wins from
then on. Every part of the app asks get() for the current value, so web
processes and workers all see the change straight away.
"""

from config import settings
from database import db

# name -> (type, lowest, highest, label shown on the page, where the default comes from)
EDITABLE = {
    "registration_open": ("bool", None, None, "Allow new people to sign up",
                          lambda: settings.REGISTRATION_OPEN),
    "scans_per_day": ("int", 1, 1000, "Scans per user per 24 hours (public mode)",
                      lambda: settings.SCANS_PER_DAY),
    "max_running_scans_per_user": ("int", 1, 10, "Scans one user may have waiting or running at once (public mode)",
                                   lambda: settings.MAX_RUNNING_SCANS_PER_USER),
    "retention_days": ("int", 1, 3650, "Delete finished scans after this many days (public mode)",
                       lambda: settings.RETENTION_DAYS),
}


def _convert(name, raw):
    kind, low, high = EDITABLE[name][:3]
    if kind == "bool":
        return str(raw).lower() in ("1", "true", "on", "yes")
    value = int(raw)
    return max(low, min(high, value))


def get(db_path, name):
    """The current value: the admin's saved value, or else the default."""
    saved = db.get_saved_settings(db_path)
    if name in saved:
        try:
            return _convert(name, saved[name])
        except ValueError:
            pass
    return EDITABLE[name][4]()


def get_all(db_path):
    return {name: get(db_path, name) for name in EDITABLE}


def save_from_form(db_path, form):
    """Save the values from the Settings page form. Returns a dict of what changed."""
    changed = {}
    for name, (kind, *_rest) in EDITABLE.items():
        raw = "1" if (kind == "bool" and form.get(name)) else ("0" if kind == "bool" else form.get(name))
        if raw is None or raw == "":
            continue
        try:
            value = _convert(name, raw)
        except ValueError:
            raise ValueError(f"'{raw}' is not a valid number for: {EDITABLE[name][3]}")
        if value != get(db_path, name):
            db.save_setting(db_path, name, int(value) if kind == "bool" else value)
            changed[name] = value
    return changed
