"""Fail-closed lifecycle hooks for the pinned original SessionStore.

Install in the trusted isolated application before publishing handlers or binding
methods. No database, retention registry, retry policy or retirement authority is
created. Destructive lifecycle remains unavailable until retirement is qualified.
"""

from __future__ import annotations

import importlib
from typing import NoReturn

from .authority import Denied


def _retirement_required(*args: object, **kwargs: object) -> NoReturn:
    # A caller may already be handling a private exception; do not chain it.
    try:
        raise Denied("upstream session retirement is not qualified")
    except Denied as error:
        error.__context__ = error.__cause__ = None
        raise


def protect_session_history() -> None:
    """Disable both original deletion entrypoints for existing/future instances.

    Original app initialization/source verification belongs to the composition
    root. Importing its store constructs the original singleton; this function
    must not be used as an implicit launcher or source authentication mechanism.
    No restore/uninstall operation is provided while protected history may exist.
    """
    store = importlib.import_module("tether.store").SessionStore
    store.delete_session = _retirement_required
    store.clear_all_data = _retirement_required
