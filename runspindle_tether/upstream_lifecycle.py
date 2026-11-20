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
    """Disable destructive lifecycle and legacy status writers on original stores.

    Original app initialization/source verification belongs to the composition
    root. Importing its store constructs the original singleton; this function
    must not be used as an implicit launcher or source authentication mechanism.
    No restore/uninstall operation is provided while protected history may exist.
    """
    store = importlib.import_module("tether.store").SessionStore
    store.delete_session = _retirement_required
    store.clear_all_data = _retirement_required

    protect_delivery_status()


def protect_delivery_status() -> None:
    """Deny legacy status writes; only the protected outbox may settle its rows.

    This deliberately disables these methods for ALL rows in the isolated process,
    not a query-then-write filter vulnerable to a status race. Original claim and
    bulk-cancel APIs already exclude protected states and are unchanged. Install
    before caching methods; no uninstall, second store or recovery authority.
    """
    store = importlib.import_module("tether.store").SessionStore
    store.mark_bridge_delivery_sent = _retirement_required
    store.mark_bridge_delivery_failed = _retirement_required
    store.cancel_bridge_delivery = _retirement_required
