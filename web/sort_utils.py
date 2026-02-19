"""Generic server-side sort helper for list views."""

from __future__ import annotations

from typing import Any, Callable


def sort_items(
    items: list,
    sort_field: str | None,
    order: str | None,
    field_map: dict[str, Callable],
) -> tuple[list, str, str]:
    """Sort *items* by *sort_field* using *field_map* key functions.

    Parameters
    ----------
    items:
        List of objects or dicts to sort.
    sort_field:
        The URL query-param value for the column to sort by (e.g. ``"name"``).
        ``None`` or empty string means "no sort requested".
    order:
        ``"asc"`` (default) or ``"desc"``.
    field_map:
        Maps URL param names to key functions, e.g.::

            {"name": lambda p: (p.name or "").lower(),
             "cost": lambda p: p.annual_cost or 0}

        Key functions should return a sortable value and handle ``None``.

    Returns
    -------
    (sorted_items, sort_field, order)
        Normalised values so the route can pass them straight to the template.
    """
    order = order if order in ("asc", "desc") else "asc"
    sort_field = sort_field or ""

    if sort_field and sort_field in field_map:
        key_fn = field_map[sort_field]
        try:
            items = sorted(items, key=key_fn, reverse=(order == "desc"))
        except TypeError:
            pass  # incomparable values – keep original order

    return items, sort_field, order
