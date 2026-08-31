"""A tiny module with two guards over it: a test suite and a lint rule."""


def total(items):
    """Sum of price * quantity. The `*` is what the test suite actually checks."""
    return sum(item["price"] * item["quantity"] for item in items)


def label(name):
    """Upper-cases a name. Nothing guards this, which is the point of the example."""
    return name.upper()
