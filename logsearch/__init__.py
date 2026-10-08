"""Index templates, an ILM policy and a query builder for structured logs.

The templates under `indices/` are the product. This package is three things
around them: a reader that composes the component templates into the mapping
Elasticsearch would end up with, an ingest path that decides what happens to a
value the mapping cannot hold, and a builder that emits search bodies which
only name fields the mapping defines.
"""

__version__ = "0.13.2"
