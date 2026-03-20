"""
db/base.py
──────────
Declarative base shared by all SQLAlchemy model classes.
Importing this module (and all model modules) before calling
Base.metadata.create_all() ensures every table is registered.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Project-wide SQLAlchemy declarative base."""
    pass
