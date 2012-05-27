# -*- coding: utf-8 -*-
'''
gds.burp.menu
~~~~~~~~~~~~~

This module contains Burp MenuItemHandler's that add
extra functionality available via Burp's context menu.
'''

__all__ = (
    'ConsoleMenu',
    )

from .base import MenuItem
from .console import ConsoleMenu
