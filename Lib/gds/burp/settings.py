# -*- coding: utf-8 -*-
'''
gds.burp.settings
~~~~~~~~~~~~~~~~~

Extension setting keys and default values. Used by :class:`BurpExtender` in
:meth:`~burp_extender.BurpExtender.saveExtensionSetting` and
:meth:`~burp_extender.BurpExtender.loadExtensionSetting`.
'''

CONFIG_FILENAME = ('jython.config.filename', 'burp.ini')
CONSOLE_CAPTION = ('jython.ui.console.caption', 'Jython')
EXTENSION_NAME = ('jython.extension.name', 'jython-burp-api')
LOG_FILENAME = ('jython.logging.filename', 'jython-burp.log')
LOG_FORMAT = ('jython.logging.format', '%(asctime)-15s - %(name)s - %(levelname)s - %(message)s')
LOG_LEVEL = ('jython.logging.level', 10)
