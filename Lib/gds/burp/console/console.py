# -*- coding: utf-8 -*-
'''
gds.burp.console.console
~~~~~~~~~~~

'''
from javax.swing import Action, JTextPane, KeyStroke, WindowConstants
from javax.swing.text import JTextComponent, SimpleAttributeSet, \
        StyleConstants, TextAction
from java.awt import Color, Font, Point, Toolkit
from java.awt.datatransfer import DataFlavor
from java.awt.event import InputEvent, KeyEvent, WindowAdapter

from java.lang import System
from java.util import Properties

from org.python.util import InteractiveInterpreter

import sys

from .history import History


class Console(object):
    # PS1 = sys.ps1
    # PS2 = sys.ps2
    PS1 = ">>> "
    PS2 = "... "

    def __init__(self, burp, namespace=None):
        self.burp = burp
        self.log = burp.log
        self._locals = dict(Burp=burp)
        self._buffer = []
        self.history = History(self)

        if namespace is not None:
            self._locals.update(namespace)

        self.interp = JythonInterpreter(self, self._locals)

        self.textpane = JTextPane(keyTyped=self.keyTyped,
                                  keyPressed=self.keyPressed)

        self.textpane.setFont(Font('Monospaced', Font.PLAIN, 11))
        self.burp.customizeUiComponent(self.textpane)

        self.initKeyMap()

        self.document.remove(0, self.document.getLength())
        self.write('Burp Extender Jython Shell', prefix='')
        self.write(self.PS1)

        self.textpane.requestFocus()
        burp.log.info('Interactive interpreter ready...')

    @property
    def document(self):
        return self.textpane.document

    def resetbuffer(self):
        self._buffer = []

    def keyTyped(self, event=None):
        if not self.inLastLine():
            event.consume()

    def keyPressed(self, event):
        if event.keyCode in (KeyEvent.VK_BACK_SPACE, KeyEvent.VK_LEFT):
            self.backspaceListener(event)

    def getText(self):
        start, end = self.__getLastLineOffsets()
        text = self.document.getText(start, end - start)
        return text.rstrip()

    def insertText(self, data):
        position = self.textpane.getCaretPosition()
        self.textpane.select(position, position)
        self.textpane.replaceSelection(data)
        self.textpane.setCaretPosition(position + len(data))

    def replaceText(self, data):
        start, end = self.__getLastLineOffsets()
        self.textpane.select(start, end)
        self.textpane.replaceSelection(data)
        self.textpane.setCaretPosition(start + len(data))

    def write(self, data, color=Color.black, prefix='\n'):
        style = SimpleAttributeSet()

        if color is not None:
            style.addAttribute(StyleConstants.Foreground, color)

        self.document.insertString(self.document.getLength(), prefix + data, style)
        self.textpane.caretPosition = self.document.getLength()

    def enterAction(self, event=None):
        text = self.getText()
        self._buffer.append(text)
        source = '\n'.join(self._buffer)
        more = self.interp.runsource(source)

        if more:
            self.write(self.PS2, color=Color.black)
        else:
            self.resetbuffer()
            self.write(self.PS1)

        self.history.append(text)

    def deleteAction(self, event=None):
        if self.inLastLine():
            if self.textpane.getSelectedText():
                self.document.remove(self.textpane.getSelectionStart(),
                     self.textpane.getSelectionEnd() - self.textpane.getSelectionStart())

            elif self.textpane.getCaretPosition() < self.document.getLength():
                self.document.remove(self.textpane.getCaretPosition(), 1)

    def deleteEndLineAction(self, event=None):
        if self.inLastLine():
            position = self.textpane.getCaretPosition()
            self.textpane.setSelectionStart(position)
            _, end = self.__getLastLineOffsets()
            self.textpane.setSelectionEnd(end - 1)
            self.textpane.cut()

    def homeAction(self, event=None):
        if self.inLastLine():
            start, end = self.__getLastLineOffsets()
            self.textpane.caretPosition = start

    def endAction(self, event=None):
        if self.inLastLine():
            start, end = self.__getLastLineOffsets()
            self.textpane.caretPosition = end - 1

    def pasteAction(self, event=None):
        if self.inLastLine():
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.getContents(self.textpane)
            contents = clipboard.getData(DataFlavor.stringFlavor)

            lines = contents.splitlines()
            for i, line in enumerate(lines):
                self.insertText(line)
                if i < len(lines) - 1:
                    self.enterAction()

    def keyboardInterruptAction(self, event=None):
        self.interp.runsource('raise KeyboardInterrupt\n')
        self.resetbuffer()
        self.write(self.PS1)

    def backspaceListener(self, event=None):
        start, end = self.__getLastLineOffsets()

        if self.textpane.getCaretPosition() <= start and \
            not self.textpane.getSelectedText():
                event.consume()

    def initKeyMap(self):
        import platform
        os_name = platform.java_ver()[-1][0]

        if os_name.startswith('Win'):
            exit_key = KeyEvent.VK_Z
            interrupt_key = KeyEvent.VK_PAUSE
        else:
            exit_key = KeyEvent.VK_D
            interrupt_key = KeyEvent.VK_C

        bindings = [
            (KeyEvent.VK_ENTER, 0, 'jython.enter', self.enterAction),
            (KeyEvent.VK_DELETE, 0, 'jython.delete', self.deleteAction),

            (KeyEvent.VK_HOME, 0, 'jython.home', self.homeAction),
            (KeyEvent.VK_LEFT, InputEvent.META_DOWN_MASK, 'jython.home', self.homeAction),
            (KeyEvent.VK_END, 0, 'jython.end', self.endAction),
            (KeyEvent.VK_RIGHT, InputEvent.META_DOWN_MASK, 'jython.end', self.endAction),

            (KeyEvent.VK_UP, 0, 'jython.up', self.history.historyUp),
            (KeyEvent.VK_DOWN, 0, 'jython.down', self.history.historyDown),

            (KeyEvent.VK_V, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask(), 'jython.paste', self.pasteAction),

            (KeyEvent.VK_A, InputEvent.CTRL_MASK, 'jython.home', self.homeAction),
            (KeyEvent.VK_E, InputEvent.CTRL_MASK, 'jython.end', self.endAction),
            (KeyEvent.VK_K, InputEvent.CTRL_MASK, 'jython.deleteEndLine', self.deleteEndLineAction),
            (KeyEvent.VK_Y, InputEvent.CTRL_MASK, 'jython.paste', self.pasteAction),

            #(interrupt_key, InputEvent.CTRL_MASK, 'jython.keyboardInterrupt', self.keyboardInterruptAction),
            ]

        keymap = JTextComponent.addKeymap('jython', self.textpane.getKeymap())

        for key, modifier, name, function in bindings:
            keymap.addActionForKeyStroke(
                    KeyStroke.getKeyStroke(key, modifier),
                    ActionDelegator(name, function))

        self.textpane.keymap = keymap

    def inLastLine(self, include=True):
        start, end = self.__getLastLineOffsets()

        if self.textpane.getSelectedText():
            position = self.textpane.getSelectionStart()
        else:
            position = self.textpane.getCaretPosition()

        if include is True:
            return start <= position <= end

        return start < position <= end

    def __getLastLineOffsets(self):
        firstElement = self.document.getRootElements()[0]
        lines = firstElement.getElementCount()

        start = firstElement.getElement(lines - 1).getStartOffset()
        end = firstElement.getElement(lines - 1).getEndOffset()

        line = self.document.getText(start, end - start)

        if len(line) >= 4 and (line[0:4] == self.PS1 or line[0:4] == self.PS2):
            return start + 4, end

        return start, end


class ActionDelegator(TextAction):
    def __init__(self, name, delegate):
        TextAction.__init__(self, name)
        self.delegate = delegate

    def actionPerformed(self, event):
        if isinstance(self.delegate, Action):
            self.delegate.actionPerformed(event)
        else:
            self.delegate(event)


class StdOutRedirector(object):
    def __init__(self, console):
        self.console = console

    def write(self, data):
        if data != '\n':
            self.console.write(data)


class StdErrRedirector(object):
    def __init__(self, console):
        self.console = console

    def write(self, data):
        self.console.write(data, color=Color.red)


class JythonInterpreter(InteractiveInterpreter):
    def __init__(self, console, _locals, *args, **kwargs):
        preProperties = System.getProperties()
        postProperties = Properties()

        console.log.debug('initializing interpreter with postProperties: %r',
                          postProperties)

        console.log.debug('Initializing interpreter with preProperties: %r',
                          preProperties)

        InteractiveInterpreter.initialize(preProperties, postProperties, args)

        InteractiveInterpreter.__init__(self, _locals)
        self.setOut(StdOutRedirector(self))
        self.setErr(StdErrRedirector(self))
        self.console = console

    def write(self, data, color=Color.black):
        self.console.write(data.rstrip('\r\n'), color=color)
