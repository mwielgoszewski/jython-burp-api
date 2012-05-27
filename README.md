jython-burp-api (burpy)
=======================

Burpy is an ISC Licensed library, written in Jython, Java and Python.

Burpy exposes a Jython interface to the popular Burp Suite web security 
testing tool, as an alternative to [Buby](http://tduehr.github.com/buby/) 
for those testers who prefer Python over Ruby.


Examples
--------
To start an interactive console, simply pass the -i command line argument
when starting Burp.  You can also click one or multiple items in Burp and
assign them to the `items` local variable like so:

    $ java -cp jython.jar:burpsuite_pro_v1.07.jar Burp.StartBurp -i
    ... launching Jython/Burp interpeter ...

    >>> Burp
    <BurpExtender 0x2>
    >>> Burp.getProxyHistory()
    [<HttpRequest [/]>, ...

    >>> items
    [<HttpRequest [/firefox/headlines.xml]>]
    >>> items[0].headers
    {'Accept-Language': 'en-us,en;q=0.5', ...
    >>> items[0].response
    <HttpResponse [302]>
    >>> len(items[0].response)
    256

and many more!

By default, we monitor a list of registered menu items for any changes.
If a file has changed (i.e., it's last modification time was updated), the
API will automatically attempt to reload it. This is great for active
development and debugging of Burp extensions.

Check out the [ConsoleMenu](blob/master/Lib/gds/burp/menu/console.py) class
for an example of how to add menu item's to Burp's context menu. Below is an
example of how to use one in your code.

    from gds.burp.menu.base import MenuItem
    
    class MyMenuItem(MenuItem):
        CAPTION = 'my caption'

        def __init__(self, _burp):
            MenuItem.__init__(self, _burp)

        @staticmethod
        def menuItemClicked(self, menuItemCaption, messageInfo):
            print('clicked %s' % (menuItemCaption,))


To add your new menu (MyMenuItem) to Burp's context menu, we need to pass a
reference of the BurpExtender object to MyMenuItem's `__init__` constructor.
For example, in BurpExtender class, we register the ConsoleMenu within the
registerExtenderCallbacks method (passing self as a reference):


    if self.opt.interactive:
        ConsoleMenu(self)


Dependencies
------------
- [Burp Suite](http://portswigger.net/burp/download.html) (free or professional)
- [Jython 2.5+](http://www.jython.org/downloads.html)


Installation / Running
----------------------
1. Install [Jython 2.5+](http://www.jython.org/downloads.html) - I prefer the standalone jar option
2. `git clone git://github.com/mwielgoszewski/jython-burp-api.git`
3. `cd jython-burp-api/`
4. Copy Burp Suite jar file(s) into current directory
5. Compile BurpExtender files:

    `$ javac -cp burpsuite_v1.4.01.jar:jython.jar java/src/*.java`

6. Start Burp by adding jython, burp extender and burp onto CLASSPATH:

    `$ java -cp java/src/:jython.jar:burpsuite_v1.4.01.jar burp.StartBurp -i`


**Note:** If Jython is _outside_ the current directory (assuming you followed the instructions
and you're in jython-burp-api/), you'll need to add Lib/ onto your Java classpath like 
so (ht Jon Passki, thanks!):

    $ java -cp Lib:java/src:/path/to/jython.jar:burp.jar burp.StartBurp -i


Contribute
----------
1. Check for open issues or open a fresh issue to start a discussion around
a feature idea or a bug.
2. Fork the repository on Github to start making your changes in a separate branch.
3. Write a test which shows that the bug was fixed or that the feature works as expected.
4. Send a pull request and bug the maintainer until it gets merged and published. :)

