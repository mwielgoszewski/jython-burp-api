jython-burp-api (burpy)
=======================

Burpy is an ISC Licensed library, written in Jython, Java and Python.

Burpy exposes a Jython interface to the popular Burp Suite web security 
testing tool, as an alternative to [Buby](http://tduehr.github.com/buby/) 
for those testers who prefer Python over Ruby.

Features
--------
By default, we monitor a list of registered menu items for any changes.
If a file has changed (i.e., its last modification time was updated), the
API will automatically attempt to reload it. This is great for active
development and debugging of Burp extensions.


Examples
--------
To start an interactive console, simply pass the -i command line argument
when starting Burp.  You can also click one or multiple items in Burp and
assign them to the `items` local variable like so:

    $ java -cp java/src/:jython.jar:burpsuite_pro_v1.07.jar burp.StartBurp -i
    ... launching Jython/Burp interpeter ...

    >>> Burp
    <BurpExtender at 0x2>
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


Adding a simple menu item
-------------------------
Check out the [ConsoleMenu](https://github.com/mwielgoszewski/jython-burp-api/blob/master/Lib/gds/burp/menu/console.py)
class for an example of how to add menu items to Burp's context menu.
Below is an example of how to use one in your code.

    from gds.burp.menu.base import MenuItem
    
    class MyMenuItem(MenuItem):
        CAPTION = 'my caption'
        
        def menuItemClicked(self, menuItemCaption, messageInfo):
            print('clicked %s' % (menuItemCaption,))


To add your new menu (MyMenuItem) to Burp's context menu, specify it as an
option under `[menus]` section in `burp.ini` and set it to enabled. If you wish
to disable the built-in ConsoleMenu item that's registered, simply set it to
disabled, like so:

    [menus]
    gds.burp.menu.console.ConsoleMenu = disabled
    myplugins.MyMenuItem = enabled


Once Burp is loaded, the new menu item should be available in Burp. You can
also register menu items at runtime by initializing them within the interactive
console. Note however, menu items registered in the console cannot be reloaded
since there is no actual file to watch for changes.

	>>> class MyMenuItem(MenuItem):
	...     CAPTION = 'my caption'
	...     def menuItemClicked(self, menuItemCaption, messageInfo):
	...         print('clicked %s' % (menuItemCaption,))
	... 
	>>> MyMenuItem(Burp)


Also, keep in mind that in order to load the menu, we need to import it,
thus requiring it to be in our class path. If you keep your plugins under the
`Lib/` directory, you should be good.


Processing HTTP requests/responses
----------------------------------
One of the methods exposed by the Burp Extender interface is `processHttpMessage`.
This method, according to the API documentation *[..] is invoked whenever any of
Burp's tools makes an HTTP or receives a response [..] For each request, the
method is invoked after the request has been fully processed by the invoking
tool and is about to be made on the network. For each response, the method is
invoked after the response has been received from the network and before any
processing is performed by the invoking tool.* To write a plugin to hook into
one of these requests or responses, implement one of the interfaces from
`gds.burp.api`, such as IRepeaterRequestHandler, IProxyResponseHandler, and the
like. For example, the following plugin would hook requests as they are sent
via Intruder and Scanner, and responses that come in Proxy and Intruder.

    from gds.burp.api import IIntruderRequestHandler, IScannerRequestHandler
    from gds.burp.api import IProxyResponseHandler, IIntruderResponseHandler
    from gds.burp.core import Component, implements

    class ExamplePlugin(Component):

        implements(IIntruderRequestHandler, IIntruderResponseHandler,
                   IScannerRequestHandler, IProxyResponseHandler)

        def processRequest(self, request):
            self.log.info("Request to %s sent through Intruder and Scanner",
                          request.url.geturl())

        def processResponse(self, request):
            self.log.info("This response from %s was received via Proxy and Intruder",
                          request.url.geturl())

To use this plugin, we need to first enable it under the `[components]` section
within `burp.ini`, as well as add it to the list of options under `[handlers]`
in the order in which we want it to be processed. Options in the `[handlers]`
section can be a comma separated list, specifying the order in which a plugin
will be called. This allows you to decouple tools and configure their use at
different times. If you are familiar with or have experience with request
filter chains, such as in Java web apps, this should be immediately clear.

    [components]
    testplugin.ExamplePlugin = enabled

    [handlers]
    intruder.request = ExamplePlugin
    intruder.response = ExamplePlugin
    proxy.request = ExamplePlugin
    proxy.response = ExamplePlugin

Note, a plugin that implements an interface but is not enabled under
`[components]` and/or is not listed in its respective option in the `[handlers]`
configuration configuration, will not get called.

Dependencies
------------
- [Burp Suite](http://portswigger.net/burp/download.html) (free or professional)
- [Jython 2.7+](http://www.jython.org/)


Installation / Running
----------------------
1. Install [Jython 2.7+](http://www.jython.org/) - I prefer the standalone jar option
2. `git clone git://github.com/mwielgoszewski/jython-burp-api.git`
3. `cd jython-burp-api/`
4. Copy Burp Suite jar file(s) into current directory
5. Compile BurpExtender files (Note: On Windows the classpath separator is a semi-colon):

    `$ javac -cp burpsuite_v1.4.01.jar:jython.jar java/src/*.java java/src/burp/*.java`

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

