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

and many more! Check out <replace me> for more!

Dependencies
------------
- [Burp Suite](http://portswigger.net/burp/download.html) (free or professional)
- [Jython 2.5+](http://www.jython.org/downloads.html)


Installation / Running
----------------------
1. Install [Jython 2.5+] (I prefer the standalone jar install)
2. `git clone git://github.com/mwielgoszewski/jython-burp-api.git`
3. `cd jython-burp-api/`
4. Copy [Burp Suite] jar file(s) into current directory
5. Compile BurpExtender files:

    $ javac -cp burpsuite_v1.4.01.jar:jython.jar java/src/*.java

6. Start Burp by adding jython, burp extender and burp onto CLASSPATH:

	$ java -cp java/src/:jython.jar:burpsuite_v1.4.01.jar burp.StartBurp -i


Contribute
----------

