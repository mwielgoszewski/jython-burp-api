import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;

/*
 * Copyright (c) 2012 Marcin Wielgoszewski.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

/**
 * @author Marcin Wielgoszewski
 * @version 1.1
 *
 */
public class BurpExtender
{

    private static IBurpExtender handler;

    public BurpExtender()
    {
        if (handler == null)
        {
            BurpExtender.handler = (IBurpExtender) JythonFactory
                    .getJythonObject(IBurpExtender.class.getName(),
                            "Lib/burp_extender.py");
        }
    }

    public static IBurpExtender getHandler()
    {
        return handler;
    }

    public static void setHandler(IBurpExtender handle)
    {
        handler = handle;
    }

    public void applicationClosing()
    {
        handler.applicationClosing();
    }

    public void newScanIssue(IScanIssue issue)
    {
        handler.newScanIssue(issue);
    }

    public void processHttpMessage(String toolName, boolean messageIsRequest,
            IHttpRequestResponse messageInfo)
    {
        handler.processHttpMessage(toolName, messageIsRequest, messageInfo);
    }

    public byte[] processProxyMessage(int messageReference,
            boolean messageIsRequest, String remoteHost, int remotePort,
            boolean serviceIsHttps, String httpMethod, String url,
            String resourceType, String statusCode, String responseContentType,
            byte[] message, int[] interceptAction)
    {

        try
        {
            return handler.processProxyMessage(messageReference,
                    messageIsRequest, remoteHost, remotePort, serviceIsHttps,
                    httpMethod, url, resourceType, statusCode,
                    responseContentType, message, interceptAction);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return message;
    }

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        handler.registerExtenderCallbacks(callbacks);
    }

    public void setCommandLineArgs(String[] args)
    {
        handler.setCommandLineArgs(args);
    }

}
