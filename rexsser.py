from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IExtensionHelpers
from burp import IScannerListener
from burp import IExtensionStateListener
from burp import IParameter
from java.io import PrintWriter
from java.net import URLEncoder
from burp import ITab
from threading import Thread
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
import re
import threading



class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener, ITab, IMessageEditorController, AbstractTableModel):
    
    def registerExtenderCallbacks(self, callbacks):
        # set our extension name
        self._callbacks = callbacks
        self.ATTRIBUTE_QUOTES = "(\".*\")|(\'.*\')"
        callbacks.setExtensionName("Rexsser")
        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._helpers = callbacks.getHelpers()
        # register ourselves as an HTTP listener
        
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)

        return

    def getTabCaption(self):
        return "Rexsser"
    
    def getUiComponent(self):
        return self._splitpane


    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 3

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Detail"
        if columnIndex == 1:
            return "Parameter"
        if columnIndex == 2:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._detail
        if columnIndex == 1:
            return logEntry._parameter
        if columnIndex == 2:
            return logEntry._url
        return ""

    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        self.toolFlag = toolFlag
        patt = "var (\w+).*=.*(.*)"
        payloads = ["fixedvaluehopefullyexists","random1'ss","random2\"ss","dumm</script>ss","<h1>duteer</h1>ss"]
        for payload in payloads:
            if self._callbacks.getToolName(toolFlag) == "Proxy":
                    self.processTestcases(patt, messageInfo, payload)

    def issues(self, messageInfo, detail, param):
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(param, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl(), detail))
        self.fireTableRowsInserted(row, row)
        self._lock.release()



    def processTestcases(self, patt, messageInfo, payload):
        irequest = self._helpers.analyzeRequest(messageInfo)
        url = irequest.getUrl()
        response = messageInfo.getResponse()
        httpservice = messageInfo.getHttpService()
        inject = URLEncoder.encode(payload, "UTF-8")
        if self._callbacks.isInScope(url):
        #patt = "var (\w+).*=.*('|\")(.*)('|\")"
            words = []
            x = re.findall(patt, self._helpers.bytesToString(response))
            for y in x:
                    words.append(y[0])
            sortedwords = list(set(words))
            if len(sortedwords) > 0:
                for word in sortedwords:
                    param = self._helpers.buildParameter(word, inject , IParameter.PARAM_URL)
                    newrequest  = self._helpers.addParameter(messageInfo.getRequest(), param)
                    t = threading.Thread(target=self.makeRequest,args=[messageInfo.getHttpService(), newrequest, word, payload])    
                    t.daemon = True
                    t.start()

    def makeRequest(self, httpservice, requestBytes, word, payload):
        #useHttps = 1 if httpservice.getProtocol() == 'https' else 0
        #print(self._helpers.bytesToString(requestBytes))
        bRequestResponse  = self._callbacks.makeHttpRequest(httpservice, requestBytes)
        tResp = bRequestResponse.getResponse()
        status = self._helpers.analyzeResponse(tResp).getStatusCode()
        url = self._helpers.analyzeRequest(bRequestResponse).getUrl()
        response = self._helpers.bytesToString(tResp)
        if status != 302:
            if payload in response:
                if payload  == 'fixedvaluehopefullyexists':
                    str1 = word+" is a valid parameter"
                    str2 = self.definesContext(payload, response)
                    self.issues(bRequestResponse, str1+" "+str2, word)
                if payload == 'random1\'ss':
                    str1 = word+" single quote reflection allowed"
                    str2 = self.definesContext(payload, response)
                    self.issues(bRequestResponse, str1+" "+str2, word)
                if payload == 'random2"ss':
                    str1 = word+" Double quote allowed"
                    str2 = self.definesContext(payload, response)
                    self.issues(bRequestResponse, str1+" "+str2, word)
                if payload == 'dumm</script>ss':
                    str1 = word+" Script tags allowed"
                    str2 = self.definesContext(payload, response)
                    self.issues(bRequestResponse, str1+" "+str2, word)
                if payload == '<h1>duteer</h1>ss':
                    str1 = word+" HTML tags allowed"
                    str2 = self.definesContext(payload, response)
                    self.issues(bRequestResponse, str1+" "+str2, word)
            else:
                pass


    def definesContext(self, reflection, html):
        indx = html.find(reflection)
        q = html[indx-1]
        q2 = html[indx+len(reflection)]
        if q in reflection and q =='"':
            return "Vulnerable to RXSS - attribute Context \""
        if q in reflection and q =="'":
            return "Vulnerable to RXSS - attribute Context '"
        else:
            return ""



class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
    

class LogEntry:
    def __init__(self, parameter, requestResponse, url, detail):
        self._parameter = parameter
        self._requestResponse = requestResponse
        self._url = url
        self._detail = detail