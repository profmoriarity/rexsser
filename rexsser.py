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
from java.awt.event import MouseAdapter
from java.awt.event import ItemListener
from javax.swing import RowFilter
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JCheckBox
from javax.swing import JTable
from javax.swing import JButton
from javax.swing import JTextArea      
from javax.swing import JToggleButton
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import SwingUtilities;
from javax.swing import BoxLayout
from javax.swing.table import AbstractTableModel;
from threading import Lock
from java.awt import Color

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
        self.logTable = logTable    
        self._splitpane.setLeftComponent(scrollPane)


        splane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        btn = JToggleButton("Turn on/off")
        self._btn = btn 
        panel  = JPanel()
        panel1 = JPanel()
        
        chxbox =  JCheckBox("In Scope Only")
        self.chxbox = chxbox
        panel1.add(self._btn)
        panel1.add(chxbox)
        panel.add(panel1)

        panel2 = JPanel()
        panel2.setLayout(BoxLayout(panel2, BoxLayout.Y_AXIS))
        textarea = JTextArea("text/html\napplication/json")
        textarea.setRows(5)
        textarea.setColumns(5)
        textarea.setLineWrap(1);
        panel2.add(JLabel("Content Types: "))
        panel2.add(textarea)
        panel.add(panel2)
        self.content_types = textarea

        panel3 = JPanel()

        panel3.add(JLabel("Status Codes: "))
        txtarea = JTextArea("200,500")
        txtarea.setRows(3)
        txtarea.setLineWrap(1)
        self.status_codes = txtarea
        panel3.add(txtarea)
        panel3.setLayout(BoxLayout(panel3, BoxLayout.Y_AXIS))
        panel.add(panel3)

        panel.setLayout(BoxLayout(panel,BoxLayout.Y_AXIS))
        tabs = JTabbedPane()
        splane.setLeftComponent(panel) 

        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        splane.setRightComponent(tabs)

        self._splitpane.setRightComponent(splane)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(splane)
        
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
        return 4

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Detail"
        if columnIndex == 1:
            return "Parameter"
        if columnIndex == 2:
            return "URL"
        if columnIndex == 3:
            return "WAF Status"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._detail
        if columnIndex == 1:
            return logEntry._parameter
        if columnIndex == 2:
            return logEntry._url
        if columnIndex == 3:
            return logEntry._waf
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
        if not self._btn.isSelected():
            return 
        code = self._helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode()
        content_type = self._helpers.analyzeResponse(messageInfo.getResponse()).getStatedMimeType()
        statuscodes = self.status_codes.getText().split(",")
        content_types = self.content_types.getText().split("\n")
        
        cts = [x.split("/")[1].upper() for x in content_types]
        print(content_type+str(cts))
        if not str(code) in statuscodes:
            return
        if not content_type in cts:
            return
        self.toolFlag = toolFlag
        patt = "var (\w+).*=.*(.*)"
        payloads = ["fixedvaluehopefullyexists","random1'ss","random2\"ss","dumm</script>ss","<h1>duteer</h1>ss"]
        for payload in payloads:
            if self._callbacks.getToolName(toolFlag) == "Proxy":
                    self.processTestcases(patt, messageInfo, payload)

    def issues(self, messageInfo, detail, param, waf):
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(param, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl(), detail, waf))
        self.fireTableRowsInserted(row, row)
        self._lock.release()



    def processTestcases(self, patt, messageInfo, payload):
        irequest = self._helpers.analyzeRequest(messageInfo)
        url = irequest.getUrl()
        response = messageInfo.getResponse()
        httpservice = messageInfo.getHttpService()
        inject = URLEncoder.encode(payload, "UTF-8")
        inScopeOnly = self.chxbox.isSelected()
        if inScopeOnly and not self._callbacks.isInScope(url):
            return
        if True:
        #patt = "var (\w+).*=.*('|\")(.*)('|\")"
            words = []
            x = re.findall(patt, self._helpers.bytesToString(response))
            for y in x:
                    words.append(y[0])
            sortedwords = list(set(words))
            requestString  = self._helpers.bytesToString(messageInfo.getRequest())
            if 'GET /' in requestString:
                mthd = 'GET'
            elif 'POST /' in requestString:
                mthd = 'POST'
            else:
                mthd = 'GET'
            if len(sortedwords) > 0:
                for word in sortedwords:
                    if mthd == 'GET':
                        param = self._helpers.buildParameter(word, inject , IParameter.PARAM_URL)
                    elif mthd == 'POST':
                        param = self._helpers.buildParameter(word, inject, IParameter.PARAM_BODY)
                    else:
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
            if status == 200:
                waf = "Allowed"
            else:
                waf = "Unknown"
            if payload in response:
                if payload  == 'fixedvaluehopefullyexists':
                    str1 = word+" is a valid parameter"
                    str2 = self.definesContext(payload, response)
                    self.issues(bRequestResponse, str2+" "+str1, word, waf)
                if payload == 'random1\'ss':
                    str1 = word+" single quote reflection allowed"
                    str2 = self.definesContext(payload, response)
                    self.issues(bRequestResponse, str2+" "+str1, word, waf)
                if payload == 'random2"ss':
                    str1 = word+" Double quote allowed"
                    str2 = self.definesContext(payload, response)
                    self.issues(bRequestResponse, str2+" "+str1, word, waf)
                if payload == 'dumm</script>ss':
                    str1 = word+" Script tags allowed"
                    str2 = self.definesContext(payload, response)
                    self.issues(bRequestResponse, str2+" "+str1, word, waf)
                if payload == '<h1>duteer</h1>ss':
                    str1 = word+" HTML tags allowed"
                    str2 = self.definesContext(payload, response)
                    self.issues(bRequestResponse, str2+" "+str1, word, waf)
            else:
                pass
        if status == 403:
            self.issues(bRequestResponse, "", word, "Blocked")


    def definesContext(self, reflection, html):
        indx = html.find(reflection)
        q = html[indx-1]
        q2 = html[indx+len(reflection)]
        if q in reflection and q =='"':
            return "[Vulnerable][attribute][\"]"
        if q in reflection and q =="'":
            return "[Vulnerable][attribute][']"
        else:
            return "[Possible]"

class Mouseclick(MouseAdapter):
    def __init__(self, extender):
        self._extender = extender

    def mouseReleased(self, evt):
        if evt.button == 3:
            self._extender.menu.show(evt.getComponent(), evt.getX(), evt.getY())

class TabTableFilter(ItemListener):
    def __init__(self, extender):
        self._extender = extender

    def itemStateChanged(self, e):
        self._extender.tableSorter.sort()


class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        self.getColumnModel().getColumn(0).setPreferredWidth(50)
        self.getColumnModel().getColumn(1).setPreferredWidth(50)
        self.getColumnModel().getColumn(2).setPreferredWidth(800)
        self.getColumnModel().getColumn(3).setPreferredWidth(50)
        self.setRowSelectionAllowed(True)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)

    def prepareRenderer(self, renderer, row, col):
        comp = JTable.prepareRenderer(self, renderer, row, col)
        value = self.getValueAt(self._extender.logTable.convertRowIndexToModel(row), col)
        
        if col == 0:
            if "Vulnerable" in value:
                comp.setBackground(Color(255, 153, 153))
                comp.setForeground(Color.BLACK)
            elif "Possible" in value:
                comp.setBackground(Color(255, 204, 153))
                comp.setForeground(Color.BLACK)
            else:
                comp.setBackground(Color(204, 255, 153))
                comp.setForeground(Color.BLACK)
        else:
            comp.setForeground(Color.BLACK)
            comp.setBackground(Color.WHITE)

        selectedRow = self._extender.logTable.getSelectedRow()
        if selectedRow == row:
            comp.setBackground(Color(201, 215, 255))
            comp.setForeground(Color.BLACK)
        return comp
    

class LogEntry:
    def __init__(self, parameter, requestResponse, url, detail, waf):
        self._parameter = parameter
        self._requestResponse = requestResponse
        self._url = url
        self._detail = detail
        self._waf = waf



