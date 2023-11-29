# -*- coding: utf-8 -*-
from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab, IParameter  # 导入IParameter模块
from javax.swing import JPanel, JButton, JTextArea, JScrollPane, JList, DefaultListModel, JLabel, JTextField, JOptionPane
from java.awt import BorderLayout, FlowLayout, Dimension
from java.awt.event import MouseAdapter, MouseEvent
import re

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def __init__(self):
        self.displayed_requests = set()  # 存储已显示请求的集合
        self.whitelist = None

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("XSS Scan")

        # UI组件初始化
        self._panel = JPanel()
        self._topPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._toggleButton = JButton("Toggle ON/OFF", actionPerformed=self.toggle)
        self._toggleButton.setPreferredSize(Dimension(100, 30))
        self._topPanel.add(self._toggleButton)
        self._clearButton = JButton("Clear", actionPerformed=self.clear)
        self._clearButton.setPreferredSize(Dimension(100, 30))
        self._topPanel.add(self._clearButton)
        self._whitelistTextField = JTextField(20)
        self._whitelistLabel = JLabel("Whitelist domains (e.g., *.qq.com):")
        self._whitelistPanel = JPanel()
        self._whitelistPanel.add(self._whitelistLabel)
        self._whitelistPanel.add(self._whitelistTextField)
        self._whitelistButton = JButton("Whitelist", actionPerformed=self.updateWhitelist)
        self._whitelistButton.setPreferredSize(Dimension(100, 30))
        self._whitelistPanel.add(self._whitelistButton)
        self._topPanel.add(self._whitelistPanel)
        self._hostList = JList(DefaultListModel())
        self._hostList.addMouseListener(HostMouseListener(self))
        self._requestDetails = JTextArea(20, 50)
        self._requestDetails.setEditable(False)
        self._hostScrollPane = JScrollPane(self._hostList)
        self._detailScrollPane = JScrollPane(self._requestDetails)
        self._panel.setLayout(BorderLayout())
        self._panel.add(self._topPanel, BorderLayout.NORTH)
        self._panel.add(self._hostScrollPane, BorderLayout.WEST)
        self._panel.add(self._detailScrollPane, BorderLayout.CENTER)
        self._authorLabel = JLabel("by:shanxi getan xiaochou vx:tzh363404794", JLabel.CENTER)
        self._panel.add(self._authorLabel, BorderLayout.SOUTH)
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        self._isEnabled = True
        self._toggleButton.setText("ON")
        self._requestDetailsMap = {}

    def toggle(self, event):
        self._isEnabled = not self._isEnabled
        self._toggleButton.setText("ON" if self._isEnabled else "OFF")

    def clear(self, event):
        self._hostList.model.clear()
        self._requestDetails.setText("")
        self._requestDetailsMap.clear()
        self.displayed_requests.clear()

    def updateWhitelist(self, event):
        whitelist = self._whitelistTextField.getText()
        self.whitelist = whitelist.strip()
        self.displayMessage("Whitelist updated to: " + self.whitelist)

    def isDomainWhitelisted(self, domain):
        if not self.whitelist:
            return True  # No whitelist, so scan all domains
        elif self.whitelist == "*":
            return True  # Whitelist is "*", so scan all domains
        elif self.whitelist.startswith("*."):
            # Whitelist is "*.example.com", so check if the domain is a subdomain of example.com
            return re.match(r'^[^.]*' + re.escape(self.whitelist[1:]), domain) is not None
        else:
            # Whitelist is "example.com", so check if the domain matches exactly
            return domain == self.whitelist

    def displayMessage(self, message):
        JOptionPane.showMessageDialog(None, message, "Message", JOptionPane.INFORMATION_MESSAGE)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == self._callbacks.TOOL_PROXY and self._isEnabled:
            if messageIsRequest:
                # 获取完整的请求数据
                requestBytes = messageInfo.getRequest()
                # 获取HTTP服务信息
                httpService = messageInfo.getHttpService()

                # 使用完整的请求数据和HTTP服务信息来分析请求
                analyzedRequest = self._helpers.analyzeRequest(httpService, requestBytes)
                url = analyzedRequest.getUrl()

                # 检查URL路径，忽略某些文件类型
                urlpath = url.getPath()
                if ('.js' in urlpath or '.css' in urlpath or '.font' in urlpath or '.jpg' in urlpath or '.js' in urlpath or '.png' in urlpath or '.webp' in urlpath or '.gif' in urlpath or '.svg' in urlpath):
                    return None

                # 仅处理GET请求
                if analyzedRequest.getMethod() == 'GET':
                    # 创建一个新的请求用于XSS测试
                    newRequest = self.createTestRequest(requestBytes, analyzedRequest, httpService)
                    # 发送新的请求（不影响原始请求）
                    self._callbacks.makeHttpRequest(httpService, newRequest)

            else:
                # 获取响应的完整数据
                responseBytes = messageInfo.getResponse()
                # 获取HTTP服务信息
                httpService = messageInfo.getHttpService()

                # 使用完整的响应数据和HTTP服务信息来分析响应
                analyzedResponse = self._helpers.analyzeResponse(responseBytes)

                # 检查是否为GET请求并且URL路径不包含指定后缀
                if analyzedResponse.getStatedMimeType() == 'text/html':
                    # 在响应中搜索预期的Payload字符串
                    payload = "}]};(confirm)()//"
                    responseText = self._helpers.bytesToString(responseBytes)

                    # 如果响应中包含了预期的Payload字符串
                    if payload in responseText:
                        listItem = httpService.getHost() + analyzedResponse.getStatedMimeType()
                        # 检查该请求是否已经在UI中显示过，如果没有则添加
                        if listItem not in self.displayed_requests:
                            self.displayed_requests.add(listItem)
                            self._hostList.model.addElement(listItem)
                            self._requestDetailsMap[listItem] = responseText

                        # 在UI中显示结果
                        self._requestDetails.setText(self._requestDetailsMap.get(listItem, ""))

    # 创建带有XSS测试字符串的新请求
    def createTestRequest(self, originalRequest, analyzedRequest, httpService):
        newRequest = bytearray(originalRequest)
        params = analyzedRequest.getParameters()
        paramInjected = False

        for param in params:
            if param.getType() == IParameter.PARAM_URL:  # 检查参数类型是否为URL
                paramValue = param.getValue()
                if "}]};(confirm)()//" not in paramValue:
                    newParam = self._helpers.buildParameter(param.getName(), paramValue + "}]};(confirm)()//", param.getType())
                    newRequest = self._helpers.updateParameter(newRequest, newParam)
                    paramInjected = True

        if paramInjected:
            # 记录新的请求信息
            listItem = httpService.getHost() + analyzedRequest.getUrl().getPath()
            self._hostList.model.addElement(listItem)
            self._requestDetailsMap[listItem] = self._helpers.bytesToString(newRequest)

        return newRequest

    def getTabCaption(self):
        return "XSS Scan"

    def getUiComponent(self):
        return self._panel

class HostMouseListener(MouseAdapter):

    def __init__(self, extender):
        self.extender = extender

    def mouseClicked(self, event):
        selectedHost = self.extender._hostList.getSelectedValue()
        if selectedHost:
            self.extender._requestDetails.setText(self.extender._requestDetailsMap.get(selectedHost, ""))
