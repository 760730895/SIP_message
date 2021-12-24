#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author  : hu_cl
# @Email   : 760730895@qq.com
# @Date    : 2021/6/9 10:04
# @File    : sippackets.py
from scapy.all import *

sipVer = 'SIP/2.0'
protocols = 'UDP'
contentType = 'application/sdp'
methods = {'BYE': 21, 'INVITE': 20, 'MESSAGE': 20}


class SipBody(object):
    def __init__(self, srcAddr, srcSipId, dstAddr, dstSipId, message, CmdType):
        self.srcSipId = srcSipId
        self.srcAddr = srcAddr
        self.dstAddr = dstAddr
        self.dstSipId = dstSipId
        self.CmdType = CmdType
        self.message = message

    def sip_body_invite(self):
        body = "v=0\r\n"
        body += "o={srcSip} 0 0 IN IP4 {srcIP}\r\n"
        body += "s=Play\r\n"
        body += "c=IN IP4 {srcIP}\r\n"
        body += "t=0 0\r\n"
        body += "m=video 45056 RTP/AVP 96 97 98\r\n"
        body += "a=recvonly\r\n"
        body += "a=rtpmap:96 PS/90000\r\n"
        body += "a=rtpmap:97 H264/90000\r\n"
        body += "a=rtpmap:98 MPEG4/90000\r\n"
        body += "y=0000001027\r\n"
        return body.format(srcSip=self.srcSipId, srcIP=self.srcAddr.split(':')[0])

    def sip_body_message(self):
        body = '<?xml version="1.0"?>\r\n'
        body += '<Query>\r\n'
        body += "<CmdType>{CmdType}</CmdType >\r\n"
        body += "<SN>1583</SN >\r\n"
        body += "<DeviceID>{dstSipId}</DeviceID>\r\n"
        body += "</Query>\r\n"
        return body.format(CmdType=self.CmdType, dstSipId=self.dstSipId)

    def sip_body_bye(self):
        body = self.message
        return body


class SipHead(SipBody):
    def __init__(self, srcAddr, srcSipId, dstAddr, dstSipId, tag, callId, method, message, CmdType,
                 protocols=protocols, sipVer=sipVer, contentType=contentType):
        self.srcAddr = srcAddr
        self.srcSipId = srcSipId
        self.dstAddr = dstAddr
        self.dstSipId = dstSipId
        self.tag = tag
        self.callId = callId
        self.method = method
        self.maxWards = 70
        self.protocols = protocols
        self.branch = str(random.randint(1000, 9999))
        self.sipVer = sipVer
        self.contentType = contentType
        self.CmdType = CmdType
        self.message = message
        self.lines = f'{method} sip:{dstSipId}@{dstAddr} {sipVer}\r\n'
        super(SipHead, self).__init__(srcAddr, srcSipId, dstAddr, dstSipId, message, CmdType)

    def sip_head_invite(self):
        heard = 'Via: {sipVer}/{protocols} {srcAddr};rport;branch=z9hG4bK34202{branch}\r\n'
        heard += 'From: <sip:{srcSipId}@{srcAddr}>;tag={fromTag}\r\n'
        heard += 'To: <sip:{dstSipId}@{dstAddr}>\r\n'
        heard += 'Call-ID: {callId}\r\n'
        heard += 'CSeq: {methodNum} {method}\r\n'
        heard += 'Max-Forwards: {maxWards}\r\n'
        heard += 'User-Agent: eXosip/4.1.0\r\n'
        heard += 'Content-Length: {contentLeng}\r\n\r\n'
        return heard.format(sipVer=self.sipVer, protocols=self.protocols, srcAddr=self.srcAddr, branch=self.branch,
                            srcSipId=self.srcSipId, fromTag=self.tag, dstSipId=self.dstSipId, dstAddr=self.dstAddr,
                            callId=self.callId, methodNum=methods.get(self.method), method=self.method,
                            maxWards=self.maxWards, contentLeng=len(self.sip_body_invite()))

    def sip_head_message(self):
        heard = 'Via: {sipVer}/{protocols} {srcAddr};rport;branch=z9hG4bK34202{branch}\r\n'
        heard += 'From: <sip:{srcSipId}@{srcAddr}>;tag={fromTag}\r\n'
        heard += 'To: <sip:{dstSipId}@{dstAddr}>\r\n'
        heard += 'Call-ID: {callId}\r\n'
        heard += 'CSeq: {methodNum} {method}\r\n'
        heard += 'Content-Type: application/MANSCDP+xml\r\n'
        heard += 'Max-Forwards: {maxWards}\r\n'
        heard += 'User-Agent: eXosip/4.1.0\r\n'
        heard += 'Content-Length: {contentLeng}\r\n\r\n'
        return heard.format(sipVer=self.sipVer, protocols=self.protocols, srcAddr=self.srcAddr, branch=self.branch,
                            srcSipId=self.srcSipId, fromTag=self.tag, dstSipId=self.dstSipId, dstAddr=self.dstAddr,
                            callId=self.callId, methodNum=methods.get(self.method), method=self.method,
                            maxWards=self.maxWards, contentLeng=len(self.sip_body_message()))

    def sip_head_bye(self):
        heard = 'Via: {sipVer}/{protocols} {srcAddr};rport;branch=z9hG4bK34202{branch}\r\n'
        heard += 'From: <sip:{srcSipId}@{srcAddr}>;tag={fromTag}\r\n'
        heard += 'To: <sip:{dstSipId}@{dstAddr}>;tag=3982398926\r\n'
        heard += 'Call-ID: {callId}\r\n'
        heard += 'CSeq: {methodNum} {method}\r\n'
        heard += 'Max-Forwards: {maxWards}\r\n'
        heard += 'User-Agent: eXosip/4.1.0\r\n'
        heard += 'Content-Length: {contentLeng}\r\n\r\n'
        return heard.format(sipVer=self.sipVer, protocols=self.protocols, srcAddr=self.srcAddr, branch=self.branch,
                            srcSipId=self.srcSipId, fromTag=self.tag, dstSipId=self.dstSipId, dstAddr=self.dstAddr,
                            callId=self.callId, methodNum=methods.get(self.method), method=self.method,
                            maxWards=self.maxWards, contentLeng=len(self.sip_body_bye()))


class SipMethod(SipHead):

    def __init__(self, srcAddr, srcSipId, dstAddr, dstSipId, tag, callId, method, message, CmdType,
                 protocols=protocols, sipVer=sipVer, contentType=contentType):
        self.srcAddr = srcAddr
        self.dstAddr = dstAddr
        self.lines = f'{method} sip:{dstSipId}@{dstAddr} {sipVer}\r\n'
        super(SipMethod, self).__init__(srcAddr, srcSipId, dstAddr, dstSipId, tag, callId, method, message, CmdType,
                                        protocols=protocols, sipVer=sipVer, contentType=contentType)

    def send_msg(self):
        if self.method == 'BYE':
            self.message = self.lines + self.sip_head_bye() + self.sip_body_bye()
        elif self.method == 'INVITE':
            self.message = self.lines + self.sip_head_invite() + self.sip_body_invite()
        elif self.method == 'MESSAGE':
            self.message = self.lines + self.sip_head_message() + self.sip_body_message()

        print('\r\n*******send_message的信息*******\r\n', self.message, '\r\n*******END*******\r\n')

        src_ip = self.srcAddr.split(':')[0]
        src_port = self.srcAddr.split(':')[1]
        dst_ip = self.dstAddr.split(':')[0]
        dst_port = self.dstAddr.split(':')[1]

        send(IP(src=src_ip, dst=dst_ip) / UDP(sport=int(src_port), dport=int(dst_port)) / self.message)


if __name__ == '__main__':
    """
    暂时支持的SIP方法  ['INVITE','BYE','MESSAGE']
    """
    srcAddr = '192.168.2.153:5080'
    srcSip = '34020000002000000001'
    dstAddr = '192.168.2.245:5060'
    # dstSip = '34020000002000000765'
    # message 使用 CmdType 字段
    CmdType = 'DeviceInfo'
    # CmdType = 'Catalog' 查询目录
    # CmdType = 'DeviceInfo' 查询设备详情
    # 不需要查询时候 CmdType = None

    dstSip = '34020000002000000011'
    tag = '1376790544'
    callId = '1710724471'
    method = 'MESSAGE'
    msg = ''

    sendsip = SipMethod(srcAddr=srcAddr, srcSipId=srcSip, dstAddr=dstAddr, dstSipId=dstSip, tag=tag, callId=callId,
                        method=method, message=msg, CmdType=CmdType)
    sendsip.send_msg()
