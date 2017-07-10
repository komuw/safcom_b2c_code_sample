#!/usr/bin/env python

"""
>>> pip install requests pycrypto ndg-httpsclient pyasn1 pyOpenSSL httplib2

Please do read the safaricom documentation for their 'API'

caution: 
  - The code samples maybe a bit stale;
  - please write better code than this; this was only for documentation purposes.

"""


import re
import os
import json
import base64
from datetime import datetime

import httplib2
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5




SAFARICOM_B2C_SP_ID = 'get_this_from_safaricom'
SAFARICOM_B2C_SP_PASSWORD = 'get_this_from_safaricom'
PASSWORD = 'get_this_from_safaricom'
SAFARICOM_B2C_SERVICE_ID = 'get_this_from_safaricom'
QUEUE_TIMEOUT_URL = 'https://you_create_this_url_that_safaricom_can_call'
RESULT_URL = 'https://you_create_this_url_that_safaricom_can_call_with_results_of_ua_request'
INITIATOR = 'get_this_from_safaricom'
SHORT_CODE = 'get_this_from_safaricom'
https_safaricom_generic_requests_url ='get_this_from_safaricom'
http_safaricom_generic_requests_url ='same_as_previous_except_its_http'
ENCRYPTING_KEY = 'get_this_from_safaricom'
INTIATOR_PASSWORD = 'get_this_from_safaricom'



def password_encoder():
    """
    """
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    m = sha256()
    m.update(SAFARICOM_B2C_SP_ID)
    m.update(SAFARICOM_B2C_SP_PASSWORD)
    m.update(timestamp)
    m_digest = m.hexdigest()
    encrypted_password = base64.b64encode(m_digest)

    return encrypted_password

def security_credential_generator():
    """
    Generate the SecurityCredential parameter required in generic API request.
    output: base64 encoded encrypted string
    #PyCrypto does not support X.509 certificates. You must first extract the public key with the command:
     openssl x509 -inform pem -in ssl_client_cert_that_you_get_from_safaricom.pem -pubkey -noout > ssl_client_cert_key_of_the_client_cert_that_you_get_from_safaricom.pem 
     #see: http://stackoverflow.com/questions/12911373/how-do-i-use-a-x509-certificate-with-pycrypto
    """
    
    # you create the ENCRYPTING_KEY using the openssl command:
    # openssl x509 -inform pem -in ssl_client_cert_that_you_get_from_safaricom.pem -pubkey -noout > ssl_client_cert_key_of_the_client_cert_that_you_get_from_safaricom.pem
    ENCRYPTING_KEY = 'path/to/ssl_client_cert_key_of_the_client_cert_that_you_get_from_safaricom.pem'

    password = INTIATOR_PASSWORD
    f = open(ENCRYPTING_KEY, "r")
    key = f.read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_v1_5.new(rsakey)
    encrypted = rsakey.encrypt(password)

    return encrypted.encode('base64')



def send_money(phone_number, amount, request_id):
    """
    sends money to the phone_number given
    """

    cbp_request_stamp = datetime.now().strftime('%Y%m%d%H%M%S')
    encrypted_password = password_encoder()
    security_credential = security_credential_generator()

    request = u"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:req="http://api-v1.gen.mm.vodafone.com/mminterface/request">
       <soapenv:Header>
          <tns:RequestSOAPHeader xmlns:tns="http://www.huawei.com/schema/osg/common/v2_1">
             <tns:spId>{0}</tns:spId>
             <tns:spPassword>{1}</tns:spPassword>
             <tns:serviceId>{2}</tns:serviceId>
             <tns:timeStamp>{3}</tns:timeStamp>
          </tns:RequestSOAPHeader>
       </soapenv:Header>
       <soapenv:Body>
          <req:RequestMsg><![CDATA[<?xml version='1.0' encoding='UTF-8'?><request xmlns="http://api-v1.gen.mm.vodafone.com/mminterface/request">
        <Transaction>
            <CommandID>{4}</CommandID>
            <LanguageCode>0</LanguageCode>
            <OriginatorConversationID>{5}</OriginatorConversationID>
            <ConversationID></ConversationID>
            <Remark>0</Remark>
            <Parameters>
                <Parameter>
                    <Key>Amount</Key>
                    <Value>{6}</Value>
                </Parameter>
            </Parameters>
            <ReferenceData>
                <ReferenceItem>
                    <Key>QueueTimeoutURL</Key>
                    <Value>{7}</Value>
                </ReferenceItem>
            </ReferenceData>
            <Timestamp>{8}</Timestamp>
        </Transaction>
        <Identity>
            <Caller>
                <CallerType>{9}</CallerType>
                <ThirdPartyID>{10}</ThirdPartyID>
                <Password>Password0</Password>
                <CheckSum>CheckSum0</CheckSum>
                <ResultURL>{11}</ResultURL>
            </Caller>
            <Initiator>
                <IdentifierType>{12}</IdentifierType>
                <Identifier>{13}</Identifier>
                <SecurityCredential>{SecurityCredential0}</SecurityCredential>
                <ShortCode>{14}</ShortCode>
            </Initiator>
            <PrimaryParty>
                <IdentifierType>{15}</IdentifierType>
                <Identifier>{16}</Identifier>
                <ShortCode>{17}</ShortCode>
            </PrimaryParty>
            <ReceiverParty>
                <IdentifierType>{18}</IdentifierType>
                <Identifier>{19}</Identifier>
                <ShortCode>{20}</ShortCode>
            </ReceiverParty>
            <AccessDevice>
                <IdentifierType>{21}</IdentifierType>
                <Identifier>{22}</Identifier>
            </AccessDevice>
        </Identity>
        <KeyOwner>{23}</KeyOwner>
    </request>]]></req:RequestMsg>
       </soapenv:Body>
    </soapenv:Envelope>""".format(SAFARICOM_B2C_SP_ID,
                                  encrypted_password,
                                  SAFARICOM_B2C_SERVICE_ID,
                                  cbp_request_stamp,
                                  "BusinessPayment",
                                  request_id,
                                  amount,
                                  QUEUE_TIMEOUT_URL,
                                  datetime.now().isoformat(),
                                  "2",
                                  "ThirdPartyID0",
                                  RESULT_URL,
                                  "11",
                                  INITIATOR,
                                  SHORT_CODE,
                                  "4",
                                  SHORT_CODE,
                                  SHORT_CODE,
                                  "1",
                                  phone_number,
                                  SHORT_CODE,
                                  "1",
                                  "Identifier3",
                                  "1",
                                  SecurityCredential0=security_credential,
                                )

    encoded_request = request.encode('utf-8')

    url = https_safaricom_generic_requests_url
    headers = {
             "Host": "http://api-v1.gen.mm.vodafone.com",
             "Content-Type": "application/soap+xml; charset=UTF-8",
             "Content-Length": str(len(encoded_request)),
             "SOAPAction": http_safaricom_generic_requests_url
             }

    client_ssl_cert_file = 'path/to/ssl_client_cert_that_you_get_from_safaricom'
    client_ssl_key_file = ENCRYPTING_KEY

    # dont't verify cert. It fails, if set to false.
    client = httplib2.Http(disable_ssl_certificate_validation=True)

    client.add_certificate(key=key_file, cert=server_cert_file, domain='')

    (head, content) = client.request(url, "POST", body=encoded_request, headers=headers)

    #print "content", content
    return content

