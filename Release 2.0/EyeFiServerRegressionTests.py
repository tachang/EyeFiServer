import unittest
import socket
import urllib2
import hashlib
import binascii
import mimetypes
import xml.sax
from xml.sax.handler import ContentHandler 
import xml.dom.minidom
import httplib
import re

import EyeFiSOAPMessages
import EyeFiCrypto

#    void testAppendsAdditionalParameterToUrlsInHrefAttributes(){?}
#    void testDoesNotRewriteImageOrJavascriptLinks(){?}
#    void testThrowsExceptionIfHrefContainsSessionId(){?}
#    void testEncodesParameterValue(){?}
    



# This class tests to see if the Eye-Fi server is listening on the correct
# network port.
class networkingLevelTest(unittest.TestCase):

  # Test to see if a socket is open on port 59278
  def testEyeFiServerListening(self):
    eyeFiServerHostname = 'localhost'
    eyeFiPort = 59278
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
      s.connect((eyeFiServerHostname, eyeFiPort))
    except:
      self.fail("Unable to connect to " + eyeFiServerHostname + ":" + str(eyeFiPort))
      
    s.close()

  
# Test the StartSession SOAP method call
class startSessionSOAPMethodTest(unittest.TestCase):
  
  # Send a malformed MAC address in the StartSession request
  def testRejectsMalformedMACAddress(self):
    soapMessage = EyeFiSOAPMessages.EyeFiSOAPMessages()
    
    xmlData = soapMessage.getStartSessionXML("EYEFIMALFORMEDMAC",
                                             "9219c72db0ecbd7e585bb10551f6bc38",
                                             "2",
                                             "315532800")
                                             
    conn = httplib.HTTPConnection("localhost", 59278)
    headers = {"Host": "api.eye.fi",
               "User-Agent": "Eye-Fi Card/2.0001",
               "Accept": "text/xml, application/soap",
               "Connection": "Keep-Alive",
               "SOAPAction": "\"urn:StartSession\""}

    conn.request("POST", "/api/soap/eyefilm/v1",xmlData,headers)
    response = conn.getresponse()    
    responseBody = response.read()
        
    
    if( responseBody.find("Agent is not authorized to receive pictures") == -1 ):
      self.fail("Did not receive a SOAP fault when sending an invalid MAC address")

  def testRejectsMalformedClientNonce(self):
    pass
  def testRejectsMalformedTransferMode(self):
    pass
  def testRejectsMalformedTransferModeTimestamp(self):
    pass
  
  
  def testCalculatesCredentialCorrectly(self):
    soapMessage = EyeFiSOAPMessages.EyeFiSOAPMessages()

    xmlData = soapMessage.getStartSessionXML("0018560304f8",
                                 "9219c72db0ecbd7e585bb10551f6bc38",
                                 "2",
                                 "315532800")
                                 
    conn = httplib.HTTPConnection("localhost", 59278)
    headers = {"Host": "api.eye.fi",
               "User-Agent": "Eye-Fi Card/2.0001",
               "Accept": "text/xml, application/soap",
               "Connection": "Keep-Alive",
               "SOAPAction": "\"urn:StartSession\""}

    conn.request("POST", "/api/soap/eyefilm/v1",xmlData,headers)
    response = conn.getresponse()    
    responseBody = response.read()
    
    if( responseBody.find("<credential>f138ce5977a8962a089b87e17155e537</credential>") == -1 ):
      self.fail("Received invalid credential after giving EyeFi server my <cnonce>")
    

    xmlData =\
    """
      <?xml version="1.0" encoding="UTF-8"?>
      <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="EyeFi/SOAP/EyeFilm">
            <SOAP-ENV:Body>
                  <ns1:GetPhotoStatus>
                        <credential>10ff036d3861ed3d1c47eb52d14841d2</credential>
                        <macaddress>0018560304f8</macaddress>
                        <filename>CIMG1812.JPG.tar</filename>
                        <filesize>250368</filesize>
                        <filesignature>22a856437b0afc4edc5a6c70f990e637</filesignature>
                  </ns1:GetPhotoStatus>
            </SOAP-ENV:Body>
      </SOAP-ENV:Envelope>
    """.strip()
    
    headers["SOAPAction"] = "\"urn:GetPhotoStatus\""
    conn.request("POST", "/api/soap/eyefilm/v1",xmlData,headers)
    response = conn.getresponse()    
    responseBody = response.read()
    
  
class getPhotoStatusSOAPMethodTest(unittest.TestCase):
  
  def testGetPhotoStatusBeforeStartSession(self):
    soapMessage = EyeFiSOAPMessages.EyeFiSOAPMessages()

    xmlData = soapMessage.getPhotoStatusXML("credential",
                                            "macaddress",
                                            "filename",
                                            "filesize",
                                            "filesignature")
                                                                                         
    conn = httplib.HTTPConnection("localhost", 59278)
    headers = {"Host": "api.eye.fi",
               "User-Agent": "Eye-Fi Card/2.0001",
               "Accept": "text/xml, application/soap",
               "Connection": "Keep-Alive",
               "SOAPAction": "\"urn:GetPhotoStatus\""}

    conn.request("POST", "/api/soap/eyefilm/v1",xmlData,headers)
    response = conn.getresponse()    
    responseBody = response.read()

    print response.status
        
    print responseBody
         





class photoUploadTest(unittest.TestCase):
  
  def testUploadSinglePhoto(self):
    soapMessage = EyeFiSOAPMessages.EyeFiSOAPMessages()
    xmlData = soapMessage.getStartSessionXML("0018560304f8",
                                             "9219c72db0ecbd7e585bb10551f6bc38",
                                             "2",
                                             "315532800")
    
    conn = httplib.HTTPConnection("localhost", 59278)
    headers = {"Host": "api.eye.fi",
               "User-Agent": "Eye-Fi Card/2.0001",
               "Accept": "text/xml, application/soap",
               "Connection": "Keep-Alive",
               "SOAPAction": "\"urn:StartSession\""}

    conn.request("POST", "/api/soap/eyefilm/v1",xmlData,headers)
    response = conn.getresponse()    
    responseBody = response.read()
    
    # Find the server's nonce and trim it appropriately
    snonceList = re.findall("<snonce>[a-f0-9]+</snonce>",responseBody)
    snonce = snonceList[0][8:40]
    
    # Calculate the credential string to send to server
    credentialString = "0018560304f8" + "c686e547e3728c63a8f78729c1592757"  + snonce   
    binaryCredentialString = binascii.unhexlify(credentialString)
    m = hashlib.md5()
    m.update(binaryCredentialString)
    credential = m.hexdigest()      
    
    
    xmlData = soapMessage.getPhotoStatusXML(credential,
                                            "0018560304f8",
                                            "EyeFiLogo.jpg.tar",
                                            "20480",
                                            "243b34de7406153e7f5ccf235079ccff")
    headers = {"Host": "api.eye.fi",
               "User-Agent": "Eye-Fi Card/2.0001",
               "Accept": "text/xml, application/soap",
               "Connection": "Keep-Alive",
               "SOAPAction": "\"urn:GetPhotoStatus\""}
               
    conn.request("POST", "/api/soap/eyefilm/v1",xmlData,headers)
    response = conn.getresponse()    
    responseBody = response.read()

    # Find the fileid and trim it appropriately
    fileidList = re.findall("<fileid>[0-9]+</fileid>",responseBody)
    
    # From the 8th character to the end    
    fileid = fileidList[0][8:]

    # Take only the beginning to 9 chars from the end
    fileid = fileid[0:-9]

    # Upload the photo
    xmlData = soapMessage.getUploadPhotoXML(fileid,
                                           "0018560304f8",
                                           "EyeFiLogo.jpg.tar",
                                           "20480",
                                           "243b34de7406153e7f5ccf235079ccff",
                                           "none")
    
    # Calculate the integrity digest
    fileToComputeDigest = open("EyeFiLogo.jpg.tar", "rb")
    fileBytes = fileToComputeDigest.read()

    eyeFiCrypto = EyeFiCrypto.EyeFiCrypto()
    integrityDigest = eyeFiCrypto.calculateIntegrityDigest(fileBytes,"c686e547e3728c63a8f78729c1592757")    
    
    # The POST fields
    fields = [("SOAPENVELOPE",xmlData),("INTEGRITYDIGEST",integrityDigest)]

    # The files to be uploaded
    targetFile = open('EyeFiLogo.jpg.tar', 'rb')
    
    files = [("FILENAME","EyeFiLogo.jpg.tar",targetFile.read())]
    
    # Create the multipart form data
    content_type, body = self.encode_multipart_formdata(fields, files)

    headers = {"Host": "api.eye.fi",
               "User-Agent": "Eye-Fi Card/2.0001",
               "Accept": "text/xml, application/soap",
               "Connection": "Keep-Alive",
               "Content-Type": content_type}
        
    conn.request("POST", "/api/soap/eyefilm/v1/upload", body, headers)

    response = conn.getresponse()    
    responseBody = response.read()
    print responseBody
    

  def encode_multipart_formdata(self, fields, files):
      """
      fields is a sequence of (name, value) elements for regular form fields.
      files is a sequence of (name, filename, value) elements for data to be uploaded as files
      Return (content_type, body) ready for httplib.HTTP instance
      """
      BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
      CRLF = '\r\n'
      L = []
      for (key, value) in fields:
          L.append('--' + BOUNDARY)
          L.append('Content-Disposition: form-data; name="%s"' % key)
          L.append('')
          L.append(value)
      for (key, filename, value) in files:
          L.append('--' + BOUNDARY)
          L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
          L.append('Content-Type: %s' % self.get_content_type(filename))
          L.append('')
          L.append(value)
      L.append('--' + BOUNDARY + '--')
      L.append('')
      body = CRLF.join(L)
      content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
      return content_type, body

  def get_content_type(self, filename):
      return mimetypes.guess_type(filename)[0] or 'application/octet-stream'





if __name__ == '__main__':
  suite = unittest.TestLoader().loadTestsFromTestCase(networkingLevelTest)  
  #unittest.TextTestRunner(verbosity=2).run(suite)
    
  suite = unittest.TestLoader().loadTestsFromTestCase(startSessionSOAPMethodTest)  
  #unittest.TextTestRunner(verbosity=2).run(suite)
  
  suite = unittest.TestLoader().loadTestsFromTestCase(getPhotoStatusSOAPMethodTest)  
  #unittest.TextTestRunner(verbosity=2).run(suite)

  suite = unittest.TestLoader().loadTestsFromTestCase(photoUploadTest)  
  unittest.TextTestRunner(verbosity=2).run(suite)
  