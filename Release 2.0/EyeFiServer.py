"""
* EyeFi Python Server v2.0
*
* Copyright (c) 2009, Jeffrey Tchang
*
* All rights reserved.
*
*
* THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import string
import cgi
import time

import sys
import os
import socket
import threading
import StringIO

import hashlib
import binascii
import select 
import tarfile

import xml.sax
from xml.sax.handler import ContentHandler 
import xml.dom.minidom

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import BaseHTTPServer

import SocketServer

import logging
import optparse
import ConfigParser

import subprocess
import random
import tempfile

import EyeFiCrypto
import EyeFiSOAPMessages

"""
General Architecture Notes


This is a standalone Eye-Fi Server that is designed to take the place of the Eye-Fi Manager.

Starting this server creates a listener on port 59278. I use the BaseHTTPServer class included
with Python. I look for specific POST/GET request URLs and execute functions based on those
URLs. Currently all files are downloaded to the directory in which this script is run.


To use this script you need to have your Eye-Fi upload key.
It is in C:\Documents and Settings\<User>\Application Data\Eye-Fi\Settings.xml.

This script uses a file for all its configuration parameters. An example configuration
file can be found in the same directory called "DefaultSettings.ini".

This script can be run with the default settings but without replacing at least the
UploadKey setting in the [Card] section of the configuration file it will not work.


"""



# Create an instance of the options parser. This object will hold
# all the command line options
optionsParser = optparse.OptionParser()



# Eye Fi XML SAX ContentHandler
class EyeFiContentHandler(ContentHandler):

  # These are the element names that I want to parse out of the XML    
  elementNamesToExtract = ["macaddress","cnonce","transfermode","transfermodetimestamp","fileid","filename","filesize","filesignature","credential"]  

  # For each of the element names I create a dictionary with the value to False
  elementsToExtract = {}

  # Where to put the extracted values
  extractedElements = {}


  def __init__(self):
    self.extractedElements = {}
    
    for elementName in self.elementNamesToExtract:
        self.elementsToExtract[elementName] = False
  
  def startElement(self, name, attributes):
  
    # If the name of the element is a key in the dictionary elementsToExtract
    # set the value to True
    if name in self.elementsToExtract:
      self.elementsToExtract[name] = True

  def endElement(self, name):

    # If the name of the element is a key in the dictionary elementsToExtract
    # set the value to False
    if name in self.elementsToExtract:
      self.elementsToExtract[name] = False


  def characters(self, content):
  
    for elementName in self.elementsToExtract:
      if self.elementsToExtract[elementName] == True:
        self.extractedElements[elementName] = content

# Implements an EyeFi server
class EyeFiServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):

  eyeFiConfiguration = ""
  serverNonce = ""
  
  def __init__(self, server_address, requestHandler, eyeFiConfiguration):
    # Set EyeFiServer.eyeFiConfiguration to the configuration object that is passed in
    self.eyeFiConfiguration = eyeFiConfiguration
    
    # Generate a nonce to be used by the server. The nonce should be very hard if not
    # impossible to predict. The method used here is to MD5 hash a random number.    
    m = hashlib.md5()
    m.update(str(random.random()))
    self.serverNonce = m.hexdigest()

    # Explicitly call the base class BaseHTTPServer.HTTPServer's __init__() method
    BaseHTTPServer.HTTPServer.__init__(self,server_address, requestHandler)    

  
  def server_bind(self):

    BaseHTTPServer.HTTPServer.server_bind(self)    
    self.socket.settimeout(None)
    self.run = True

  def get_request(self):  
    while self.run:
      try:
        connection, address = self.socket.accept()
        eyeFiLogger.debug("Incoming connection from client %s" % address[0])
        
        # Set the timeout of the socket to 60 seconds
        connection.settimeout(None)
        return (connection, address)
        
      except socket.timeout:
        pass

  def stop(self):
    self.run = False

  def serve(self):
    while self.run:
      self.handle_request()
  
  # Override the method finish_request() found in the BaseServer class to insert some debugging
  # output. This class can be found in the file SocketServer.py.
  def finish_request(self, request, client_address):
    eyeFiLogger.debug("Creating instance of " + str(self.RequestHandlerClass) + " to service request from " + str(client_address))
    self.RequestHandlerClass(request, client_address, self)


# This class is responsible for handling HTTP requests passed to it.
# It implements the two most common HTTP methods, do_GET() and do_POST()
#
# One of the more important variables that can be used in this class is
# self.server.eyeFiConfiguration which holds the initial configuration data
#
class EyeFiRequestHandler(BaseHTTPRequestHandler):

  protocol_version = 'HTTP/1.1'
  sys_version = ""
  server_version = "Eye-Fi Agent/2.0.4.0 (Windows XP SP2)"    

  def __init__(self, request, client_address, server):
    BaseHTTPRequestHandler.__init__(self, request, client_address, server)


  def do_GET(self):
    eyeFiLogger.debug(self.command + " " + self.path + " " + self.request_version)
    
    self.send_response(200)
    self.send_header('Content-type','text/html')
    # I should be sending a Content-Length header with HTTP/1.1 but I am being lazy
    # self.send_header('Content-length', '123')
    self.end_headers()
    self.wfile.write(self.client_address)
    self.wfile.write(self.headers)
    self.close_connection = 0
    

  def do_POST(self):
    eyeFiLogger.debug(self.command + " " + self.path + " " + self.request_version)

    SOAPAction = ""
    contentLength = ""

    # Loop through all the request headers and pick out ones that are relevant    
    
    eyeFiLogger.debug("Headers received in POST request:")
    for headerName in self.headers.keys():
      for headerValue in self.headers.getheaders(headerName):

        if( headerName == "soapaction"):
          SOAPAction = headerValue
        
        if( headerName == "content-length"):
          contentLength = int(headerValue)

        eyeFiLogger.debug(headerName + ": " + headerValue)

    
    # Read contentLength bytes worth of data
    eyeFiLogger.debug("Attempting to read " + str(contentLength) + " bytes of data")
    postData = self.rfile.read(contentLength)
    eyeFiLogger.debug("Finished reading " + str(contentLength) + " bytes of data")
    
    # To avoid logging the entire photograph only log postData that is under 2K
    if( contentLength <= 2048 ):
      eyeFiLogger.debug("postData: " + postData)

    # TODO: Implement some kind of visual progress bar
    # bytesRead = 0
    # postData = ""
    
    # while(bytesRead < contentLength):
    #  postData = postData + self.rfile.read(1)
    #   bytesRead = bytesRead + 1
      
    #  if(bytesRead % 10000 == 0):
    #    print "#",    


    # Perform action based on path and SOAPAction
    # A SOAPAction of StartSession indicates the beginning of an EyeFi
    # authentication request
    if((self.path == "/api/soap/eyefilm/v1") and (SOAPAction == "\"urn:StartSession\"")):
      eyeFiLogger.debug("Got StartSession request")
      response = self.startSession(postData)
      contentLength = len(response)

      eyeFiLogger.debug("StartSession response: " + response)
            
      self.send_response(200)
      self.send_header('Date', self.date_time_string())      
      self.send_header('Pragma','no-cache')
      self.send_header('Server','Eye-Fi Agent/2.0.4.0 (Windows XP SP2)')
      self.send_header('Content-Type','text/xml; charset="utf-8"') 
      self.send_header('Content-Length', contentLength)
      self.end_headers()
      
      self.wfile.write(response)
      self.wfile.flush()
      self.handle_one_request()
    
    # GetPhotoStatus allows the card to query if a photo has been uploaded
    # to the server yet
    if((self.path == "/api/soap/eyefilm/v1") and (SOAPAction == "\"urn:GetPhotoStatus\"")):
      eyeFiLogger.debug("Got GetPhotoStatus request")

      response = self.getPhotoStatus(postData)
      contentLength = len(response)

      eyeFiLogger.debug("GetPhotoStatus response: " + response)
      
      self.send_response(200)
      self.send_header('Date', self.date_time_string())      
      self.send_header('Pragma','no-cache')
      self.send_header('Server','Eye-Fi Agent/2.0.4.0 (Windows XP SP2)')
      self.send_header('Content-Type','text/xml; charset="utf-8"') 
      self.send_header('Content-Length', contentLength)
      self.end_headers()
      
      self.wfile.write(response)
      self.wfile.flush()

      
    # If the URL is upload and there is no SOAPAction the card is ready to send a picture to me  
    if((self.path == "/api/soap/eyefilm/v1/upload") and (SOAPAction == "")):
      eyeFiLogger.debug("Got upload request")      
      response = self.uploadPhoto(postData)
      contentLength = len(response)

      eyeFiLogger.debug("Upload response: " + response)

      self.send_response(200)
      self.send_header('Date', self.date_time_string())      
      self.send_header('Pragma','no-cache')
      self.send_header('Server','Eye-Fi Agent/2.0.4.0 (Windows XP SP2)')
      self.send_header('Content-Type','text/xml; charset="utf-8"') 
      self.send_header('Content-Length', contentLength)
      self.end_headers()
      
      self.wfile.write(response)
      self.wfile.flush()

    # If the URL is upload and SOAPAction is MarkLastPhotoInRoll
    if((self.path == "/api/soap/eyefilm/v1") and (SOAPAction == "\"urn:MarkLastPhotoInRoll\"")):
      eyeFiLogger.debug("Got MarkLastPhotoInRoll request")      
      response = self.markLastPhotoInRoll(postData)
      contentLength = len(response)
      
      eyeFiLogger.debug("MarkLastPhotoInRoll response: " + response)
      self.send_response(200)
      self.send_header('Date', self.date_time_string())      
      self.send_header('Pragma','no-cache')
      self.send_header('Server','Eye-Fi Agent/2.0.4.0 (Windows XP SP2)')
      self.send_header('Content-Type','text/xml; charset="utf-8"') 
      self.send_header('Content-Length', contentLength)
      self.send_header('Connection', 'Close')      
      self.end_headers()
      
      self.wfile.write(response)
      self.wfile.flush()
      
      eyeFiLogger.debug("Connection closed.")


  # Handles MarkLastPhotoInRoll action
  def markLastPhotoInRoll(self,postData):
    # Create the XML document to send back
    doc = xml.dom.minidom.Document()

    SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","SOAP-ENV:Envelope")
    SOAPElement.setAttribute("xmlns:SOAP-ENV","http://schemas.xmlsoap.org/soap/envelope/")    
    SOAPBodyElement = doc.createElement("SOAP-ENV:Body")

    markLastPhotoInRollResponseElement = doc.createElement("MarkLastPhotoInRollResponse")
    
    SOAPBodyElement.appendChild(markLastPhotoInRollResponseElement)
    SOAPElement.appendChild(SOAPBodyElement)
    doc.appendChild(SOAPElement)

    return doc.toxml(encoding="UTF-8")


  # Handles receiving the actual photograph from the card.
  # postData will most likely contain multipart binary post data that needs to be parsed 
  def uploadPhoto(self,postData):
    
    # Take the postData string and work with it as if it were a file object
    postDataInMemoryFile = StringIO.StringIO(postData)
    
    # Get the content-type header which looks something like this
    # content-type: multipart/form-data; boundary=---------------------------02468ace13579bdfcafebabef00d    
    contentTypeHeader = self.headers.getheaders('content-type').pop()
    eyeFiLogger.debug(contentTypeHeader)
    
    # Extract the boundary parameter in the content-type header
    headerParameters = contentTypeHeader.split(";")
    eyeFiLogger.debug(headerParameters)      
    
    boundary = headerParameters[1].split("=")
    boundary = boundary[1].strip()
    eyeFiLogger.debug("Extracted boundary: " + boundary)          
    
    # eyeFiLogger.debug("uploadPhoto postData: " + postData)
    
    # Parse the multipart/form-data
    form = cgi.parse_multipart(postDataInMemoryFile, {"boundary":boundary,"content-disposition":self.headers.getheaders('content-disposition')})
    eyeFiLogger.debug("Available multipart/form-data: " + str(form.keys()))
    
    # Parse the SOAPENVELOPE using the EyeFiContentHandler()
    soapEnvelope = form['SOAPENVELOPE'][0]
    eyeFiLogger.debug("SOAPENVELOPE: " + soapEnvelope)
    handler = EyeFiContentHandler()
    parser = xml.sax.parseString(soapEnvelope,handler)

    eyeFiLogger.debug("Extracted elements: " + str(handler.extractedElements))

    
    # Write the newly uploaded file to memory
    untrustedFile = StringIO.StringIO()
    untrustedFile.write(form['FILENAME'][0])
        
    # Perform an integrity check on the file before writing it out
    eyeFiCrypto = EyeFiCrypto.EyeFiCrypto()
    verifiedDigest = eyeFiCrypto.calculateIntegrityDigest(untrustedFile.getvalue(),
                                                          self.server.eyeFiConfiguration['Card']['UploadKey'])
    unverifiedDigest = form['INTEGRITYDIGEST'][0]

    # Continue only if the digests match
    eyeFiLogger.debug("Comparing my digest [" + verifiedDigest + "] to card's digest [" + unverifiedDigest  + "].")
    if( verifiedDigest == unverifiedDigest ):
    
      # Figure out where I am going to put this file
      if( 'DownloadLocation' in self.server.eyeFiConfiguration['Global'] ):
        downloadLocation = os.path.normpath(self.server.eyeFiConfiguration['Global']['DownloadLocation'])
        tarFilePath = os.path.join(downloadLocation,handler.extractedElements["filename"])
      else:
        downloadLocation = os.path.join(os.curdir,"pictures")
        tarFilePath = os.path.join(os.curdir,"pictures",handler.extractedElements["filename"])
        
      # Check to see if the path exists, if it doesn't, create it
      if( os.path.exists(downloadLocation) == False ):
        eyeFiLogger.debug("Path " + downloadLocation + " does not exist. Creating it.")
        os.mkdir(downloadLocation)
      
      tarFile = open(tarFilePath,"wb")
      eyeFiLogger.debug("Opened file " + tarFilePath + " for binary writing")

      tarFile.write(untrustedFile.getvalue())
      eyeFiLogger.debug("Wrote file " + tarFilePath)

      tarFile.close()
      eyeFiLogger.debug("Closed file " + tarFilePath)

      eyeFiLogger.debug("Extracting TAR file " + tarFilePath)
      imageTarfile = tarfile.open(tarFilePath)
      imageNames = imageTarfile.getnames()     
      imageTarfile.extractall(downloadLocation)

      eyeFiLogger.debug("Closing TAR file " + tarFilePath)
      imageTarfile.close()

      eyeFiLogger.debug("Deleting TAR file " + tarFilePath)
      os.remove(tarFilePath)

      # Run a command on the file if specified
      if( 'ExecuteOnUpload' in self.server.eyeFiConfiguration['Global'] ):
        command = self.server.eyeFiConfiguration['Global']['ExecuteOnUpload']
        imagePath = os.path.join(downloadLocation,imageNames[0])      
        eyeFiLogger.debug("Executing command \"" + command + " " + imagePath + "\"")
        pid = subprocess.Popen([command, imagePath]).pid
      
      responseElementText = "true"
    else:   
      eyeFiLogger.error("Digests do not match. Check UploadKey setting in .ini file.")
      responseElementText = "false"
      
    # Close the temporary string buffer   
    untrustedFile.close()   
        
    # Create the XML document to send back
    doc = xml.dom.minidom.Document()

    SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","SOAP-ENV:Envelope")
    SOAPElement.setAttribute("xmlns:SOAP-ENV","http://schemas.xmlsoap.org/soap/envelope/")    
    SOAPBodyElement = doc.createElement("SOAP-ENV:Body")
    
    uploadPhotoResponseElement = doc.createElement("UploadPhotoResponse")
    successElement = doc.createElement("success")
    successElementText = doc.createTextNode(responseElementText)

    successElement.appendChild(successElementText)
    uploadPhotoResponseElement.appendChild(successElement)
    
    SOAPBodyElement.appendChild(uploadPhotoResponseElement)
    SOAPElement.appendChild(SOAPBodyElement)
    doc.appendChild(SOAPElement)

    return doc.toxml(encoding="UTF-8")
  
  # GetPhotoStatus allows the Eye-Fi card to query the server as to the current uploaded
  # status of a file. Even more important is that it authenticates the card to the server
  # by the use of the <credential> field. Essentially if the credential is correct the
  # server should allow files with the given filesignature to be uploaded.
  def getPhotoStatus(self,postData):
    handler = EyeFiContentHandler()
    parser = xml.sax.parseString(postData,handler)
   
    eyeFiLogger.debug("Extracted elements: " + str(handler.extractedElements))
    
    # Calculate the credential string that I am expecting the card to send to me
    credentialString = handler.extractedElements["macaddress"] + self.server.eyeFiConfiguration['Card']['UploadKey'] + self.server.serverNonce;
    eyeFiLogger.debug("Concatenated credential string (pre MD5): " + credentialString)
    
    binaryCredentialString = binascii.unhexlify(credentialString)
    m = hashlib.md5()
    m.update(binaryCredentialString)
    credential = m.hexdigest()
    eyeFiLogger.debug("Credential string I'm expecting from card: " + credential)
    eyeFiLogger.debug("Credential string I got from card: " + handler.extractedElements["credential"])
          

    # Create the XML document to send back
    doc = xml.dom.minidom.Document()

    SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","SOAP-ENV:Envelope")
    SOAPElement.setAttribute("xmlns:SOAP-ENV","http://schemas.xmlsoap.org/soap/envelope/")    
    SOAPBodyElement = doc.createElement("SOAP-ENV:Body")
    
    getPhotoStatusResponseElement = doc.createElement("GetPhotoStatusResponse")
    getPhotoStatusResponseElement.setAttribute("xmlns","http://localhost/api/soap/eyefilm")

    # Check the credentials and see what to send back
    if( handler.extractedElements["credential"] != credential ):
      eyeFiLogger.error("Eye-Fi card did not supply proper credential string in GetPhotoStatus SOAP call.")

    fileidElement = doc.createElement("fileid")
    fileidElementText = doc.createTextNode("1")
    fileidElement.appendChild(fileidElementText)
    
    offsetElement = doc.createElement("offset")
    offsetElementText = doc.createTextNode("0")
    offsetElement.appendChild(offsetElementText)
    
    getPhotoStatusResponseElement.appendChild(fileidElement)
    getPhotoStatusResponseElement.appendChild(offsetElement)
    
    SOAPBodyElement.appendChild(getPhotoStatusResponseElement)
    
    SOAPElement.appendChild(SOAPBodyElement)
    doc.appendChild(SOAPElement)

    return doc.toxml(encoding="UTF-8")
    
     
  def startSession(self, postData):  
    eyeFiLogger.debug("Delegating the XML parsing of startSession postData to EyeFiContentHandler()")
    handler = EyeFiContentHandler()
    parser = xml.sax.parseString(postData,handler)
    
    eyeFiLogger.debug("Extracted elements: " + str(handler.extractedElements))
    
    # Retrieve it from C:\Documents and Settings\<User>\Application Data\Eye-Fi\Settings.xml
    eyeFiUploadKey = self.server.eyeFiConfiguration['Card']['UploadKey']
    eyeFiLogger.debug("Setting Eye-Fi upload key to " + eyeFiUploadKey)
    
    credentialString = handler.extractedElements["macaddress"] + handler.extractedElements["cnonce"] + eyeFiUploadKey;
    eyeFiLogger.debug("Concatenated credential string (pre MD5): " + credentialString)

    # Return the binary data represented by the hexadecimal string
    # resulting in something that looks like "\x00\x18\x03\x04..."
    binaryCredentialString = binascii.unhexlify(credentialString)
    
    # Now MD5 hash the binary string    
    m = hashlib.md5()
    m.update(binaryCredentialString)
    
    # Hex encode the hash to obtain the final credential string
    credential = m.hexdigest()

    # Create the XML document to send back
    doc = xml.dom.minidom.Document()
    
    SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","SOAP-ENV:Envelope")
    SOAPElement.setAttribute("xmlns:SOAP-ENV","http://schemas.xmlsoap.org/soap/envelope/")    
    SOAPBodyElement = doc.createElement("SOAP-ENV:Body")
    

    startSessionResponseElement = doc.createElement("StartSessionResponse")
    startSessionResponseElement.setAttribute("xmlns","http://localhost/api/soap/eyefilm")

    credentialElement = doc.createElement("credential")
    credentialElementText = doc.createTextNode(credential)
    credentialElement.appendChild(credentialElementText)
        
    snonceElement = doc.createElement("snonce")
    snonceElementText = doc.createTextNode(str(self.server.serverNonce))
    snonceElement.appendChild(snonceElementText)
    
    transfermodeElement = doc.createElement("transfermode")
    transfermodeElementText = doc.createTextNode(handler.extractedElements["transfermode"])
    transfermodeElement.appendChild(transfermodeElementText)

    transfermodetimestampElement = doc.createElement("transfermodetimestamp")
    transfermodetimestampElementText = doc.createTextNode(handler.extractedElements["transfermodetimestamp"])
    transfermodetimestampElement.appendChild(transfermodetimestampElementText)

    upsyncallowedElement = doc.createElement("upsyncallowed")
    upsyncallowedElementText = doc.createTextNode("false")
    upsyncallowedElement.appendChild(upsyncallowedElementText)


    startSessionResponseElement.appendChild(credentialElement)
    startSessionResponseElement.appendChild(snonceElement)
    startSessionResponseElement.appendChild(transfermodeElement)
    startSessionResponseElement.appendChild(transfermodetimestampElement)
    startSessionResponseElement.appendChild(upsyncallowedElement)

    SOAPBodyElement.appendChild(startSessionResponseElement)
    
    SOAPElement.appendChild(SOAPBodyElement)
    doc.appendChild(SOAPElement)


    return doc.toxml(encoding="UTF-8")



def setupLogging(eyeFiConfiguration):

  # Declare the main logger as a global
  global eyeFiLogger
    
  # Determine the log level 
  if(eyeFiConfiguration['Global']['LogLevel'] == 'DEBUG'):
    loglevel = logging.DEBUG
    
  elif(eyeFiConfiguration['Global']['LogLevel'] == 'INFO'):
    loglevel = logging.INFO
    
  elif(eyeFiConfiguration['Global']['LogLevel'] == 'WARNING'):
    loglevel = logging.WARNING

  elif(eyeFiConfiguration['Global']['LogLevel'] == 'ERROR'):
    loglevel = logging.ERROR

  elif(eyeFiConfiguration['Global']['LogLevel'] == 'CRITICAL'):
    loglevel = logging.CRITICAL

  else:
    loglevel = logging.ERROR

  # Create the logger with the appropriate log level
  eyeFiLogger = logging.Logger("eyeFiLogger",loglevel)

  # Define the logging format to be used
  eyeFiLoggingFormat = logging.Formatter("[%(asctime)s][%(funcName)s] - %(message)s",'%m/%d/%y %I:%M%p')


  # Option to suppress console messages
  if( eyeFiConfiguration['Global'].as_bool('ConsoleOutput') == True ):
    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleHandler.setFormatter(eyeFiLoggingFormat)
    eyeFiLogger.addHandler(consoleHandler)

  # Option to log to a file
  if( 'LogFile' in eyeFiConfiguration['Global'] ):
    fileHandler = logging.FileHandler(eyeFiConfiguration['Global']['LogFile'],"w",encoding=None, delay=0)
    fileHandler.setFormatter(eyeFiLoggingFormat)
    eyeFiLogger.addHandler(fileHandler)

  # Define a do-nothing handler so that existing logging messages don't error out
  class NullHandler(logging.Handler):
    def emit(self, record):
      pass
  eyeFiLogger.addHandler(NullHandler())



def commandLineOptions():

  optionsParser.add_option("-c", "--config", action="store", dest="configfile",
                           help="Path to configuration file (example in DefaultSettings.ini)")


# This function attempts to read the configuration file. If no configuration
# was passed into the program then this function is responsible for setting
# defaults before returning the ConfigParser object
def readConfigurationFile(options):
  
  # Use the configobj 3rd party module
  from configobj import ConfigObj

  # Create a dictionary with default values
  defaultEyeFiConfiguration = { 'Global':
                                         { 'ListenPort': '59278',
                                           'LogLevel'  : 'INFO',
                                           'ConsoleOutput': 'True'}
                              }
                              
  # Load the defaults into a configuration object
  eyeFiConfiguration = ConfigObj(defaultEyeFiConfiguration)
  
  # If the configuration file parameter was given attempt to read the configuration file
  if( options.configfile != None ):
    eyeFiConfiguration.merge(ConfigObj(options.configfile))
  else:
    print "Warning: No configuration file specified! Run this server with the -h command."
  
  # Return the entire ConfigParser object
  return eyeFiConfiguration


  
def main():
  
  # Load the available command line options
  commandLineOptions()
  
  # Parse the command line options
  (options, args) = optionsParser.parse_args()
    
  # Read the configuration file
  eyeFiConfiguration = readConfigurationFile(options)
        
  # Setup the logging that will be used for the rest of the program
  setupLogging(eyeFiConfiguration)

  
  eyeFiLogger.debug("Command line options: " + str(options))
  eyeFiLogger.debug("eyeFiConfiguration: " + str(eyeFiConfiguration))

    
  # This is the hostname and port which the server will listen
  # for requests. A blank hostname indicates all interfaces.
  server_address = ('', eyeFiConfiguration['Global'].as_int('ListenPort'))
    
  try:
    # Create an instance of an HTTP server. Requests will be handled
    # by the class EyeFiRequestHandler
    eyeFiServer = EyeFiServer(server_address, EyeFiRequestHandler, eyeFiConfiguration)

    # Spawn a new thread for the server    
    eyeFiServerThread = threading.Thread(group=None, target=eyeFiServer.serve, name="EyeFiServerThread")    
    eyeFiServerThread.daemon = True
    eyeFiServerThread.start()

    eyeFiLogger.info("Eye-Fi server started listening on port " + str(server_address[1]))
    eyeFiLogger.info("Press <CTRL>+C to terminate.")

    while(True):
      time.sleep(60)
    
  except KeyboardInterrupt:
    eyeFiLogger.info("Eye-Fi server shutting down")
    
    # It is possible that the signal arrives before the eyeFiServer variable is initialized
    if( "eyeFiServer" in locals() ):
      eyeFiServer.stop()
      eyeFiServer.socket.close()
      
    eyeFiLogger.info("Eye-Fi server stopped")
      

if __name__ == '__main__':
    main()

