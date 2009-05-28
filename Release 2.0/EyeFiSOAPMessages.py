import xml.sax
from xml.sax.handler import ContentHandler 
import xml.dom.minidom


class EyeFiSOAPMessages():


  def getUploadPhotoXML(self, fileid, macaddress, filename, filesize, filesignature, encryption):
    doc = xml.dom.minidom.Document()
    
    SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","SOAP-ENV:Envelope")
    SOAPElement.setAttribute("xmlns:SOAP-ENV","http://schemas.xmlsoap.org/soap/envelope/")    
    SOAPElement.setAttribute("xmlns:ns1","EyeFi/SOAP/EyeFilm")    

    SOAPBodyElement = doc.createElement("SOAP-ENV:Body")
    
    uploadPhotoElement = doc.createElement("ns1:UploadPhoto")

    fileidElement = doc.createElement("fileid")
    fileidElementText = doc.createTextNode(str(fileid))
    fileidElement.appendChild(fileidElementText)

    macaddressElement = doc.createElement("macaddress")
    macaddressElementText = doc.createTextNode(str(macaddress))
    macaddressElement.appendChild(macaddressElementText)

    filenameElement = doc.createElement("filename")
    filenameElementText = doc.createTextNode(str(filename))
    filenameElement.appendChild(filenameElementText)

    filesizeElement = doc.createElement("filesize")
    filesizeElementText = doc.createTextNode(str(filesize))
    filesizeElement.appendChild(filesizeElementText)

    filesignatureElement = doc.createElement("filesignature")
    filesignatureElementText = doc.createTextNode(str(filesignature))
    filesignatureElement.appendChild(filesignatureElementText)

    encryptionElement = doc.createElement("encryption")
    encryptionElementText = doc.createTextNode(str(encryption))
    encryptionElement.appendChild(encryptionElementText)

    uploadPhotoElement.appendChild(fileidElement)
    uploadPhotoElement.appendChild(macaddressElement)
    uploadPhotoElement.appendChild(filenameElement)
    uploadPhotoElement.appendChild(filesizeElement)
    uploadPhotoElement.appendChild(filesignatureElement)
    uploadPhotoElement.appendChild(encryptionElement)

    SOAPBodyElement.appendChild(uploadPhotoElement)
    SOAPElement.appendChild(SOAPBodyElement)
    doc.appendChild(SOAPElement)

    return doc.toxml(encoding="UTF-8")

  def getStartSessionXML(self, macaddress, cnonce, transfermode, transfermodetimestamp):
    doc = xml.dom.minidom.Document()
    
    SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","SOAP-ENV:Envelope")
    SOAPElement.setAttribute("xmlns:SOAP-ENV","http://schemas.xmlsoap.org/soap/envelope/")    
    SOAPBodyElement = doc.createElement("SOAP-ENV:Body")
    
    startSessionElement = doc.createElement("StartSession")
    startSessionElement.setAttribute("xmlns","EyeFi/SOAP/EyeFilm")
    
    macaddressElement = doc.createElement("macaddress")
    macaddressElementText = doc.createTextNode(str(macaddress))
    macaddressElement.appendChild(macaddressElementText)
        
    cnonceElement = doc.createElement("cnonce")
    cnonceElementText = doc.createTextNode(str(cnonce))
    cnonceElement.appendChild(cnonceElementText)

    transfermodeElement = doc.createElement("transfermode")
    transfermodeElementText = doc.createTextNode(str(transfermode))
    transfermodeElement.appendChild(transfermodeElementText)

    transfermodetimestampElement = doc.createElement("transfermodetimestamp")
    transfermodetimestampElementText = doc.createTextNode(str(transfermodetimestamp))
    transfermodetimestampElement.appendChild(transfermodetimestampElementText)

    startSessionElement.appendChild(macaddressElement)
    startSessionElement.appendChild(cnonceElement)
    startSessionElement.appendChild(transfermodeElement)
    startSessionElement.appendChild(transfermodetimestampElement)

    SOAPBodyElement.appendChild(startSessionElement)
    
    SOAPElement.appendChild(SOAPBodyElement)
    doc.appendChild(SOAPElement)

    return doc.toxml(encoding="UTF-8")

  def getPhotoStatusXML(self, credential, macaddress, filename, filesize, filesignature ):
    doc = xml.dom.minidom.Document()
    
    SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","SOAP-ENV:Envelope")
    SOAPElement.setAttribute("xmlns:SOAP-ENV","http://schemas.xmlsoap.org/soap/envelope/")    
    SOAPElement.setAttribute("xmlns:ns1","EyeFi/SOAP/EyeFilm")    

    SOAPBodyElement = doc.createElement("SOAP-ENV:Body")
    
    getPhotoStatusElement = doc.createElement("ns1:GetPhotoStatus")

    credentialElement = doc.createElement("credential")
    credentialElementText = doc.createTextNode(str(credential))
    credentialElement.appendChild(credentialElementText)
        
    macaddressElement = doc.createElement("macaddress")
    macaddressElementText = doc.createTextNode(str(macaddress))
    macaddressElement.appendChild(macaddressElementText)

    filenameElement = doc.createElement("filename")
    filenameElementText = doc.createTextNode(str(filename))
    filenameElement.appendChild(filenameElementText)
    
    filesizeElement = doc.createElement("filesize")
    filesizeElementText = doc.createTextNode(str(filesize))
    filesizeElement.appendChild(filesizeElementText)
    
    filesignatureElement = doc.createElement("filesignature")
    filesignatureElementText = doc.createTextNode(str(filesignature))
    filesignatureElement.appendChild(filesignatureElementText)

    getPhotoStatusElement.appendChild(credentialElement)
    getPhotoStatusElement.appendChild(macaddressElement)
    getPhotoStatusElement.appendChild(filenameElement)
    getPhotoStatusElement.appendChild(filesizeElement)
    getPhotoStatusElement.appendChild(filesignatureElement)
    
    SOAPBodyElement.appendChild(getPhotoStatusElement)
    SOAPElement.appendChild(SOAPBodyElement)
    doc.appendChild(SOAPElement)

    return doc.toxml(encoding="UTF-8")
      
  def getSOAPFaultXML(self, faultvalue, faulttext):
    doc = xml.dom.minidom.Document()
    
    SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","SOAP-ENV:Envelope")
    SOAPElement.setAttribute("xmlns:SOAP-ENV","http://schemas.xmlsoap.org/soap/envelope/")    
    SOAPBodyElement = doc.createElement("SOAP-ENV:Body")
        
    SOAPFaultElement = doc.createElement("SOAP-ENV:Fault")
    codeElement = doc.createElement("SOAP-ENV:Code")
    
    valueElement = doc.createElement("SOAP-ENV:Value")
    valueElementText = doc.createTextNode(str(faultvalue))
    valueElement.appendChild(valueElementText)
    
    reasonElement = doc.createElement("SOAP-ENV:Reason")
    
    faulttextElement = doc.createElement("SOAP-ENV:Text")
    faulttextElement.setAttribute("xml:lang","en-US")
    faulttextElementText = doc.createTextNode(str(faulttext))
    faulttextElement.appendChild(faulttextElementText)

    codeElement.appendChild(valueElement)
    reasonElement.appendChild(faulttextElement)
    
    SOAPFaultElement.appendChild(codeElement)
    SOAPFaultElement.appendChild(reasonElement)

    SOAPBodyElement.appendChild(SOAPFaultElement)
    
    SOAPElement.appendChild(SOAPBodyElement)
    doc.appendChild(SOAPElement)

    return doc.toxml(encoding="UTF-8")

