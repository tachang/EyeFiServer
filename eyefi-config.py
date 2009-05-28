import os
import time

log = open('requestMessage.log', 'wb')

requestMessageFilename = "D:\\EyeFi\\reqm"
requestCounterFilename = "/media/CASIO-DSC/EyeFi/reqc"
responseMessageFilename = "/media/CASIO-DSC/EyeFi/rspm"

counter = 1
previousRequestMessage = ""
while(True):

  requestMessageFile = open(requestMessageFilename, "r")

  
  requestMessage = requestMessageFile.read(16)

  if(previousRequestMessage != requestMessage):
    message = ""
    for char in requestMessage:
      message = message + "," + str(hex(ord(char)))

    log.write(str(counter) + ": " + message + "\n")
    previousRequestMessage = requestMessage
    log.flush()
    
  requestMessageFile.close()
  counter = counter + 1


# message = "l".ljust(16384,"\x00")


