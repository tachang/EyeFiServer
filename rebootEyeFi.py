import os
import time

requestMessageFilename = "D:\\EyeFi\\REQM"
requestMessageFile = open(requestMessageFilename, "w")

message = "\x62".ljust(16384,"\x00")
requestMessageFile.write(message)
requestMessageFile.flush()
requestMessageFile.close()

print "Issued Eye-Fi reboot command"