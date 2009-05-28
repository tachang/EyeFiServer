import binascii
import struct
import array
import hashlib

class EyeFiCrypto():
    
  # The TCP checksum requires an even number of bytes. If an even
  # number of bytes is not passed in then nul pad the input and then
  # compute the checksum
  def calculateTCPChecksum(self, bytes):

    # If the number of bytes I was given is not a multiple of 2
    # pad the input with a null character at the end
    if(len(bytes) % 2 != 0 ):
      bytes = bytes + "\x00"
        
    counter = 0
    sumOfTwoByteWords = 0
        
    # Loop over all the bytes, two at a time
    while(counter < len(bytes) ):
    
      # For each pair of bytes, cast them into a 2 byte integer (unsigned short)
      # Compute using little-endian (which is what the '<' sign if for)
      unsignedShort = struct.unpack("<H",bytes[counter:counter+2])
      
      # Add them all up
      sumOfTwoByteWords = sumOfTwoByteWords + int(unsignedShort[0])
      counter = counter + 2

    
    # The sum at this point is probably a 32 bit integer. Take the left 16 bits
    # and the right 16 bites, interpret both as an integer of max value 2^16 and
    # add them together. If the resulting value is still bigger than 2^16 then do it
    # again until we get a value less than 16 bits.
    while (sumOfTwoByteWords >> 16):
      sumOfTwoByteWords = (sumOfTwoByteWords >> 16) + (sumOfTwoByteWords & 0xFFFF) 
    
    # Take the one's complement of the result through the use of an xor
    checksum = sumOfTwoByteWords ^ 0xFFFFFFFF

    # Compute the final checksum by taking only the last 16 bits
    checksum = (checksum & 0xFFFF)
    
    return checksum

  
  def calculateIntegrityDigest(self, bytes, uploadkey):

    # If the number of bytes I was given is not a multiple of 512
    # pad the input with a null characters to get the proper alignment
    while(len(bytes) % 512 != 0 ):
      bytes = bytes + "\x00"
      
    counter = 0
    
    # Create an array of 2 byte integers
    concatenatedTCPChecksums = array.array('H')
    
    # Loop over all the bytes, using 512 byte blocks
    while(counter < len(bytes) ): 
      
      tcpChecksum = self.calculateTCPChecksum(bytes[counter:counter+512])
      concatenatedTCPChecksums.append(tcpChecksum)
      counter = counter + 512

    # Append the upload key
    concatenatedTCPChecksums.fromstring(binascii.unhexlify(uploadkey))

    # Get the concatenatedTCPChecksums array as a binary string
    integrityDigest = concatenatedTCPChecksums.tostring()
    
    # MD5 hash the binary string    
    m = hashlib.md5()
    m.update(integrityDigest)
    
    # Hex encode the hash to obtain the final integrity digest
    integrityDigest = m.hexdigest()
    
    return integrityDigest
