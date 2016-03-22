#=============================================================================#
# A simple python build script to build the singles/stages/stagers and 
# some usefull information such as offsets and a hex dump. The binary output
# will be placed in the bin directory. A hex string and usefull comments will
# be printed to screen.
#
# Example:
#     >python build.py stager_reverse_tcp_nx
#
# Example, to build everything:
#     >python build.py all > build_output.txt
#
# Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
#=============================================================================#
import os, sys, time
from subprocess import Popen
from struct import pack
#=============================================================================#
def clean( dir="./bin/" ):
  for root, dirs, files in os.walk( dir ):
    for name in files:
      if name[-4:] == ".bin":
        os.remove( os.path.join( root, name ) )
#=============================================================================#
def locate( src_file, dir="./src/" ):
  for root, dirs, files in os.walk( dir ):
    for name in files:
      if src_file == name:
        return root
  return None
#=============================================================================#
def build( name ):
  location = locate( "{0!s}.asm".format(name) )
  if location:
    input = os.path.normpath( os.path.join( location, name ) )
    output = os.path.normpath( os.path.join( "./bin/", name ) )
    p = Popen( ["nasm", "-f bin", "-O3", "-o {0!s}.bin".format(output), "{0!s}.asm".format(input) ] )
    p.wait()
    xmit( name )
  else:
    print "[-] Unable to locate '{0!s}.asm' in the src directory".format(name)
#=============================================================================#
def xmit_dump_ruby( data, length=16 ):
  dump = ""
  for i in xrange( 0, len( data ), length ):
    bytes = data[ i : i+length ]
    hex = "\"{0!s}\"".format(( ''.join( [ "\\x{0:02X}".format(ord(x)) for x in bytes ] ) ))
    if i+length <= len(data):
      hex += " +"
    dump += "{0!s}\n".format(( hex ))
  print dump
#=============================================================================#
def xmit_offset( data, name, value ):
  offset = data.find( value );
  if offset != -1:
    print "# {0!s} Offset: {1:d}".format(name, offset )
#=============================================================================#
def xmit( name, dump_ruby=True ):
  bin = os.path.normpath( os.path.join( "./bin/", "{0!s}.bin".format(name) ) )
  f = open( bin, 'rb')
  data = f.read()
  print "# Name: {0!s}\n# Length: {1:d} bytes".format(name, len( data ) )
  xmit_offset( data, "Port", pack( ">H", 4444 ) )           # 4444
  xmit_offset( data, "Host", pack( ">L", 0x7F000001 ) )     # 127.0.0.1
  xmit_offset( data, "ExitFunk", pack( "<L", 0x0A2A1DE0 ) ) # kernel32.dll!ExitThread
  xmit_offset( data, "ExitFunk", pack( "<L", 0x56A2B5F0 ) ) # kernel32.dll!ExitProcess
  xmit_offset( data, "ExitFunk", pack( "<L", 0xEA320EFE ) ) # kernel32.dll!SetUnhandledExceptionFilter
  xmit_offset( data, "ExitFunk", pack( "<L", 0xE035F044 ) ) # kernel32.dll!Sleep
  if dump_ruby:
    xmit_dump_ruby( data )
#=============================================================================#
def main( argv=None ):
  if not argv:
    argv = sys.argv
  try:
    if len( argv ) == 1:
      print "Usage: build.py [clean|all|<name>]"
    else:
      print "# Built on {0!s}\n".format((  time.asctime( time.localtime() ) ))
      if argv[1] == "clean":
        clean()
      elif argv[1] == "all":
        for root, dirs, files in os.walk( "./src/migrate/" ):
          for name in files:
            if name[-4:] == ".asm":
              build( name[:-4] )
        for root, dirs, files in os.walk( "./src/single/" ):
          for name in files:
            if name[-4:] == ".asm":
              build( name[:-4] )
        for root, dirs, files in os.walk( "./src/stage/" ):
          for name in files:
            if name[-4:] == ".asm":
              build( name[:-4] )
        for root, dirs, files in os.walk( "./src/stager/" ):
          for name in files:
            if name[-4:] == ".asm":
              build( name[:-4] )
      else:
        build( argv[1] )
  except Exception, e:
    print "[-] ", e
#=============================================================================#
if __name__ == "__main__":
  main()
#=============================================================================#