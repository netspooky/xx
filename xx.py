import sys
import hashlib
import argparse
import re, shlex, dis # Macro dependencies

parser = argparse.ArgumentParser(description="xx")
parser.add_argument('inFile', help='File to open')
parser.add_argument('-x', dest='dumpHex', help='Dump hex instead of writing file', action="store_true")
parser.add_argument('-o', dest='outFile', help='Output Filename')
parser.add_argument('-r', dest='rawOut', help='Dump buffer to stdout instead of writing file', action="store_true")
parser.add_argument('-m', dest='macroEnable', help='Enables macro support for advanced use (UNSAFE)', action="store_true")

xxVersion = "0.5"

# Comments - The box drawing comments are generated when checking a token
asciiComments = [ "#", ";", "%", "|","\x1b", "-", "/" ]
twoCharComments = [ "--", "//", ]
filterList = [",","$","\\x","0x","h",":"," "]
# XXX: Add rest of the escape sequences, what do we support here?
escapes = {"n":"\n", "\\":"\\", "t":"\t", "r":"\r"} # List of escape sequences to be interpreted when parsing quoted strings  

class xxToken:
    """
    Class to hold an xx token.
    This is a text element with certain attributes that need to be tracked.
    """
    def __init__(self, inData, lineNum, isComment, isString):
        # Data
        self.lineNum = lineNum # The line number
        self.rawData = inData # This is the raw token data. Save a copy of this and don't touch it.
        self.rawDataLen = len(inData) # This is the length of the raw token data. Save a copy of this and don't touch it
        self.normData = inData # This is where normalized data goes and is what is modified as the token is parsed
        self.normDataLen = len(inData) # This will be modified if normData is modified
        self.hexData = ""  # This is the fully parsed hex data that is passed to the main buffer to output
        # State 
        self.isString = isString # Is this token a string?
        self.isAscii = 0 # Does this token contain ASCII data?
        self.isComment = isComment # Is this token a comment?
        self.hasComment = 0 # Does this token contain a comment?
    def __str__(self):
        byterepr = bytes(self.rawData, 'latin1')
        return f"t\"{byterepr}\""
    def __repr__(self):
        byterepr = bytes(self.rawData, 'latin1')
        return f"xxToken({byterepr}, lineNum={self.lineNum}, isComment={self.isComment})"
    def testASCII(self):
        """
        Tests if the token can be decoded as ASCII
        """
        try:
            if self.normData.encode('ascii'):
                self.isAscii = 1
        except:
            return
    def testComment(self):
        """
        Test if a token either is a comment, or contains comments.
        Some may be missed in the first pass so we double check here.
        """
        if self.normDataLen > 0:
            firstCharComment = testCharComment(self.normData[0]) # This tests the first char
            if firstCharComment:
                self.isComment = 1
                return
            else:
                if self.normDataLen > 1:
                    if self.normData[0:2] in twoCharComments:
                        self.isComment = 1 # This means that the first two chars are a two char comment
                        return
            # If you get here, it could still be a comment, but within a string.
            # Example: 41414141#comment
            if self.isAscii == 0:
                cL = getCommentList()
                tempString = self.normData
                for comment in cL:
                    if comment in tempString:
                        tempString = tempString.split(comment)[0] # Split the comment away from this
                        self.hasComment = 1
                        self.normData = tempString
                        self.normDataLen = len(tempString)
        else:
            return 0
    def testHexData(self):
        """
        This attempts to decode the buffer as hex, if it succeeds, self.hexData is filled and self.isHex is set
        """
        if self.isComment == 0 and self.isString == False:
            tempData = filterIgnored(self.normData)
            try:
                testHex = bytes.fromhex(tempData)
                if(len(testHex) != 0):
                    # If we pass a string containing whitespace to bytes.fromhex()
                    # it returns an empty bytes object. We have to fail that or we
                    # lose the whitespace
                    self.isHex = 1
                    self.hexData = tempData
                    self.normData = tempData
                    self.normDataLen = len(tempData)
            except:
                return
    def getHexFromString(self):
        """
        This takes double quote enclosed string data and converts it to hexData
        """
        if self.isAscii and len(self.hexData) == 0:
            if self.isComment == 0:
                self.hexData = ascii2hex(self.normData)
    def testBinary(self):
        if self.isString == False:
            if len(self.normData) == 10:
                if self.normData[0:2] == "0y":
                    bindata = self.normData[2:]
                    for c in bindata:
                        if (c != "0") and (c != "1"):
                            return
                    self.normData = "{:02x}".format(int(bindata, 2))

class xxMacroProcessor:
    """
    Macro (pre)processor for xx language.
    """
    def __init__(self):
        self.macros = {}
        self.define_macro("$DEF", self.def_macro)

    def define_macro(self, name, body):
        """
        Defines a macro with the given name and body (can be an atom or function)
        """
        self.macros[name] = body

    def def_macro(self, name, body):
        """
        Internal macro definition function used for "$DEF" macro. If macro body starts with 'py' it is python code.
        """
        val = body
        if body.startswith("py"):
            val = eval(re.sub("λ|\\\.", "lambda", body[2:]))
        self.define_macro(name, val)

    def process_macros(self, line):
        """
        Processes macros in the given line and returns the resulting line. It implements it's own parsing using regex for better or worse.
        """
        # Remove comments from the line
        for comment in asciiComments + twoCharComments:
            line = line.split(comment)[0]

        # Define the pattern to match macros - example: (MACRO ARG1 ARG2 ...)
        pattern = r'(?<!\\)\([\s*]*([A-Za-z|$|@]\S*\b)((?:\s*"[^"]*"|\s*\S*)*)\s*\)'

        while True:
            match = re.search(pattern, line)
            if match:
                macro = match.group(1)
                args = shlex.split(match.group(2))  # Parse arguments, handling quoted strings
                try:
                    val = self.macros[macro]
                    if callable(val):
                        replacement = val(*args)
                    else:
                        replacement = str(val)
                except LookupError:
                    print(f"> {line} -> {macro} doesn't exist!")
                    exit()
                except SyntaxError:
                    print(f"> {line} -> syntax error at macro definition")
                    exit()
                except Exception as e:
                    print(f"> {line} -> {e}")
                    exit()
                if replacement is None:
                    replacement = ""
                
                line = line[:match.start()] + str(replacement) + line[match.end():]
            else:
                break

        return line

################################################################################
def getTokenAttributes(inTok):
    """
    Sets various token attributes
    """
    inTok.testASCII()
    inTok.testComment()
    inTok.testBinary()
    inTok.testHexData()
    inTok.getHexFromString()

def getCommentList():
    """
    This generates a list of all characters for comparison
    """
    cList = []
    for c in asciiComments:
        cList.append(c)
    for c in twoCharComments:
        cList.append(c)
    for c in range(9472,9633):
        cList.append(chr(c))
    return cList

def filterIgnored(inText):
    """
    This function filters out ignored characters.
    """
    for f in filterList:
        inText = inText.replace(f,"")
    return inText

def testCharComment(inChar):
    """
    A generic comment tester, checks if the input character is a comment or not
    """
    tCom = inChar
    o = ord(tCom)
    if (o >= 9472) and (o < 9632):
        return 1
    elif tCom in asciiComments:
        return 1
    else:
        return 0

################################################################################
def ascii2hex(inString):
    """
    Convert ASCII string to hex
    """
    formatted = ""
    for char in inString:
        hex_char = format(ord(char), "02x")
        formatted += hex_char
    return formatted

def writeBin(outbuf,outfile):
    """
    Writes the binary file
    """
    #outfile = f"{file_name.split('.xx')[0]}.{h}.bin"
    with open(outfile,'wb') as f:
        f.write(outbuf)
    print(outfile)

def dHex(inBytes):
    """
    Does a simple hex dump, use yxd library later
    """
    offs = 0
    while offs < len(inBytes):
        bHex = ""
        bAsc = ""
        bChunk = inBytes[offs:offs+16]
        for b in bChunk:
            bAsc += chr(b) if chr(b).isprintable() and b < 0x7F else '.'
            bHex += "{:02x} ".format(b)
        sp = " "*(48-len(bHex))
        print("{:08x}: {}{} {}".format(offs, bHex, sp, bAsc))
        offs = offs + 16
################################################################################
"""
inputs:
    multilineComment: are we currently within a multi-line comment (initial value: False)
    joinedLine: incremental fragments around multi-line comment (initial value: "")
    line: the current line to filter
outputs:
    multilineComment: updated accordingly
    joinedLine: updated accordingly
    lineResult: filtered line ready to consume, if mustContinue is False
    mustContinue: if True, the caller must continue / loop to get a new line
"""
def filterMultLineComments(multilineComment, joinedLine, line):
    lineResult = joinedLine
    joinedLine = ""
    mustContinue = False
    while len(line) > 0:
        if multilineComment:
            if "*/" in line:
                l = line.split("*/")
                line = "*/".join(l[1:])
                multilineComment = False
            else:
                joinedLine += lineResult
                mustContinue = True
                break
        else:
            if "/*" in line:
                l = line.split("/*")
                lineResult += l[0]
                line = "/*".join(l[1:])
                multilineComment = True
            else:
                lineResult += line
                break
    return multilineComment, joinedLine, lineResult, mustContinue

################################################################################
def tokenizeXX(xxline, lineNum):
    # We cannot just split() the string, since it will corrupt repeated whitespace
    # We have to interpret quoted string verbatim with no changes.
    # XXX: newline.xx: Comment gets inserted into file; "\n" error
    xxline = xxline.strip()
    tokens = []
    buf = ""
    verbatim = False # Verbatim mode means we are interpreting data in a string
    isEscape = False 
    isString = False
    for c in xxline:
        if c == "\\" and not isEscape and verbatim: # Interpret escape sequences
            isEscape = True
            continue
        if isEscape:
            # if an escape sequence is known then replace it, otherwise copy as is
            if c in escapes:
                buf += escapes[c]
            else:
                buf += "\\"
                buf += c
            isEscape = False
            continue
        if c == '"':
            # When we find a quote, switch verbatim mode - this preserves
            # whitespace and comment characters inside strings
            verbatim = not verbatim
            isString = True # This flag indicates that this buffer was a string
            continue
        if c == " " and not verbatim:
            # We split, but only if we are not inside a string rn
            if buf != "":
                # Avoid creating empty tokens if spaces are repeated.
                isComment = False
                for k in asciiComments + twoCharComments:
                    if k in buf:
                        isComment = True
                        break
                tokens.append(xxToken(buf, lineNum, isComment, isString))
                isString = False
            buf = ""
            continue
        buf += c
    tokens.append(xxToken(buf, lineNum, False, isString)) # Append last token on EOL
    return tokens

def parseXX(xxFile, macroEnable):
    if macroEnable: macro_processor = xxMacroProcessor()
    xxOut = b"" 
    lineNum = 0
    joinedLine = ""
    multilineComment = False
    for line in xxFile:
        lineNum = lineNum + 1
        multilineComment, joinedLine, line, mustContinue = filterMultLineComments(multilineComment, joinedLine, line)
        if mustContinue:
            continue
        
        if macroEnable: line = macro_processor.process_macros(line) # (Pre)Process line using macros
        lineTokens = tokenizeXX(line, lineNum)
        isComment = 0
        linesHexData = ""
        for t in lineTokens:
            getTokenAttributes(t)
            if t.isComment or t.hasComment:
                isComment = 1
                break
            linesHexData += t.hexData
        xxOut += bytes.fromhex(linesHexData)
    return xxOut

if __name__ == '__main__':
    args = parser.parse_args()
    inFile = args.inFile
    dumpHex = args.dumpHex
    outFile = args.outFile
    rawOut = args.rawOut
    macroEnable = args.macroEnable
    with open(inFile,"r") as f:
        xxFileLines = f.readlines()
    out = parseXX(xxFileLines, macroEnable)
    if dumpHex:
        dHex(out)
    elif rawOut:
        sys.stdout.buffer.write(out)
    else:
        m = hashlib.sha256()
        m.update(out)
        shorthash = m.digest().hex()[0:8]
        if outFile:
            filename = outFile
        else:
            filename = f"{inFile.split('.xx')[0]}.{shorthash}.bin"
        writeBin(out,filename)
