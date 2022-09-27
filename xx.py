import sys
import hashlib
import re
import argparse

parser = argparse.ArgumentParser(description="xx")
parser.add_argument('inFile', help='File to open')
parser.add_argument('-x', dest='dumpHex', help='Dump hex instead of writing file', action="store_true")

xxVersion = "0.3"

comments = [ "--", "//", "#", ";", "%", "|","\x1b",
             "┌","─","┬","┐","╔","═","╦","╗","╓","╥",
             "╖","╒","╤","╕","│","║","├","┼","┤","╠",
             "╬","╣","╟","╫","╢","╞","╪","╡","└","┴",
             "┘","╚","╩","╝","╙","╨","╜","╘","╧","╛"
            ]

filterList = [",","$","\\x","0x","h",":"," "]

def writeBin(b,h,file_name):
    outfile = f"{file_name.split('.xx')[0]}.{h}.bin"
    with open(outfile,'wb') as f:
        f.write(b)
    print(outfile)

def dHex(inBytes):
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

def repl(matchobj):
    formatted = matchobj.group(1)
    for char in matchobj.group(2):
        hex_char = format(ord(char), "x")
        formatted += hex_char
    return formatted

def parseString(inText):
    strPattern = '(.*?)"([^"]+?)"'
    result3 = re.sub(strPattern, repl, inText)
    return result3

def filterComments(inText):
    for f in filterList:
        inText = inText.replace(f,"")
    return inText

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


"""
inputs: 
  xxFile -- a list of lines from an xx file to parse
outputs: 
  xxOut -- a binary buffer of compiled hex data from the xx file
"""
def parseXX(xxFile):
    xxOut = b""
    multilineComment = False
    joinedLine = ""
    lineNum = 0
    for line in xxFile:
        origLine = line
        lineNum = lineNum + 1
        multilineComment, joinedLine, line, mustContinue = filterMultLineComments(multilineComment, joinedLine, line)
        if mustContinue:
            continue
        try:
            for comment in comments:
                if comment in line:
                    line = line.split(comment)[0]
            line = parseString(line)
            line = filterComments(line)
            xxOut += bytes.fromhex(line)
        except Exception as e:
            print(f"Syntax Error on Line: {lineNum}")
            print(f"Line {lineNum}: {origLine}\n")
            print(e)
            sys.exit(1)
    return xxOut

if __name__ == '__main__':
    args = parser.parse_args()
    inFile = args.inFile
    dumpHex = args.dumpHex

    out = b""

    with open(inFile,"r") as f:
        xxFile = f.readlines()

    out = parseXX(xxFile)

    if dumpHex:
        dHex(out)
    else:
        m = hashlib.sha256()
        m.update(out)
        shorthash = m.digest().hex()[0:8]
        writeBin(out,shorthash,inFile)

