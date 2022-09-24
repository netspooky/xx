import sys
import hashlib
import re
import argparse

parser = argparse.ArgumentParser(description="xx")
parser.add_argument('inFile', help='File to open')
parser.add_argument('-x', dest='dumpHex', help='Dump hex instead of writing file', action="store_true")

xxVersion = "0.2"

comments = [ "--", "//", "#", ";", "%", "|",
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
            bHex += "{:02X} ".format(b)
        sp = " "*(48-len(bHex))
        print("{:08X}: {}{} {}".format(offs, bHex, sp, bAsc))
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

if __name__ == '__main__':
    args = parser.parse_args()
    inFile = args.inFile
    dumpHex = args.dumpHex

    out = b""

    with open(inFile,"r") as f:
        xxFile = f.readlines()

    lineNum = 0
    for line in xxFile:
        lineNum = lineNum + 1
        try:
            for comment in comments:
                if comment in line:
                    line = line.split(comment)[0]    
            line = parseString(line)
            line = filterComments(line)
            out += bytes.fromhex(line)
        except Exception as e:
            print(f"Syntax Error on Line: {lineNum}")
            print(f"Line {lineNum}: {line}\n")
            print(e)
            sys.exit(1)

    if dumpHex:
        dHex(out)
    else:
        m = hashlib.sha256()
        m.update(out)
        shorthash = m.digest().hex()[0:8]
        writeBin(out,shorthash,inFile)
