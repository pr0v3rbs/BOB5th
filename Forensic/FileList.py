import os
import sys

# cui color highlight, i use only OKBLUE and ENDC
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# print target directory files
def PrintDirs(dir):
    fileList = sorted(os.listdir(dir)) # get files from directory
    for file in fileList:
        if os.path.isdir(dir + "/" + file): # check that file was directory to highlight text
            sys.stdout.write(bcolors.OKBLUE + file + bcolors.ENDC + "  ")
        else:
            sys.stdout.write(file + "  ")
    print ""

# print target directory files with recurrsive search
def PrintRecurDirs(dir):
    dirList = [dir]
    while len(dirList) != 0:
        curDir = dirList[0]
        del dirList[0] # get head directory item
        print curDir + " :"
        PrintDirs(curDir) # print directory files
        print ""
        fileList = sorted(os.listdir(curDir))
        for file in fileList:
            if os.path.isdir(curDir + "/" + file): # check and insert directory in list
                dirList.append(curDir + "/" + file)


dir = "./"
isRecurrsive = False
isParseSuccess = True

# check user input
if len(sys.argv) == 2:
    dir = sys.argv[1]
elif len(sys.argv) == 3:
    if sys.argv[1] == "-r": # check recurrsive option
        isRecurrsive = True
        dir = sys.argv[2]
    else:
        isParseSucess = False
elif len(sys.argv) != 1:
    isParseSuccess = False


if isParseSuccess and os.path.exists(dir): # last check before running
    if isRecurrsive:
        PrintRecurDirs(dir)
    else:
        PrintDirs(dir)
else :
    print "Invalid directory"
