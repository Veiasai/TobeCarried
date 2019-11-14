import os

def test(file, args, configFile, loglevel="Info"):
    os.system("ptrace -l %s -f %s -c %s -a=%s" % (loglevel, file, configFile, args))

def testOpenKey():
    file = "openKey"
    args = "testFile"
    configFile = ""
    test(file, args, configFile)

def testReadKey():
    file = "readKey"
    args = "testFile"
    configFile = ""
    test(file, args, configFile)

def testWriteKey():
    file = "writeKey"
    args = "testFile"
    configFile = ""
    test(file, args, configFile)

if __name__ == "__main__":
    testOpenKey()
    testReadKey()
    testWriteKey()