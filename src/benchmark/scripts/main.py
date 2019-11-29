import os

def test(file, args, configFile, loglevel="info"):
    cmd = """./ptrace -l %s -f %s -c %s -o logs/log.txt -r report -d childlog --args=%s""" % (loglevel, file, configFile, args)
    print(cmd)
    ret = os.system(cmd)
    print(ret)

def testOpenKey():
    file = "openkey"
    args = "testFile"
    f = open(args, "w")
    f.close()
    configFile = "default_config.yaml"
    test(file, args, configFile)

def testReadKey():
    file = "readkey"
    args = "testFile"
    configFile = "default_config.yaml"
    test(file, args, configFile)

def testWriteKey():
    file = "writekey"
    args = "testFile"
    configFile = "default_config.yaml"
    test(file, args, configFile)

def testNetLink():
    file = "netlink"
    args = ""
    configFile = "default_config.yaml"
    test(file, args, configFile)

if __name__ == "__main__":
    testOpenKey()
    testNetLink()
    testReadKey()
    testWriteKey()