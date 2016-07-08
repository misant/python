#!/usr/bin/env python
import paramiko
from multiprocessing import Pool
import getpass

#hostnames = ['172.16.70.3', '172.16.70.2']
hostnamesf = open('rb', 'r')
hostnames = hostnamesf.readlines()
hostnamesf.close()


user = 'admin'
#pw = getpass.getpass("Enter ssh password:")
ssh = paramiko


def processFunc(hostname):
    handle = ssh.SSHClient()
    handle.set_missing_host_key_policy(ssh.AutoAddPolicy())
    handle.connect(hostname, username=user)
    print("child")
    stdin, stdout, stderr = handle.exec_command("system identity print; system clock print")
    cmdOutput = ""
    while True:
        try:
            cmdOutput += stdout.next()
        except StopIteration:
            break
    print("Got output from host %s:%s" % (hostname, cmdOutput))
    handle.close()

pool = Pool(len(hostnames))
pool.map(processFunc, hostnames, 1)
pool.close()
pool.join()

## If you want to compare speed:
#for hostname in hostnames:
#    processFunc(hostname)
