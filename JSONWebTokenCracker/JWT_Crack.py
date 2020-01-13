#!/usr/bin/python3
import sys, os, queue, threading, jwt
from termcolor import colored

NumOfThreads=100
Queue = queue.Queue()

try:
    encoded=sys.argv[1]
    WordList=open(sys.argv[2],'r')
except:
    print("Usage: %s encoded wordlist" % sys.argv[0])
    sys.exit(1)

class checkHash(threading.Thread):
    def __init__(self,Queue):
        threading.Thread.__init__(self)
        self.Queue=Queue
    def run(self):
        while True:
            self.secret=self.Queue.get()
            try:
                jwt.decode(encoded, self.secret, algorithms=['HS256'])
                print(colored('Success! ['+self.secret+']','green'))
                os._exit(0)
                self.Queue.task_done()
            except jwt.InvalidTokenError:
                print(colored('Invalid Token ['+self.secret+']','red'))
            except jwt.ExpiredSignatureError:
                print(colored('Token Expired ['+self.secret+']','red'))

for i in range(NumOfThreads):
    t=checkHash(Queue)
    t.setDaemon(True)
    t.start()

for word in WordList.readlines():
    Queue.put(word.strip())

Queue.join()
