import threading
import time
def hello():
    print("hello world")
t=threading.Thread(target=hello)
t.start()