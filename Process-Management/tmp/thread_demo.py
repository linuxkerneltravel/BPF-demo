#!/usr/bin/python
#encoding: utf-8
import threading


#  银行存钱和取钱
def add(lock):
    global money  # 生命money为全局变量
    for i in range(1000000):
        # 2. 操作变量之前进行加锁
        lock.acquire()
        money += 1  # money;  money+1; money=money+1;
        # 3. 操作变量之后进行解锁
        lock.release()


def reduce(lock):
    global money
    for i in range(1000000):
        # 2. 操作变量之前进行加锁
        lock.acquire()
        money -= 1
        # 3. 操作变量之后进行解锁
        lock.release()


if __name__ == '__main__':
    money = 0
    # 1. 实例化一个锁对象;
    lock = threading.Lock()

    t1 = threading.Thread(target=add, args=(lock,))
    t2 = threading.Thread(target=reduce, args=(lock,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    print("当前金额:", money)
