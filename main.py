#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import socket   # 创建和操作ICMP套接字
import os       # 使用os模块中的getpid函数来获取当前进程的ID
import sys
import struct   # 打包和解包ICMP报文中的各个字段
import time     # 进行时间的记录和延时
import select   # 监听套接字是否可读，以便接收ICMP回复
import binascii

ICMP_ECHO_REQUEST = 8  # 回显请求消息的ICMP类型代码
ICMP_ECHO_REPLY = 0  # echo应答报文的ICMP类型代码
ICMP_Type_Unreachable = 11  # 不可接受的主机
ICMP_Type_Overtime = 3  # 请求延时
ID = 0  # ID of icmp_header
SEQUENCE = 0  # sequence of ping_request_msg


def checksum(string):
    """
    此函数作用是计算给定字符串的校验和，并返回计算结果。
    用于计算ICMP报文的校验和，校验和可以确保ICMP报文在传输过程中没有被篡改或者损坏。
    对于要发送的ICMP报文，可能需要计算并且设置正确的校验和以确保数据的完整性
    """
    csum = 0  # 初始化校验和变量

    countTo = (len(string) // 2) * 2  # 确保需要计算校验和的字节数是偶数，如果是奇数，最后一个单独字节无法与另一个字节配对。
    count = 0  # 初始化循环计数器

    while count < countTo:
        thisVal = string[count + 1] * 256 + string[count]  # 将每两个字节组合成16位整数，*256是为了左移八位
        csum = csum + thisVal  # 将每个16位整数累加到校验和中
        csum = csum & 0xffffffff  # 校验和限制在32位范围内，0xffffffff是一个三十二位的全为1的二进制数，用来限制位数
        count = count + 2  # 每次迭代处理两个字节

    if countTo < len(string):
        csum = csum + string[len(string) - 1]  # 如果字节数是奇数，则将最后一个字节添加到校验和中
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)  # 将校验和的高16位与低16位相加
    csum = csum + (csum >> 16)  # 将进位的结果加到校验和中
    answer = ~csum  # 对校验和按位取反
    answer = answer & 0xffff  # 将结果限制在16位范围内
    answer = answer >> 8 | (answer << 8 & 0xff00)  # 将结果进行字节序转换，高位和低位交换

    answer = socket.htons(answer)  # 将结果以网络字节序进行主机字节序转换

    return answer  # 返回计算得到的校验和

def receiveOnePing(icmpSocket, ID, timeout):
    # 1. Wait for the socket to receive a reply
    timeBeginReceive = time.time()  # 记录开始接收回复的时间
    whatReady = select.select([icmpSocket], [], [], timeout)  #select函数等待套接字‘icmpSocket’接收到回复。select函数会阻塞程序，直到套接字收到回复或超时发生
    timeInRecev = time.time() - timeBeginReceive  # 计算从开始到接收到回复的时间
    if not whatReady[0]:  # whatReady是通过select函数返回的列表，时表示可读事件的列表，如果whatReady【0】长度为0，表示套接字没有可读事件，即在超时时间内没有收到回复
        return -1
    timeReceived = time.time()  # 记录接收到回复的时间
    # 2. Once received, record time of receipt, otherwise, handle a timeout
    recPacket, addr = icmpSocket.recvfrom(1024)  # 使用套接字的 recvfrom() 方法接收 ICMP 包和发送者的地址，存储在变量 recPacket 和 addr 中。这里的 1024 是接收缓冲区的大小。
    # 3. Compare the time of receipt to time of sending, producing the total network delay
    byte_in_double = struct.calcsize("!d")  # 确定double类型的数据在字节流中的大小
    timeSent = struct.unpack("!d", recPacket[28: 28 + byte_in_double])[0]  #timeSent是指数据包从发送方发送出去的时间
    totalDelay = timeReceived - timeSent  # 通过接收时间和发送时间差计算延迟
    # 4. Unpack the packet header for useful information, including the ID
    rec_header = recPacket[20:28]  # 从接收到的ICMP包中提取出包头部分的信息，如回复类型 replyType、回复代码 replyCode、回复校验和 replyChecksum、回复ID replyId 和回复序列号 replySequence 等。
    replyType, replyCode, replyCkecksum, replyId, replySequence = struct.unpack('!bbHHh', rec_header)
    # 5. Check that the ID matches between the request and reply
    if ID == replyId and replyType == ICMP_ECHO_REPLY:
        # 6. Return total network delay
        """
        如果请求的ID和回复的ID匹配，并且回复类型是ICMP回复，则返回总的网络延迟
        """
        return totalDelay
    elif timeInRecev > timeout or replyType == ICMP_Type_Overtime:
        """
        如果接收到回复的时间超过超时时间timeout或者回复类型是ICMP超时，则返回-3表示超时或者过期
        """
        return -3  # ttl overtime/timeout
    elif replyType == ICMP_Type_Unreachable:
        """
        如果返回类型是ICMP不可达，则返回-11，表示目标不可达
        """
        return -11  # unreachable
    else:
        print("request over time")
        return -1


def sendOnePing(icmpSocket, destinationAddress, ID):
    icmp_checksum = 0
    # 1. Build ICMP header
    #  将！bbHHh格式字符串将后面五个参数分别打包成字节流
    icmp_header = struct.pack('!bbHHh', ICMP_ECHO_REQUEST, 0, icmp_checksum, ID, SEQUENCE)
    time_send = struct.pack('!d', time.time())  # 获得当前时间，并打包到time_send中
    # 2. Checksum ICMP packet using given function
    icmp_checksum = checksum(icmp_header + time_send)  # 通过对内部的两个数据进行连接，调用checksum函数计算ICMP校验和
    # 3. Insert checksum into packet
    #  使用计算得到的新的icmp_checksum更新ICMP头部
    icmp_header = struct.pack('!bbHHh', ICMP_ECHO_REQUEST, 0, icmp_checksum, ID, SEQUENCE)
    # 4. Send packet using socket
    icmp_packet = icmp_header + time_send  # 结合起来构建完整的ICMP数据包
    icmpSocket.sendto(icmp_packet, (destinationAddress, 80))  # 在端口80上向目标地址发送ICMP数据报
    # 5. Record time of sending
    timestamp = int(time.time())  # 记录发送的时间戳，并储存到头中
    icmp_header = struct.pack('!bbII', ICMP_ECHO_REQUEST, 0, timestamp, ID)



def doOnePing(destinationAddress, timeout):
    # 1. Create ICMP socket
    icmpName = socket.getprotobyname('icmp')  # 获取ICMP协议的名称，并将其赋值给icmpName变量
    icmp_Socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmpName)  # 用socket.socket（）函数创建一个ICMP套接字
    # 2. Call sendOnePing function
    sendOnePing(icmp_Socket, destinationAddress, ID)  # 发送ICMP消息到指定的目标地址
    # 3. Call receiveOnePing function
    totalDelay = receiveOnePing(icmp_Socket, ID, timeout)  # 等待接受并处理来自目标地址的ICMP回复消息，并计算延迟时间
    # 4. Close ICMP socket
    icmp_Socket.close()  #关闭之前创建的ICMP套接字，释放资源
    # 5. Return total network delay
    return totalDelay
    pass  # Remove/replace when function is complete


def ping(host, count, timeout):
    send = 0  # 发送数据包计数
    lost = 0  # 丢失数据包计数
    receive = 0  # 接收数据包计数
    maxTime = 0    #最大延迟时间初始化为0方便更新数据
    minTime = 1000  # 最小延迟时间初始化为一个较大的值方便更新数据
    sumTime = 0  # 接收到的数据报延迟时间总和
    # 1. Look up hostname, resolving it to an IP address
    desIp = socket.gethostbyname(host)  # 将主机名解析为IP地址
    global ID
    ID = os.getpid()  # 获取进程ID（PID），用作数据包的标识符
    for i in range(0, count):
        global SEQUENCE
        SEQUENCE = i  # ICMP数据包的序列号
        # 2. Call doOnePing function, approximately every second
        delay = doOnePing(desIp, timeout) * 1000  # 调用doOnePing函数，获取延迟时间（ms）
        send += 1  # 增加发送数据包计数器
        if delay > 0:
            receive += 1   # 如果有延迟，则增加接收数据报计数器
            if maxTime < delay:  # 如果当前延迟大于最大延迟时间，则更新最大延迟时间
                maxTime = delay
            if minTime > delay:  # 如果当前延迟时间小于最小延迟时间，则更新最小延迟时间
                minTime = delay
            sumTime += delay  # 更新总延迟时间
            # 3. Print out the returned delay
            print("Receive from: " + str(desIp) + ", delay = " + str(int(delay)) + "ms")
        else:
            lost += 1  # 延迟小于等于0的情况下，表示无法成功接收到数据包的响应
            print("Fail to connect. ", end="")  # end=”“表示结束时不会自动换行而是以一个空格结束
            if delay == -11:
                # type = 11, target unreachable
                print("Target net/host/port/protocol is unreachable.")
            elif delay == -3:
                # type = 3, ttl overtime
                print("Request overtime.")
            else:
                # otherwise, overtime
                print("Request overtime.")
        time.sleep(1)  # 暂停一秒继续运行
    # 4. Continue this process until stopped
    if receive != 0:
        avgTime = sumTime / receive  # 计算每次成功的ping的平均时间
        recvRate = receive / send * 100.0  # 计算成功率
        print(
            "\nSend: {0}, success: {1}, lost: {2}, rate of success: {3}%.".format(send, receive, lost, recvRate))
        print(
            "MaxTime = {0}ms, MinTime = {1}ms, AvgTime = {2}ms".format(int(maxTime), int(minTime), int(avgTime)))
    else:
        print("\nSend: {0}, success: {1}, lost: {2}, rate of success: 0.0%".format(send, receive, lost))


if __name__ == '__main__':
    while True:
        try:
            hostName = input("Input ip/name of the host you want: ")
            count = int(input("How many times you want to detect: "))
            timeout = int(input("Input timeout: "))
            ping(hostName, count, timeout)
            break
        except Exception as e:
            print(e)
            continue
