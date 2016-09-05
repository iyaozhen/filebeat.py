#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
使用Python简单实现filebeat(https://www.elastic.co/products/beats/filebeat)逻辑,推送数据到下游

Authors: iyaozhen
Date: 2016-04-20
Since: v2.0 2016-8-28
多日志文件支持
"""

import socket
import time
import json
import subprocess
import select
import random
import sys
import os
import logging
import logging.handlers
import Queue
import threading
import signal


class FileBeat(object):
    """
    py filebeat 类
    """
    def __init__(self, config_file):
        self.subprocess_list = []
        self.epoll_list = []

        try:
            with open(config_file, 'r') as f:
                conf = json.load(f)
        except IOError:
            sys.exit("read config file error")
        else:
            try:
                self.prospectors = conf['prospectors']
                self.filebeat_conf = conf['filebeat']
                self.logstash_conf = conf['logstash']
            except KeyError as e:
                sys.exit(e)
            else:
                self.init_log(self.filebeat_conf['logging']['path'],
                              self.filebeat_conf['logging']['level'])

                signal.signal(signal.SIGINT, self.signal_handler)
                signal.signal(signal.SIGTERM, self.signal_handler)

                self.sockets = self.get_sockets(self.logstash_conf)
                if self.sockets is False:
                    con_fail = "[error] can not connect logstash clusters"
                    logging.error(con_fail)
                    sys.exit()

    def publish_to_logstash(self, data, re_connect_per=10000):
        """
        发布数据到logstash集群
        Args:
            data: 需要推送的数据
                发出去的是个json格式数据包, 可以很方便设置一些自定义字段, logtash接收数据时配置:
                input {
                    tcp {
                        port => xxxx
                        codec => json
                    }
                }
            re_connect_per: 触发重连概率基数

        Returns:
            如果成功返回已发送内容的字节大小,失败返回False
        """
        # 随机选取出一个有效的socket通道（负载均衡）
        random_address = self.__random_choice_socket(self.sockets)
        # 全部通道不可用,触发重连
        if random_address is False:
            self.re_connect(self.sockets)
            # 直接返回失败,本次数据丢失
            return False
        else:
            # 概率触发重连
            if self.__random_trigger(re_connect_per):
                self.re_connect(self.sockets)
            try:
                res = self.sockets[random_address].sendall(data + '\r\n')
            except socket.error:
                if random_address is not False:
                    # 将出错的socket置为False
                    self.sockets[random_address] = False
                # 尝试重连
                self.re_connect(self.sockets)
                # 尝试重新发送
                # TODO 失败数据持久化存储
                return self.publish_to_logstash(data, re_connect_per)
            else:
                return res

    @staticmethod
    def get_socket(address):
        """
        根据配置信息建立tcp连接
        Args:
            address: host:name字符串

        Returns:
            建立成功返回socket对象, 失败返回False
        """
        (ip, port) = address.split(':')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)  # 在客户端开启心跳维持
        try:
            s.connect((ip, int(port)))
        except socket.error:
            return False
        else:
            return s

    def get_sockets(self, addresses):
        """
        根据配置信息建立tcp连接
        Args:
            addresses: host:name的list

        Returns:
            返回每个addresse对应的socket(字典), 全部连接失败返回False
        """
        sockets = {}
        for address in addresses:
            sockets[address] = self.get_socket(address)
        # 建立连接都没有成功
        if self.sockets_is_all_fail():
            return False
        else:
            return sockets

    def re_connect(self):
        """
        重建连接

        Returns:
            None
        """
        for address, socket in self.sockets.iteritems():
            if socket is False:
                self.sockets[address] = self.get_socket(address)

    def sockets_is_all_fail(self):
        """
        检查已经建立连接的sockets是否都挂了

        Returns:
            bool
        """
        for socket in self.sockets.values():
            if socket is not False:
                return False

        return True

    def __random_choice_socket(self):
        """
        随机选择一个可用的通道

        Returns:
            socket object, if all failure return False
        """
        real_sockets = {}
        for address, socket in self.sockets.iteritems():
            if socket is not False:
                real_sockets[address] = socket

        if real_sockets:
            return random.choice(real_sockets.keys())
        else:
            return False

    @staticmethod
    def __random_trigger(denominator):
        """
        1/denominator return True
        Args:
            denominator: 概率分母

        Returns:
            bool
        """
        if random.randint(1, denominator) == 1:
            return True
        else:
            return False

    @staticmethod
    def __list_in_string(search, string):
        """
        判断list中的某个元素是否在字符串中
        Args:
            search: list, 需要去string中查找的字符串集
            string: 字符串

        Returns:
            bool
        """
        return any(temp in string for temp in search)

    def data_filter(self, data, include_lines=None, exclude_lines=None):
        """
        数据过滤器, 检测数据是否可以通过过滤
        Args:
            data: 获取到的数据
            include_lines: 需要包含的行
            exclude_lines: 需要排除的行

        Returns:
            bool
        """
        if include_lines is not None:
            # 有白名单则需至少命中一个才能通过
            if self.__list_in_string(include_lines, data):
                if exclude_lines is not None:
                    # 黑名单命中一个就不能通过
                    if self.__list_in_string(exclude_lines, data):
                        return False
                    else:
                        return True
                else:
                    return True
            else:
                return False
        else:
            if exclude_lines is not None:
                if self.__list_in_string(exclude_lines, data):
                    return False
                else:
                    return True
            else:
                return True

    @staticmethod
    def tail_file(file_path, from_head=False):
        """
        创建子进程tail file
        Args:
            file_path: 文件路径
            from_head: 是否重头开始读取文件

        Returns:

        """
        if from_head is True:
            # 先输出现有文件全部内容, 然后tail文件
            # -F 当文件变化时能切换到新的文件
            cmd = "cat %s && tail -F %s" % (file_path, file_path)
        else:
            cmd = "tail -F %s" % file_path

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True, bufsize=1)
        except OSError as e:
            return False, str(e)
        else:
            # https://docs.python.org/2/library/select.html
            epoll = select.epoll()
            epoll.register(process.stdout)

            return process, epoll

    @staticmethod
    def get_current_path(file_path, file_ext):
        """
        获取当前文件路径
        Args:
            file_path: 文件基础路径
            file_ext: 文件后缀(时间戳参数)

        Returns:
            string
        """
        if file_ext is not None:
            return file_path % time.strftime(file_ext, time.localtime())
        else:
            return file_path

    @classmethod
    def wait_file(cls, current_file_path, file_path, file_date_ext):
        # 如果文件不存在, 等待当前文件生成
        while FileBeat.is_non_zero_file(current_file_path) is False:
            time.sleep(60)
            current_file_path = FileBeat.get_current_path(file_path, file_date_ext)

        return current_file_path

    @staticmethod
    def is_non_zero_file(file_path):
        """
        检查文件是否存在且不为空
        Args:
            file_path: 文件路径

        Returns:
            bool
        """
        return True if os.path.isfile(file_path) and os.path.getsize(file_path) > 0 \
            else False

    @staticmethod
    def init_log(log_path, level=logging.INFO, max_mb=100, backup_count=7,
                 log_format="%(levelname)s: %(asctime)s: %(filename)s:%(lineno)d * %(thread)d %(message)s",
                 datefmt="%m-%d %H:%M:%S"):
        """
        init_log - initialize log module

        Args:
          log_path:      - Log file path prefix.
                           Log data will go to two files: log_path.log and log_path.log.wf
                           Any non-exist parent directories will be created automatically
          level:         - msg above the level will be displayed
                           DEBUG < INFO < WARNING < ERROR < CRITICAL
                           the default value is logging.INFO
          max_mb:     - a file max size(MB)
                           default value: 1000*1000*100=100MB
          backup_count:  - how many backup file to keep
                           default value: 7
          log_format:    - format of the log
                           default format:
                           %(levelname)s: %(asctime)s: %(filename)s:%(lineno)d * %(thread)d %(message)s
                           INFO: 12-09 18:02:42: log.py:40 * 139814749787872 HELLO WORLD
          datefmt:        - log date format

        Raises:
            OSError: fail to create log directories
            IOError: fail to open log file

        Returns:
            None
        """
        formatter = logging.Formatter(log_format, datefmt)
        logger = logging.getLogger()
        logger.setLevel(level)

        log_dir = os.path.dirname(log_path)
        if not os.path.isdir(log_dir):
            os.makedirs(log_dir)

        max_mb *= 1000 * 1000
        handler = logging.handlers.RotatingFileHandler(log_path + ".log",
                                                       maxBytes=max_mb,
                                                       backupCount=backup_count)
        handler.setLevel(level)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        handler = logging.handlers.RotatingFileHandler(log_path + ".log.wf",
                                                       maxBytes=max_mb,
                                                       backupCount=backup_count)
        handler.setLevel(logging.WARNING)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    def prospector(self, prospector, queue, from_head=True):
        file_path = prospector['path']
        file_date_ext = prospector['date_ext']
        encoding = prospector['encoding']
        include_lines = prospector['include_lines']
        exclude_lines = prospector['exclude_lines']
        fields = prospector['fields']

        current_file_path = FileBeat.get_current_path(file_path, file_date_ext)
        last_file_path = current_file_path
        # 如果文件不存在, 等待当前文件生成
        while FileBeat.is_non_zero_file(current_file_path) is False:
            logging.info("waiting file create %s" % current_file_path)
            time.sleep(60)
            current_file_path = FileBeat.get_current_path(file_path, file_date_ext)
        while True:
            # 创建子进程tail文件
            logging.info("start tail file %s" % current_file_path)
            (process, epoll) = FileBeat.tail_file(current_file_path, from_head)
            if process is False:
                error_str = epoll
                logging.error(error_str)
            else:
                if process not in self.subprocess_list:
                    self.subprocess_list.append(process)
            # 轮训子进程是否获取到数据
            while True:
                if epoll.poll(1):  # timeout 1s
                    data = process.stdout.readline().rstrip()
                    if len(data) > 0:
                        is_no_data = False
                        logging.debug("get data form subprocess.PIPE [%s]", data)
                        # 统一转换为unicode编码
                        data_unicode = data.decode(encoding, 'ignore')
                        if FileBeat.data_filter(data_unicode, include_lines, exclude_lines):
                            # 数据封装
                            packaged_data = {
                                'message': data_unicode.encode('utf8', 'ignore')
                            }
                            # 添加自定义字段
                            if fields is not None:
                                for key, value in fields.iteritems():
                                    packaged_data[key] = value
                            packaged_data = json.dumps(packaged_data)
                            logging.debug("packaged data [%s]", data)
                            # put no wait
                            try:
                                queue.put(packaged_data, False)
                            except Queue.Full:
                                logging.error("queue is full, data loss [%s]" % packaged_data)
                    else:
                        is_no_data = True
                else:
                    is_no_data = True

                if is_no_data:
                    # 若当前目标日志文件名变化, 则跳出循环, 读取新的文件
                    current_file_path = FileBeat.get_current_path(file_path, file_date_ext)
                    if current_file_path != last_file_path:
                        try:
                            epoll.unregister(process.stdout)
                            epoll.close()
                        except KeyError:
                            logging.error("epoll object unregister or close error")
                        try:
                            process.send_signal(signal.SIGINT)
                            process.terminate()
                        except OSError:
                            logging.error("kill sub process error")
                        if process in self.subprocess_list:
                            self.subprocess_list.remove(process)
                        last_file_path = current_file_path
                        break

    def signal_handler(self, *args):
        """
        safe exit
        Args:
            *args:

        Returns:
            None

        """
        for indx in xrange(len(self.subprocess_list)):
            epoll = self.subprocess_list[indx]
            process = self.epoll_list[indx]
            # stop tail -F
            process.send_signal(signal.SIGINT)
            epoll.unregister(process.stdout)
            epoll.close()
            # close sub process
            logging.info('close sub process %s' % process.pid)
            process.terminate()
            process.wait()

        sys.exit('safe exit')

    def run(self):
        """
        主进程，读取配置文件然后创建子进程运行日志收集任务
        Returns:
            None
        """
        # 和线程间使用队列通讯
        q = Queue.Queue(maxsize=self.filebeat_conf['queue_maxsize'])
        for prospector in self.prospectors:
            t = threading.Thread(target=FileBeat.prospector,
                                 args=(prospector, q, False))
            t.daemon = True
            t.start()

        logging.info("all thread is already running")

        while True:
            # block get data from the queue.
            data = q.get()
            print data
            # if FileBeat.publish_to_logstash(sockets, data, re_connect_per) is False:
            #     logging.error("publish to logstash failure [%s]" % data)
            # else:
            #     logging.info("publish to logstash success")


if __name__ == "__main__":
    FileBeat('./filebeat.json').run()
