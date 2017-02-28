#! /usr/bin/python

import sys
import socket
import struct
import random

class TraceGenerator(object):
    def __init__(self, as_num):
        self.as_num = as_num
        self.entry_num = 10
        self.test_num = 250
        self.rand_range = 2 ** 32 - 1
        self.base_entry1 = ',46.20.255.29-3,37.49.237.83,0(IGP),'
        self.base_entry2 = ',9318:120 25091:25409 65300:6695,151,0\n'
        self.lines_trace = []

    def run(self):
        preloaded_num = self.as_num * self.entry_num
        total_num = preloaded_num + self.test_num * 2
        self.lines_trace = ['%d %d\n' % (total_num, preloaded_num)] + self.lines_trace
        prefixes = random.sample(xrange(0, self.rand_range), preloaded_num + self.test_num)
        for i in xrange(0, self.as_num):
            for j in xrange(0, self.entry_num):
                entry = socket.inet_ntoa(struct.pack("!I", prefixes[i * self.entry_num + j])) + self.base_entry1 + '%d' % i + self.base_entry2
                self.lines_trace.append('%d 1\n' % i)
                self.lines_trace.append(entry)
        for i in xrange(0, self.test_num):
            entry = socket.inet_ntoa(struct.pack("!I", prefixes[preloaded_num + i])) + self.base_entry1 + '0' + self.base_entry2
            self.lines_trace.append('0 1\n')
            self.lines_trace.append(entry)
            self.lines_trace.append('0 2\n')
            self.lines_trace.append(entry)

    def write_to_file(self):
        fn_trace = './conf/trace_%d.conf' % self.as_num
        fp_trace = open(fn_trace, 'w+')
        fp_trace.writelines(self.lines_trace)
        fp_trace.close()

if __name__ == '__main__':
    if len(sys.argv) is not 2:
        print 'usage: ./trace_gen.py [as_num]'
        exit(0)
    as_num = int(sys.argv[1])
    trace_generator = TraceGenerator(as_num)
    trace_generator.run()
    trace_generator.write_to_file()
