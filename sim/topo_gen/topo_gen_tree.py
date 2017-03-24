#! /usr/bin/python

import sys
from random import randint
from collections import defaultdict

class TopoGenerator(object):
    def __init__(self, as_num):
        self.as_num = as_num
        self.edge_num = 0
        self.rand_range = as_num / 10   # parameter
        self.as_relationships = defaultdict(lambda: defaultdict(lambda: []))
        self.lines_topo = []
        self.lines_as = []

    def run(self):
        # 3: i is j's customer, 2: i and j are peers
        # for as_relationships, 1 means customer, 2 means peer, 3 means provider
        for i in range(0, self.as_num):
            for j in range(i+1, self.as_num):
                relationship = randint(0, self.rand_range)
                if relationship == 2 or relationship == 3:
                    self.edge_num += 1
                    self.lines_topo.append('%d %d %d\n' % (i, j, relationship))
                    self.as_relationships[i][relationship].append(j)
                    self.as_relationships[j][4-relationship].append(i)

    def write_to_file(self):
        fn_topo = './conf/topo_tree_%d.conf' % self.as_num
        fn_as = './conf/as_tree_%d.conf' % self.as_num
        fp_topo = open(fn_topo, 'w+')
        fp_as = open(fn_as, 'w+')
        self.lines_topo = ['%d %d\n' % (self.as_num, self.edge_num)] + self.lines_topo
        self.lines_as.append('%d\n' % self.as_num)
        for i in range(0, self.as_num):
            for r in range(1, 4):
                self.lines_as.append('%d' % len(self.as_relationships[i][r]))
                for j in range(0, len(self.as_relationships[i][r])):
                    self.lines_as.append(' %d' % self.as_relationships[i][r][j])
                self.lines_as.append('\n')
        fp_topo.writelines(self.lines_topo)
        fp_as.writelines(self.lines_as)
        fp_topo.close()
        fp_as.close()

if __name__ == "__main__":
    if len(sys.argv) is not 2:
        print 'usage: ./topo_gen.py [as_num]'
        exit(0)
    as_num = int(sys.argv[1])
    topo_generator = TopoGenerator(as_num)
    topo_generator.run()
    topo_generator.write_to_file()
