#! /usr/bin/python

import sys
from random import randint
from collections import defaultdict

if len(sys.argv) is not 2:
    print 'usage: ./topo_gen.py [as_num]'
    exit(0)

as_num = int(sys.argv[1])
fn_topo = './conf/topo_sparse_%d.conf' % as_num
fn_as = './conf/as_sparse_%d.conf' % as_num
edge_num = 0

as_relationships = defaultdict(lambda: defaultdict(lambda: []))
lines_topo = []
lines_as = []

def eliminate_loop(as_num, as_graph):
    global edge_num
    global lines_topo
    as_recursion = defaultdict(lambda: 0)
    #print 'start to eliminate loops'
    for i in range(0, as_num):
        #print 'as %d' % i
        if as_recursion[i]:
            #print 'skip %d' % i
            continue
        path  = [-1]
        stack = [-1,i]
        while len(stack) != 1:
            #print 'new while current stack:', stack
            #print 'new while current path:', path
            if stack[-1] == path[-1]:
                stack = stack[:-1]
                path = path[:-1]
                continue
            iter_as = stack[-1]
            path.append(iter_as)
            as_recursion[iter_as] = 1
            #print 'iter %d current path ' % iter_as, path
            if len(as_graph[iter_as][1]) is 0:
                #print 'the end of a line'
                path = path[:-1]
                stack = stack[:-1]
                #print 'after the end stack:', stack
                #print 'after the end path:', path
                continue
            #print 'iter %d customers: ' % iter_as, as_graph[iter_as][1]
            for i in as_graph[iter_as][1]:
                if i in path:
                    #print '...........loop detected provider:%d --> customer:%d..........' % (iter_as, i)
                    as_graph[i][3].remove(iter_as)
                    e1 = '%d %d %d\n' % (iter_as, i, 1)
                    e2 = '%d %d %d\n' % (i, iter_as, 3)
                    if e1 in lines_topo:
                        lines_topo.remove(e1)
                        edge_num -= 1
                    if e2 in lines_topo:
                        lines_topo.remove(e2)
                        edge_num -= 1
            as_graph[iter_as][1][:] = [i for i in as_graph[iter_as][1] if i not in path]
            for j in as_graph[iter_as][1]:
                stack.append(j)

fp_topo = open(fn_topo, 'w+')
fp_as = open(fn_as, 'w+')

# 0: without connection, 1: i is j's provider
# 3: i is j's customer, 2: i and j are peers
# for as_relationships, 1 means customer, 2 means peer, 3 means provider
rand_range = as_num / 5
for i in range(0, as_num):
    for j in range(i+1, as_num):
        relationship = randint(0, rand_range)
        if relationship >= 1 and relationship <= 3:
            edge_num += 1
            lines_topo.append('%d %d %d\n' % (i, j, relationship))
            as_relationships[i][relationship].append(j)
            as_relationships[j][4-relationship].append(i)

# print the original graph by edges
#print 'the original graph, as_num:%d' % as_num
#for i in lines_topo:
#    print i[:-1]

# detect and eliminate loops for an directed graph, provider --> customer
eliminate_loop(as_num, as_relationships)

lines_topo = ['%d %d\n' % (as_num, edge_num)] + lines_topo

lines_as.append('%d\n' % as_num)
for i in range(0, as_num):
    for r in range(1, 4):
        lines_as.append('%d' % len(as_relationships[i][r]))
        for j in range(0, len(as_relationships[i][r])):
            lines_as.append(' %d' % as_relationships[i][r][j])
        lines_as.append('\n')

fp_topo.writelines(lines_topo)
fp_as.writelines(lines_as)
fp_topo.close()
fp_as.close()
