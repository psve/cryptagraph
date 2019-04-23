#!/bin/python

from graph_tool.all import *
import csv, sys

size = 1000
width = int(size * 2)
height = size

path = sys.argv[1]
vertex_data = set()
edge_data = set()

with open(path, "r") as f:
    reader = csv.reader(f)
    
    for row in reader:
        data = [int(x) for x in row]
        vertex_data.add((data[0], data[1]))
        vertex_data.add((data[2], data[3]))
        edge_data.add((data[0], data[1], data[2], data[3]))

print("Data read")

vertices = dict()

for x in vertex_data:
    vertices[x] = len(vertices)

stages = max([x for (x,y) in vertices.keys()]) + 1

g = Graph(directed=True)

for e in edge_data:
    f = vertices[(e[0], e[1])]
    t = vertices[(e[2], e[3])]
    g.add_edge(f, t)

print("Graph generated")

pos = g.new_vertex_property("vector<float>")
max_name = max([x[1] for x in vertices.keys()])

for v in vertices.keys():
    x = (v[0]-1) / (stages-1) * width
    y = v[1] / max_name * height
    pos[vertices[v]] = [x, y]

print("Positions generated")

graph_draw(g, pos = pos, \
    vertex_size = 3.5, \
    output_size = (width, height), \
    bg_color = [1,1,1,1], \
    edge_pen_width= 0.1, \
    edge_color = [0.09, 0.40, 0.549, 1.0], \
    vertex_color = [0.871, 0.106, 0.106, 1.0], \
    output = path+".png")
