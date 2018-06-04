from graph_tool.all import *
import csv, sys

def num_active(x):    
    count = 0

    for i in range(16):
        if ((x >> 4*i) & 0xf) != 0:
            count += 1

    return count

size = 1000
# width = int(size * (16/9))
width = int(size * 2)
height = size

path = sys.argv[1]
vertex_data = []
edge_data = []

with open(path, "r") as f:
    reader = csv.reader(f)
    
    for row in reader:
        if len(row) == 2:
            vertex_data.append([int(x) for x in row])
        elif len(row) == 4:
            edge_data.append([int(x) for x in row])

print("Data read")

vertices = dict()
labels = dict()

for x in vertex_data:
    labels[len(vertices)] = (x[0], x[1])
    vertices[(x[0], x[1])] = len(vertices)

stages = max([x for (x,y) in vertices.keys()]) + 1

g = Graph(directed=True)

for e in edge_data:
    f = vertices[(e[0], e[1])]
    t = vertices[(e[2], e[3])]
    g.add_edge(f, t)

print("Graph generated")

# start_vertices = [(x,y) for (x,y) in vertices.keys() if x == 0]
# end_vertices = [(x,y) for (x,y) in vertices.keys() if x == stages-1]

# s = vertices[start_vertices[0]]
# t = vertices[end_vertices[0]]

# for path in all_paths(g, s, t):
#     x = [labels[i][1] for i in path]
    
#     for y in x:
#         print("{:016x}->".format(y), end="")
#     print()

pos = g.new_vertex_property("vector<float>")
max_name = max([x[1] for x in vertices.keys()])
# max_name = max([num_active(x[1]) for x in vertices.keys()])

for v in vertices.keys():
    x = (v[0]-1) / (stages-1) * width
    # y = num_active(v[1]) / max_name * height
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
