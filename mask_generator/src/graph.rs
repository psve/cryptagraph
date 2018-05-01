use fnv::FnvHashMap;
use indexmap::IndexMap;

#[derive(Clone, Debug)]
pub struct Vertex {
    pub predecessors: FnvHashMap<usize, f64>,
    pub successors: FnvHashMap<usize, f64>,
}

impl Vertex {
    fn new() -> Vertex {
        Vertex {
            predecessors: FnvHashMap::default(),
            successors: FnvHashMap::default(),
        }
    }

    fn add_predecessor(&mut self, predecessor: usize, length: f64) {
        self.predecessors.insert(predecessor, length);
    }

    fn add_successor(&mut self, successor: usize, length: f64) {
        self.successors.insert(successor, length);
    }
}

/*************************************************************************************************/

#[derive(Clone)]
pub struct MultistageGraph {
    vertices: Vec<FnvHashMap<usize, Vertex>>,
}

impl MultistageGraph {
    pub fn new(stages: usize) -> MultistageGraph {
        let vertices = vec![FnvHashMap::default(); stages];

        MultistageGraph {
            vertices: vertices,
        }
    }

    pub fn stages(&self) -> usize {
        self.vertices.len()
    }

    pub fn add_vertex(&mut self, stage: usize, label: usize) {    
        if !self.vertices.get(stage).expect("Stage out of range").contains_key(&label) {
            let vertex = Vertex::new();
            self.vertices.get_mut(stage)
                         .expect("Stage out of range")
                         .insert(label, vertex);
        }
    }

    pub fn add_edge(&mut self, stage: usize, from: usize, to: usize, length: f64) {
        if self.vertices.get(stage).expect("Stage out of range").contains_key(&from) &&
           self.vertices.get(stage+1).expect("Stage out of range").contains_key(&to) {
            {
                let from_vertex = self.vertices.get_mut(stage)
                                      .expect("Stage out of range")
                                      .get_mut(&from).expect("Error 1");
                from_vertex.add_successor(to, length);
            }
            {
                let to_vertex = self.vertices.get_mut(stage+1)
                                    .expect("Stage out of range")
                                    .get_mut(&to).expect("Error 2");
                to_vertex.add_predecessor(from, length);
            }
        }
    }

    pub fn add_edges(&mut self, edges: &IndexMap<(usize, usize, usize), f64>) {
        for (&(stage, from, to), &length) in edges {
            self.add_edge(stage, from, to, length);
        }
    }

    pub fn add_edges_and_vertices(&mut self, edges: &IndexMap<(usize, usize, usize), f64>) {
        for (&(stage, from, to), &length) in edges {
            if stage == 0 {
                self.add_vertex(0, from);
            } else {
                self.add_vertex(stage+1, to);
            }

            self.add_edge(stage, from, to, length);
        }
    }

    pub fn remove_vertex(&mut self, stage: usize, label: usize) {
        {
            let (before, mid) = self.vertices.split_at_mut(stage);
            let (mid, after) = mid.split_at_mut(1);
            match mid[0].get(&label) {
                Some(vertex) => {
                    match before.last_mut() {
                        Some(other_stage) => {
                            for other in vertex.predecessors.keys() {
                                let mut other_vertex = other_stage.get_mut(&other).expect("Error 5");
                                other_vertex.successors.remove(&label);
                            }
                        },
                        None => {}
                    }

                    match after.first_mut() {
                        Some(other_stage) => {
                            for other in vertex.successors.keys() {
                                let mut other_vertex = other_stage.get_mut(&other).expect("Error 6");
                                other_vertex.predecessors.remove(&label);
                            }   
                        },
                        None => {}
                    }
                },
                None => { }
            }
        }

        self.vertices[stage].remove(&label);
    }

    /* Remove any edges that aren't part of a path from source to sink. 
     *
     * graph    Graph to prune.
     */
    pub fn prune_graph(&mut self, start: usize, stop: usize) {
        let mut pruned = true;

        while pruned {
            pruned = false;

            for stage in start..stop {
                let mut remove = Vec::new();

                for (&label, vertex) in self.get_stage(stage).unwrap() {
                    if stage == start && vertex.successors.len() == 0 {
                        remove.push(label);
                    } else if stage == stop-1 && vertex.predecessors.len() == 0 {
                        remove.push(label);
                    } else if (stage != start && stage != stop-1) && (vertex.successors.len() == 0 ||
                        vertex.predecessors.len() == 0) {
                        remove.push(label);
                    }
                }

                for label in remove {
                    self.remove_vertex(stage, label);
                    pruned = true;
                }
            }
        }
    }

    pub fn get_vertex(&self, stage: usize, label: usize) -> Option<&Vertex> {
        self.vertices.get(stage).expect("Stage out of range.").get(&label)
    }

    pub fn get_stage(&self, stage: usize) -> Option<&FnvHashMap<usize, Vertex>> {
        Some(&self.vertices.get(stage).expect("Stage out of range."))
    }

    pub fn has_vertex(&self, stage: usize, label: usize) -> bool {
        self.vertices.get(stage).expect("Stage out of range.").contains_key(&label)
    }

    pub fn num_vertices(&self) -> usize {
        self.vertices.iter().fold(0, |sum, ref x| sum + x.len())
    }

    pub fn num_edges(&self) -> usize {
        self.vertices.iter()
                     .fold(0, 
                        |sum0, ref x| sum0 + x.values()
                                           .fold(0, 
                                                |sum1, ref y| sum1 + y.successors.len()))
    }
}