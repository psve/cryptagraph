use fnv::FnvHashMap;

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
        let vertex = Vertex::new();

        if stage < self.vertices.len() && !self.vertices[stage].contains_key(&label) {
            self.vertices[stage].insert(label, vertex);
        }
    }

    pub fn add_edge(&mut self, stage: usize, from: usize, to: usize, length: f64) {
        if stage+1 < self.vertices.len() && 
           self.vertices[stage].contains_key(&from) &&
           self.vertices[stage+1].contains_key(&to) {
            {
                let from_vertex = self.vertices[stage].get_mut(&from).expect("Error 1");
                from_vertex.add_successor(to, length);
            }
            {
                let to_vertex = self.vertices[stage+1].get_mut(&to).expect("Error 2");
                to_vertex.add_predecessor(from, length);
            }
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
                                // println!("{} {} {}", stage, label, other);
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

    pub fn get_vertex(&self, stage: usize, label: usize) -> Option<&Vertex> {
        if stage < self.vertices.len() {
            self.vertices[stage].get(&label)
        } else {
            None
        }
    }

    pub fn get_stage(&self, stage: usize) -> Option<&FnvHashMap<usize, Vertex>> {
        if stage < self.vertices.len() {
            Some(&self.vertices[stage]) 
        } else {
            None
        }
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