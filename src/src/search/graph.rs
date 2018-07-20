use fnv::FnvHashMap;
use indexmap::IndexMap;
use std::mem;

/**
A vertex of a graph. It contains a list of predecessors and a list of successors.

predecessors        A map from a vertex label to a length
successors          A map from a vertex label to a length
*/
#[derive(Clone, Debug)]
pub struct Vertex {
    pub predecessors: FnvHashMap<u128, f64>,
    pub successors: FnvHashMap<u128, f64>,
}

impl Vertex {
    /**
    Create a new vertex without any predecessors or successors.
    */
    fn new() -> Vertex {
        Vertex {
            predecessors: FnvHashMap::default(),
            successors: FnvHashMap::default(),
        }
    }

    /**
    Add a predecessor to the vertex.
    */
    fn add_predecessor(&mut self, 
                       predecessor: u128, 
                       length: f64) {
        self.predecessors.insert(predecessor, length);
    }

    /**
    Add a successor to the vertex.
    */
    fn add_successor(&mut self, 
                     successor: u128, 
                     length: f64) {
        self.successors.insert(successor, length);
    }
}

/*************************************************************************************************/

/**
A structure describing a multistage graph. 

vertices    A vector where each element contains a map of vertices for the given stage. 
*/
#[derive(Clone)]
pub struct MultistageGraph {
    pub vertices: Vec<FnvHashMap<u128, Vertex>>,
}

impl MultistageGraph {
    /**
    Create a new empty multistage graph with a fixed number of stages.
    
    stages      Number of stages in the graph.
    */
    pub fn new(stages: usize) -> MultistageGraph {
        let vertices = vec![FnvHashMap::default(); stages];

        MultistageGraph {
            vertices: vertices,
        }
    }

    /**
    Get the number of stages in the graph.
    */
    pub fn stages(&self) -> usize {
        self.vertices.len()
    }

    /**
    Adds a vertex to the graph. Panics if the target stage doesn't exist. 
    Does not insert the vertex if a vertex with the same label already exists in 
    the target stage. 

    stage       The stage to add the vertex to.
    label       The name of the vertex.
    */
    pub fn add_vertex(&mut self, 
                      stage: usize, 
                      label: u128) {    
        if !self.vertices.get(stage).expect("Stage out of range").contains_key(&label) {
            let vertex = Vertex::new();
            self.vertices.get_mut(stage)
                         .expect("Stage out of range")
                         .insert(label, vertex);
        }
    }

    /**
    Adds an edge with a length to the graph. Panics if the target stage or the following
    stage doesn't exist. If the endpoints don't exist, the edge isn't added. 

    stage       The stage of the start vertex.
    from        The label of the start vertex.
    to          The label of the end vertex.
    length      The length of the edge.
    */
    pub fn add_edge(&mut self, 
                    stage: usize, 
                    from: u128, 
                    to: u128, 
                    length: f64) {
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

    /** 
    Add multiple edges to the graph. Panics when edd_edge does. 

    edges   A map containg tupes of the type (stage, to, from) mapping to a length.
    */
    pub fn add_edges(&mut self, edges: &IndexMap<(usize, u128, u128), f64>) {
        for (&(stage, from, to), &length) in edges {
            self.add_edge(stage, from, to, length);
        }
    }

    /**
    Adds multiple edges to the graph, and crates vertices in the first or last stage if they
    don't exist. Does not create vertices in other stages.

    edges   A map containg tupes of the type (stage, from, to) mapping to a length.
    */
    pub fn add_edges_and_vertices(&mut self, edges: &IndexMap<(usize, u128, u128), f64>) {
        for (&(stage, from, to), &length) in edges {
            if stage == 0 {
                self.add_vertex(0, from);
            } 

            if stage == self.vertices.len()-2 {
                self.add_vertex(stage+1, to);
            }

            self.add_edge(stage, from, to, length);
        }
    }

    /**
    Removes a vertex from the graph. All other vertices are updates such that successors and 
    predecessors are consistent. 

    stage       Stage to remove a vertex from.
    label       Name of the vertex to remove.
    */
    pub fn remove_vertex(&mut self, 
                         stage: usize, 
                         label: u128) {
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

    /** 
    Remove any edges that aren't part of a path from a vertex in stage <start> to
    a vertex in stage <stop>. 
    
    start       Stage to perform pruning from.
    stop        Stage to perform pruning to.
    */
    pub fn prune(&mut self, 
                 start: usize, 
                 stop: usize) {
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

    /** 
    Reverses the graph, i.e. all edges are reversed, and the order of the stages are reversed.
    */
    pub fn reverse(&mut self) {
        self.vertices.reverse();
        
        for stage in self.vertices.iter_mut() {
            for (_, vertex) in stage.iter_mut() {
                mem::swap(&mut vertex.predecessors, &mut vertex.successors);
            }
        }       
    }

    /**
    Get a reference to a vertex. Returns None if the vertex doesn't exist.

    stage       Stage to get a vertex from.
    label       Name of the vertex.
    */
    pub fn get_vertex(&self, 
                      stage: usize, 
                      label: u128) 
                      -> Option<&Vertex> {
        self.vertices.get(stage).expect("Stage out of range.").get(&label)
    }

    /**
    Get a stage of the graph. Returns None if the stage index is out of range.

    stage       Stage to get. 
    */
    pub fn get_stage(&self, 
                     stage: usize) 
                     -> Option<&FnvHashMap<u128, Vertex>> {
        self.vertices.get(stage)
    }

    /**
    Check if a vertex exists. 
    
    stage       Stage to check.
    label       Label of the vertex.
    */
    pub fn has_vertex(&self, stage: usize, label: u128) -> bool {
        self.vertices.get(stage).expect("Stage out of range.").contains_key(&label)
    }

    /**
    Check if an edge exists.

    stage           Start stage of the edge.
    label_from      Start label of the edge.
    label_to        End label of the edge.
    */
    pub fn has_edge(&self, stage: usize, label_from: u128, label_to: u128) -> bool {
        match self.vertices.get(stage).expect("Stage out of range.").get(&label_from) {
            Some(vertex) => {
                return vertex.successors.contains_key(&label_to);
            },
            None => {
                return false;
            }
        }
    }

    /**
    Returns the number of vertices in the graph.
    */
    pub fn num_vertices(&self) -> usize {
        self.vertices.iter().fold(0, |sum, ref x| sum + x.len())
    }

    /**
    Returns the number of edges in the graph. 
    */
    pub fn num_edges(&self) -> usize {
        self.vertices.iter()
                     .fold(0, 
                        |sum0, ref x| sum0 + x.values()
                                           .fold(0, 
                                                |sum1, ref y| sum1 + y.successors.len()))
    }
}