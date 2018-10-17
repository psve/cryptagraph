//! Types for representing a multistage graph. 

use fnv::FnvHashMap;
use indexmap::IndexMap;
use std::mem;

/// A vertex of a graph. The vertex knows its predecessors and successors as well as 
/// the distances to these.
#[derive(Clone, Debug)]
pub struct Vertex {
    predecessors: FnvHashMap<u128, f64>,
    pub successors: FnvHashMap<u128, f64>,
}

impl Vertex {
    /// Create a new vertex without any predecessors or successors.
    fn new() -> Vertex {
        Vertex {
            predecessors: FnvHashMap::default(),
            successors: FnvHashMap::default(),
        }
    }

    /// Add a predecessor to the vertex.
    fn add_predecessor(&mut self, 
                       predecessor: u128, 
                       length: f64) {
        self.predecessors.insert(predecessor, length);
    }

    /// Add a successor to the vertex.
    fn add_successor(&mut self, 
                     successor: u128, 
                     length: f64) {
        self.successors.insert(successor, length);
    }

    /// Checks if the vertex has any predecessors
    pub fn has_predecessors(&self) -> bool {
        !self.predecessors.is_empty()
    }

    /// Checks if the vertex has any successors
    pub fn has_successors(&self) -> bool {
        !self.successors.is_empty()
    }
}

/*************************************************************************************************/

/// A structure describing a directed multistage graph. 
#[derive(Clone)]
pub struct MultistageGraph {
    pub vertices: Vec<FnvHashMap<u128, Vertex>>,
}

impl MultistageGraph {
    /// Create a new empty multistage graph with a fixed number of stages.
    pub fn new(stages: usize) -> MultistageGraph {
        let vertices = vec![FnvHashMap::default(); stages];

        MultistageGraph {
            vertices,
        }
    }

    /// Get the number of stages in the graph.
    pub fn stages(&self) -> usize {
        self.vertices.len()
    }

    /// Adds a vertex to the graph.  Does not insert the vertex if a vertex with the same 
    /// label already exists in the target stage. 
    ///
    /// # Panics
    /// Panics if the target stage doesn't exist.
    pub fn add_vertex(&mut self, 
                      stage: usize, 
                      label: u128) {    
        self.vertices.get_mut(stage)
            .expect("Stage out of range")
            .entry(label)
            .or_insert_with(Vertex::new);
    }

    /// Adds an edge with a given length to the graph. The tail of the edge is at `stage` and
    // the head of the edge is at `stage+1`. If the endpoints don't exist, the 
    /// edge isn't added. 
    ///
    /// # Panics
    /// Panics if the target stage or the following stage doesn't exist.
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

    /// Add multiple edges to the graph.
    ///
    /// # Panics
    /// Panics when `edd_edge` does.
    pub fn add_edges(&mut self, edges: &IndexMap<(usize, u128, u128), f64>) {
        for (&(stage, from, to), &length) in edges {
            self.add_edge(stage, from, to, length);
        }
    }

    /// Adds multiple edges to the graph, and crates vertices in the first or last stage if they
    /// don't exist. Does not create vertices in other stages.
    ///
    /// Each try of `edges` is of the form `<(stage, label, label), length>`.
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

    /// Removes a vertex from the graph. All other vertices are updates such that successors and 
    /// predecessors are consistent. 
    pub fn remove_vertex(&mut self, 
                         stage: usize, 
                         label: u128) {
        {
            let (before, mid) = self.vertices.split_at_mut(stage);
            let (mid, after) = mid.split_at_mut(1);
            
            if let Some(vertex) = mid[0].get(&label) {
                if let Some(other_stage) = before.last_mut() {
                    for other in vertex.predecessors.keys() {
                        let other_vertex = other_stage.get_mut(&other).expect("Error 5");
                        other_vertex.successors.remove(&label);
                    }
                }

                if let Some(other_stage) = after.first_mut() {
                    for other in vertex.successors.keys() {
                        let other_vertex = other_stage.get_mut(&other).expect("Error 6");
                        other_vertex.predecessors.remove(&label);
                    }
                }
            }
        }

        self.vertices[stage].remove(&label);
    }

    /// Remove any edges that aren't part of a path from a vertex in stage `start` to
    /// a vertex in stage `stop`. 
    pub fn prune(&mut self, 
                 start: usize, 
                 stop: usize) {
        let mut pruned = true;

        while pruned {
            pruned = false;

            for stage in start..stop {
                let mut remove = Vec::new();

                for (&label, vertex) in self.get_stage(stage).unwrap() {
                    if (vertex.successors.is_empty() && stage != stop-1) ||
                       (vertex.predecessors.is_empty() && stage != start) {
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

    /// Reverses the graph, i.e. all edges are reversed, and the order of the stages are reversed.
    pub fn reverse(&mut self) {
        self.vertices.reverse();
        
        for stage in &mut self.vertices {
            for vertex in stage.values_mut() {
                mem::swap(&mut vertex.predecessors, &mut vertex.successors);
            }
        }       
    }

    /// Get a reference to a vertex. Returns None if the vertex doesn't exist.
    pub fn get_vertex(&self, 
                      stage: usize, 
                      label: u128) 
                      -> Option<&Vertex> {
        self.vertices.get(stage).expect("Stage out of range.").get(&label)
    }

    /// Get a reference to a stage of the graph. Returns None if the stage index is out of range.
    pub fn get_stage(&self, 
                     stage: usize) 
                     -> Option<&FnvHashMap<u128, Vertex>> {
        self.vertices.get(stage)
    }

    /// Check if a vertex exists. 
    pub fn has_vertex(&self, stage: usize, label: u128) -> bool {
        self.vertices.get(stage).expect("Stage out of range.").contains_key(&label)
    }

    /// Check if an edge exists.
    pub fn has_edge(&self, stage: usize, label_from: u128, label_to: u128) -> bool {
        match self.vertices.get(stage).expect("Stage out of range.").get(&label_from) {
            Some(vertex) => vertex.successors.contains_key(&label_to),
            None => false
        }
    }

    /// Returns the number of vertices in the graph.
    pub fn num_vertices(&self) -> usize {
        self.vertices.iter().fold(0, |sum, ref x| sum + x.len())
    }

    /// Returns the number of edges in the graph. 
    pub fn num_edges(&self) -> usize {
        self.vertices.iter()
                     .fold(0, 
                        |sum0, ref x| sum0 + x.values()
                                           .fold(0, 
                                                |sum1, ref y| sum1 + y.successors.len()))
    }
}