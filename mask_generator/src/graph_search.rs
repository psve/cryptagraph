/*
use std::f64;
use std::cmp::Ordering;
use std::collections::{HashMap, BinaryHeap};
*/
use std::collections::HashMap;

/*************************************************************************************************/
/*
#[derive(Clone, Debug)]
struct Path {
    length: f64,
    previous: Option<usize>,
    previous_index: usize
}

impl Path {
    fn new(length: f64, previous: Option<usize>, previous_index: usize) -> Path {
        Path {
            length: length,
            previous: previous,
            previous_index: previous_index
        }
    }

    fn from_candidate(candidate: &Candidate) -> Path {
        Path {
            length: candidate.length,
            previous: Some(candidate.previous),
            previous_index: candidate.previous_index
        }
    }
}
*/
/*************************************************************************************************/
/*
#[derive(Clone, Debug)]
struct Candidate {
    length: f64,
    previous: usize,
    previous_index: usize
}

impl Candidate {
    fn new(length: f64, previous: usize, previous_index: usize) -> Candidate {
        Candidate {
            length: length,
            previous: previous,
            previous_index: previous_index
        }
    }
}

impl Ord for Candidate {
    fn cmp(&self, other: &Candidate) -> Ordering {
        other.length.partial_cmp(&self.length).expect("Float comparison error")
    }
}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Candidate) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Candidate {
    fn eq(&self, other: &Candidate) -> bool {
        self.length == other.length
    }
}

impl Eq for Candidate { }
*/
/*************************************************************************************************/

#[derive(Clone, Debug)]
pub struct Vertex {
    pub predecessors: HashMap<usize, f64>,
    pub successors: HashMap<usize, f64>,
}

impl Vertex {
    fn new(stage: usize) -> Vertex {
        Vertex {
            predecessors: HashMap::new(),
            successors: HashMap::new(),
        }
    }

    fn add_predecessor(&mut self, predecessor: usize, length: f64) {
        self.predecessors.insert(predecessor, length);
    }

    fn add_successor(&mut self, successor: usize, length: f64) {
        self.successors.insert(successor, length);
    }

    fn remove_predecessor(&mut self, predecessor: usize) {
        self.predecessors.remove(&predecessor);
    }

    fn remove_successor(&mut self, successor: usize) {
        self.successors.remove(&successor);
    }
}

/*************************************************************************************************/

#[derive(Clone)]
pub struct MultistageGraph {
    vertices: Vec<HashMap<usize, Vertex>>,
}

impl MultistageGraph {
    pub fn new(stages: usize) -> MultistageGraph {
        let vertices = vec![HashMap::new(); stages];

        MultistageGraph {
            vertices: vertices,
        }
    }

    pub fn stages(&self) -> usize {
        self.vertices.len()
    }

    pub fn stage_len(&self, stage: usize) -> usize {
        if stage < self.vertices.len() {
            self.vertices[stage].len()
        } else {
            0
        }
    }

    pub fn add_vertex(&mut self, stage: usize, label: usize) {
        let vertex = Vertex::new(stage);

        if stage < self.vertices.len() {
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

    pub fn remove_edge(&mut self, stage: usize, from: usize, to: usize) {
        if stage+1 < self.vertices.len() && 
           self.vertices[stage].contains_key(&from) &&
           self.vertices[stage+1].contains_key(&to) {
            {
                let from_vertex = self.vertices[stage].get_mut(&from).expect("Error 3");
                from_vertex.remove_successor(to);
            }
            {
                let to_vertex = self.vertices[stage+1].get_mut(&to).expect("Error 4");
                to_vertex.remove_predecessor(from);
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

    pub fn get_stage(&self, stage: usize) -> Option<&HashMap<usize, Vertex>> {
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

    /*pub fn print(&self) {
        for (i, stage) in self.vertices.iter().enumerate() {
            println!("Stage {}:", i);

            for (j, vertex) in stage.iter().enumerate() {
                println!("  {} ", j);

                for (successor, length) in &vertex.successors {
                    println!("    --{}--> {}", length, successor);
                }

                println!("");
            }
        }
    }*/
}