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

#[derive(Clone)]
pub struct Vertex {
    // pub stage: usize,
    pub predecessors: HashMap<usize, f64>,
    pub successors: HashMap<usize, f64>,
    /*paths: Vec<Path>,
    candidates: BinaryHeap<Candidate>*/
}

impl Vertex {
    fn new(stage: usize) -> Vertex {
        Vertex {
            // stage: stage,
            predecessors: HashMap::new(),
            successors: HashMap::new(),
            /*paths: Vec::new(),
            candidates: BinaryHeap::new()*/
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
    vertices: Vec<Vec<Vertex>>,
    // pub current_path: usize
}

impl MultistageGraph {
    pub fn new(stages: usize) -> MultistageGraph {
        let vertices = vec![vec![]; stages];

        MultistageGraph {
            vertices: vertices,
            // current_path: 0,
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

    pub fn add_vertex(&mut self, stage: usize) {
        let vertex = Vertex::new(stage);

        if stage < self.vertices.len() {
            self.vertices[stage].push(vertex);
        }
    }

    pub fn add_edge(&mut self, stage: usize, from: usize, to: usize, length: f64) {
        if stage+1 < self.vertices.len() && 
           from < self.vertices[stage].len() && 
           to < self.vertices[stage+1].len() {
            // Check if edge already exists
            if !self.vertices[stage][from].successors.contains_key(&to) {
                self.vertices[stage][from].add_successor(to, length);
                self.vertices[stage+1][to].add_predecessor(from, length);
            }
        }
    }

    pub fn remove_edge(&mut self, stage: usize, from: usize, to: usize) {
        if stage+1 < self.vertices.len() && 
           from < self.vertices[stage].len() && 
           to < self.vertices[stage+1].len() {
            self.vertices[stage][from].remove_successor(to);
            self.vertices[stage+1][to].remove_predecessor(from);
        }   
    }

    pub fn get_vertex(&self, stage: usize, index: usize) -> Option<&Vertex> {
        if stage < self.vertices.len() && index < self.vertices[stage].len() {
            Some(&self.vertices[stage][index])
        } else {
            None
        }
    }

    /*pub fn get_vertex_mut(&mut self, stage: usize, index: usize) -> Option<&mut Vertex> {
        if stage < self.vertices.len() && index < self.vertices[stage].len() {
            Some(&mut self.vertices[stage][index])
        } else {
            None
        }
    }*/

    pub fn num_vertices(&self) -> usize {
        self.vertices.iter().fold(0, |sum, ref x| sum + x.len())
    }

    pub fn num_edges(&self) -> usize {
        self.vertices.iter()
                     .fold(0, 
                        |sum0, ref x| sum0 + x.iter()
                                           .fold(0, 
                                                |sum1, ref y| sum1 + y.successors.len()))
    }

    pub fn print(&self) {
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
    }
    
    /*
    fn get_path(&self, start_stage: usize, 
        start_vertex: usize, start_index: usize) -> Option<(f64, Vec<(usize, usize)>)> {
        let mut vertex_ref = &self.vertices[start_stage][start_vertex];
        
        if start_index > vertex_ref.paths.len() - 1 {
            return None;
        }

        let mut path = vec![(start_stage, start_vertex)];
        let length = vertex_ref.paths[start_index].length;
        let mut current_index = start_index;
        let mut current_stage = start_stage;

        loop {
            current_stage = current_stage.wrapping_sub(1);
            let current_vertex = vertex_ref.paths[current_index].previous;
            current_index = vertex_ref.paths[current_index].previous_index;

            if current_vertex.is_some() {
                vertex_ref = &self.vertices[current_stage][current_vertex.expect("Error 0")];
                path.push((current_stage, current_vertex.expect("Error 1")));
            } else {
                break;
            }
        }

        path.reverse();

        if length.is_infinite() {
            None
        } else {
            Some((length, path))
        }
    }

    fn find_shortest_paths(&mut self) {
        for vertex in self.vertices[0].iter_mut() {
            vertex.paths.push(Path::new(0.0, None, 0));
        }

        for s in 1..self.vertices.len() {
            for v in 0..self.vertices[s].len() {
                let mut min_length = f64::INFINITY;
                let mut min_index = None;
                
                {
                    let vertex = &self.vertices[s][v];

                    for (&predecessor_index, &edge_length) in &vertex.predecessors {
                        let predecessor_length = self.vertices[s-1][predecessor_index].paths[0].length;
                        let length = if predecessor_length.is_infinite() {
                            predecessor_length
                        } else {
                            predecessor_length + edge_length
                        };

                        if length < min_length {
                            min_length = length;
                            min_index = Some(predecessor_index);
                        }
                    }
                }

                let vertex = &mut self.vertices[s][v];
                vertex.paths.push(Path::new(min_length, min_index, 0));
            }
        }
    }

    fn generate_next_path(& mut self, stage: usize, vertex: usize, index: usize) {
        // B.1
        if index == 1 && stage > 0 {
            let mut new_candidates = BinaryHeap::new();
            
            {
                let vertex_ref = &self.vertices[stage][vertex];
                match vertex_ref.paths[0].previous {
                    Some(best_previous) => {
                        for (&idx, &len) in &vertex_ref.predecessors {
                            if idx == best_previous {
                                continue;
                            }

                            let previous_len = self.vertices[stage-1][idx].paths[0].length;
                            if !previous_len.is_infinite() {
                                let candidate = Candidate::new(previous_len + len, idx, 0);
                                new_candidates.push(candidate);
                            };
                        }
                    },
                    None => {}
                }
            }

            self.vertices[stage][vertex].candidates = new_candidates;
        }

        // Not B.2
        if !(stage == 0 && index == 1) {
            // B.3
            match self.vertices[stage][vertex].paths[index-1].previous {
                Some(previous_vertex) => {
                    let previous_index  = self.vertices[stage][vertex].paths[index-1].previous_index;

                    // B.4
                    if self.vertices[stage-1][previous_vertex].paths.len()-1 < previous_index+1 {
                        self.generate_next_path(stage-1, previous_vertex, previous_index+1);
                    }

                    // B.5
                    // We have to check if a new path was added in the recursive call
                    if !(self.vertices[stage-1][previous_vertex].paths.len() <= previous_index+1) {
                        let previous_length = self.vertices[stage-1][previous_vertex].paths[previous_index+1].length;
                        let new_length = *self.vertices[stage][vertex].predecessors.get(&previous_vertex).expect("Error 4");
                        let new_candidate = Candidate::new(previous_length + new_length, previous_vertex, previous_index+1);
                        self.vertices[stage][vertex].candidates.push(new_candidate);
                    }
                },
                None => {}
            }
        }

        // B.6
        match self.vertices[stage][vertex].candidates.pop() {
            Some(candidate) => {
                let new_path = Path::from_candidate(&candidate);
                self.vertices[stage][vertex].paths.push(new_path);
            },
            None => {}
        }
    }

    pub fn get_next_path(& mut self, stage: usize, vertex: usize) -> Option<(f64, Vec<(usize, usize)>)> {
        let current_path = self.current_path;

        if current_path == 0 {
            self.find_shortest_paths();
        } else {
            self.generate_next_path(stage, vertex, current_path);
        }

        self.current_path += 1;
        self.get_path(stage, vertex, current_path)
    }
    */
}