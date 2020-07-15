//! Types for representing a multistage graph.

use fnv::FnvHashMap;

/// Computes the hamming weight of x.
fn hw(x: u64) -> u64 {
    x.count_ones() as u64
}

/// A structure describing a directed multistage graph.
#[derive(Clone, Debug)]
pub struct MultistageGraph {
    forward: FnvHashMap<u128, FnvHashMap<u128, (u64, f64)>>,
    backward: FnvHashMap<u128, FnvHashMap<u128, (u64, f64)>>,
    stages: usize,
}

impl MultistageGraph {
    /// Create a new empty multistage graph with a fixed number of stages.
    pub fn new(stages: usize) -> MultistageGraph {
        MultistageGraph {
            forward: FnvHashMap::default(),
            backward: FnvHashMap::default(),
            stages,
        }
    }

    /// Get a map of edges indexed tail to head.
    pub fn forward_edges(&self) -> &FnvHashMap<u128, FnvHashMap<u128, (u64, f64)>> {
        &self.forward
    }

    /// Get a mutable map of edges indexed tail to head.
    fn forward_edges_mut(&mut self) -> &mut FnvHashMap<u128, FnvHashMap<u128, (u64, f64)>> {
        &mut self.forward
    }

    /// Get a map of edges indexed head to tail.
    pub fn backward_edges(&self) -> &FnvHashMap<u128, FnvHashMap<u128, (u64, f64)>> {
        &self.backward
    }

    /// Get a mutable map of edges indexed head to tail.
    fn backward_edges_mut(&mut self) -> &mut FnvHashMap<u128, FnvHashMap<u128, (u64, f64)>> {
        &mut self.backward
    }

    /// Get the number of stages.
    pub fn stages(&self) -> usize {
        self.stages
    }

    /// Insert a new stage at the start of the graph.
    pub fn insert_stage_before(&mut self) {
        self.stages += 1;

        for edges in self.forward.values_mut() {
            for e in edges.values_mut() {
                *e = (e.0 << 1, e.1);
            }
        }

        for edges in self.backward.values_mut() {
            for e in edges.values_mut() {
                *e = (e.0 << 1, e.1);
            }
        }
    }

    /// Insert a new stage at the end of the graph.
    pub fn insert_stage_after(&mut self) {
        self.stages += 1;
    }

    /// Add an edge to one or more stages of the graph.
    ///
    /// # Panics
    /// Panics if the graph already has an edge of this type but with a different length.
    pub fn add_edges(&mut self, tail: u128, head: u128, stages: u64, length: f64) {
        if stages == 0 || stages >= (1 << self.stages) {
            return;
        }

        let entry_tail = self.forward.entry(tail).or_insert_with(FnvHashMap::default);
        let entry_head = entry_tail.entry(head).or_insert((0, length));

        if (entry_head.1 - length).abs() > std::f64::EPSILON {
            panic!("Lengths are incompatible.");
        }

        entry_head.0 |= stages;

        let entry_head = self
            .backward
            .entry(head)
            .or_insert_with(FnvHashMap::default);
        let entry_tail = entry_head.entry(tail).or_insert((0, length));

        if (entry_tail.1 - length).abs() > std::f64::EPSILON {
            panic!("Lengths are incompatible.");
        }

        entry_tail.0 |= stages;
    }

    /// Remove an edge from one or more stages of the graph.
    pub fn remove_edges(&mut self, tail: u128, head: u128, stages: u64) {
        if stages >= (1 << self.stages) {
            return;
        }

        let empty_edge;

        let entry_tail_f = match self.forward.get_mut(&tail) {
            Some(entry_tail_f) => {
                match entry_tail_f.get_mut(&head) {
                    Some(entry_head_f) => {
                        entry_head_f.0 &= !stages;

                        empty_edge = entry_head_f.0 == 0;
                    }
                    None => return,
                };

                entry_tail_f
            }
            None => return,
        };

        let entry_head_b = match self.backward.get_mut(&head) {
            Some(entry_head_b) => {
                match entry_head_b.get_mut(&tail) {
                    Some(entry_tail_b) => {
                        entry_tail_b.0 &= !stages;
                    }
                    None => return,
                };

                entry_head_b
            }
            None => return,
        };

        if empty_edge {
            entry_tail_f.remove(&head);
            entry_head_b.remove(&tail);
        }

        if entry_tail_f.is_empty() {
            self.forward.remove(&tail);
        }

        if entry_head_b.is_empty() {
            self.backward.remove(&head);
        }
    }

    /// Check if there is a vertex v with an outgoing edge in the given stage.
    pub fn has_vertex_outgoing(&self, v: u128, stage: usize) -> bool {
        if stage < self.stages {
            if let Some(heads) = self.forward.get(&v) {
                for (stages, _) in heads.values() {
                    if ((stages >> stage) & 0x1) == 1 {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if there is a vertex v with an incoming edge in the given stage.
    pub fn has_vertex_incoming(&self, v: u128, stage: usize) -> bool {
        if stage > 0 {
            if let Some(tails) = self.backward.get(&v) {
                for (stages, _) in tails.values() {
                    if ((stages >> (stage - 1)) & 0x1) == 1 {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if the vertex v exists in the given stage.
    pub fn has_vertex(&self, v: u128, stage: usize) -> bool {
        self.has_vertex_outgoing(v, stage) || self.has_vertex_incoming(v, stage)
    }

    /// Returns the binary representation of the stages where the edge exists
    pub fn get_edge(&self, tail: u128, head: u128) -> u64 {
        if let Some(heads) = self.forward.get(&tail) {
            if let Some(&(edge, _)) = heads.get(&head) {
                return edge;
            }
        }

        0
    }

    /// Returns all vertices with outgoing edges in the given stage.
    pub fn get_vertices_outgoing(&self, stage: usize) -> Vec<u128> {
        let mut vertices = Vec::new();

        for (tail, heads) in self.forward_edges() {
            for &(stages, _) in heads.values() {
                if ((stages >> stage) & 0x1) == 1 {
                    vertices.push(*tail);
                    break;
                }
            }
        }

        vertices
    }

    /// Returns all vertices with incoming edges in the given stage.
    pub fn get_vertices_incoming(&self, stage: usize) -> Vec<u128> {
        if stage < 1 {
            return Vec::new();
        }

        let mut vertices = Vec::new();

        for (head, tails) in self.backward_edges() {
            for &(stages, _) in tails.values() {
                if ((stages >> (stage - 1)) & 0x1) == 1 {
                    vertices.push(*head);
                    break;
                }
            }
        }

        vertices
    }

    /// Returns the binary representation of v's predecessors in each stage.
    fn has_predecessors(&self, v: u128) -> u64 {
        if let Some(entry) = self.backward.get(&v) {
            return entry.values().fold(0, |sum, x| sum | x.0) << 1;
        }

        0
    }

    /// Returns the binary representation of v's successors in each stage.
    fn has_successors(&self, v: u128) -> u64 {
        if let Some(entry) = self.forward.get(&v) {
            return entry.values().fold(0, |sum, x| sum | x.0) >> 1;
        }

        0
    }

    /// Remove any edges that aren't part of a path from a vertex in stage `start` to
    /// a vertex in stage `stop`.
    pub fn prune(&mut self, start: usize, stop: usize) {
        let mask = !((1 << start) - 1) & ((1 << stop) - 1);

        loop {
            let mut remove = Vec::new();

            for (&tail, heads) in &self.forward {
                let no_predecessors = !self.has_predecessors(tail);

                for (&head, edges) in heads {
                    let targets = (edges.0 & no_predecessors) & !(1 << start);
                    let targets = targets & mask;

                    if targets != 0 {
                        remove.push((tail, head, targets));
                    }
                }
            }

            let mut pruned = !remove.is_empty();

            for &(tail, head, stages) in &remove {
                self.remove_edges(tail, head, stages);
            }

            remove.clear();

            for (&head, tails) in &self.backward {
                let no_successors = !self.has_successors(head);

                for (&tail, edges) in tails {
                    let targets = (edges.0 & no_successors) & !(1 << (stop - 1));
                    let targets = targets & mask;

                    if targets != 0 {
                        remove.push((tail, head, targets));
                    }
                }
            }

            pruned |= !remove.is_empty();

            for &(tail, head, stages) in &remove {
                self.remove_edges(tail, head, stages);
            }

            if !pruned {
                break;
            }
        }
    }

    /// Returns the number of edges in the graph.
    pub fn num_edges(&self) -> usize {
        self.forward
            .values()
            .fold(0, |e, v| e + v.values().fold(0, |e, &v| e + hw(v.0))) as usize
    }

    /// Returns the number of vertices in a given stage.
    pub fn num_vertices(&self, stage: usize) -> usize {
        let mut count = 0;

        if stage < self.stages {
            for heads in self.forward.values() {
                for (stages, _) in heads.values() {
                    if ((stages >> stage) & 0x1) == 1 {
                        count += 1;
                        break;
                    }
                }
            }
        } else if stage == self.stages {
            for tails in self.backward.values() {
                for (stages, _) in tails.values() {
                    if ((stages >> (stage - 1)) & 0x1) == 1 {
                        count += 1;
                        break;
                    }
                }
            }
        }

        count
    }

    /// Adds all edges of another graph to this graph, leaving the other graph empty.
    ///
    /// # Panics
    /// Panics if the two graphs have a different number of stages.
    pub fn union(&mut self, other: &mut MultistageGraph) {
        if self.stages() != other.stages() {
            panic!("Cannot take union of graphs with different number of stages.")
        }

        for (tail, mut heads) in other.forward_edges_mut().drain() {
            if !self.forward.contains_key(&tail) {
                self.forward.insert(tail, heads.clone());
            } else {
                let entry_tail = self.forward.get_mut(&tail).expect("This shouldn't happen.");

                for (head, (stages, length)) in heads.drain() {
                    let entry_head = entry_tail.entry(head).or_insert((0, length));

                    if (entry_head.1 - length).abs() > std::f64::EPSILON {
                        panic!("Lengths are incompatible.");
                    }

                    entry_head.0 |= stages;
                }
            }
        }

        for (head, mut tails) in other.backward_edges_mut().drain() {
            if !self.backward.contains_key(&head) {
                self.backward.insert(head, tails.clone());
            } else {
                let entry_head = self
                    .backward
                    .get_mut(&head)
                    .expect("This shouldn't happen.");

                for (tail, (stages, length)) in tails.drain() {
                    let entry_tail = entry_head.entry(tail).or_insert((0, length));

                    if (entry_tail.1 - length).abs() > std::f64::EPSILON {
                        panic!("Lengths are incompatible.");
                    }

                    entry_tail.0 |= stages;
                }
            }
        }
    }
}
