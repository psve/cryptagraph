use fnv::FnvHashMap;

fn hw(x: u64) -> u64 {
    let y = [( x & 0xff) as u8,
             ((x >>  8) & 0xff) as u8,
             ((x >> 16) & 0xff) as u8,
             ((x >> 24) & 0xff) as u8,
             ((x >> 32) & 0xff) as u8,
             ((x >> 40) & 0xff) as u8,
             ((x >> 48) & 0xff) as u8,
             ((x >> 56) & 0xff) as u8];

    hamming::weight(&y[..])
}

#[derive(Clone, Debug)]
pub struct MultistageGraph {
    forward: FnvHashMap<u128, FnvHashMap<u128,(u64, f64)>>,
    backward: FnvHashMap<u128, FnvHashMap<u128,(u64, f64)>>,
    stages: usize,
}

impl MultistageGraph {
    pub fn new(stages: usize) -> MultistageGraph {
        MultistageGraph {
            forward: FnvHashMap::default(),
            backward: FnvHashMap::default(),
            stages
        }
    }

    pub fn forward_edges(&self) -> &FnvHashMap<u128, FnvHashMap<u128,(u64, f64)>> {
        &self.forward
    }

    fn forward_edges_mut(&mut self) -> &mut FnvHashMap<u128, FnvHashMap<u128,(u64, f64)>> {
        &mut self.forward
    }

    pub fn backward_edges(&self) -> &FnvHashMap<u128, FnvHashMap<u128,(u64, f64)>> {
        &self.backward
    }

    fn backward_edges_mut(&mut self) -> &mut FnvHashMap<u128, FnvHashMap<u128,(u64, f64)>> {
        &mut self.backward
    }

    pub fn stages(&self) -> usize {
        self.stages
    }

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

    pub fn insert_stage_after(&mut self) {
        self.stages += 1;
    }

    fn add_edge(&mut self, tail: u128, head: u128, stage: usize, length: f64) {
        if stage >= self.stages {
            return
        }

        let entry_tail = self.forward.entry(tail).or_insert_with(FnvHashMap::default);
        let entry_head = entry_tail.entry(head).or_insert((0, length));

        if entry_head.1 != length {
            panic!("Lengths are incompatible.");
        }

        entry_head.0 |= 1 << stage;
        
        let entry_head = self.backward.entry(head).or_insert_with(FnvHashMap::default);
        let entry_tail = entry_head.entry(tail).or_insert((0, length));

        if entry_tail.1 != length {
            panic!("Lengths are incompatible.");
        }

        entry_tail.0 |= 1 << stage;
    }

    pub fn add_edges(&mut self, tail: u128, head: u128, stages: u64, length: f64) {
        if stages == 0 || stages >= (1 << self.stages) {
            return
        }

        let entry_tail = self.forward.entry(tail).or_insert_with(FnvHashMap::default);
        let entry_head = entry_tail.entry(head).or_insert((0, length));

        if entry_head.1 != length {
            panic!("Lengths are incompatible.");
        }

        entry_head.0 |= stages;
        
        let entry_head = self.backward.entry(head).or_insert_with(FnvHashMap::default);
        let entry_tail = entry_head.entry(tail).or_insert((0, length));

        if entry_tail.1 != length {
            panic!("Lengths are incompatible.");
        }

        entry_tail.0 |= stages;
    }

    fn remove_edge(&mut self, tail: u128, head: u128, stage: usize) {
        if stage >= self.stages {
            return
        }

        let empty_edge;

        let entry_tail_f = match self.forward.get_mut(&tail) {
            Some(entry_tail_f) => {
                match entry_tail_f.get_mut(&head) {
                    Some(entry_head_f) => {
                        entry_head_f.0 &= !(1 << stage);

                        empty_edge = entry_head_f.0 == 0;
                    },
                    None => return,
                };

                entry_tail_f
            },
            None => return,
        };

        let entry_head_b = match self.backward.get_mut(&head) {
            Some(entry_head_b) => {
                match entry_head_b.get_mut(&tail) {
                    Some(entry_tail_b) => {
                        entry_tail_b.0 &= !(1 << stage);
                    },
                    None => return,
                };

                entry_head_b
            },
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

    fn remove_edges(&mut self, tail: u128, head: u128, stages: u64) {
        if stages >= (1 << self.stages) {
            return
        }

        let empty_edge;

        let entry_tail_f = match self.forward.get_mut(&tail) {
            Some(entry_tail_f) => {
                match entry_tail_f.get_mut(&head) {
                    Some(entry_head_f) => {
                        entry_head_f.0 &= !stages;

                        empty_edge = entry_head_f.0 == 0;
                    },
                    None => return,
                };

                entry_tail_f
            },
            None => return,
        };

        let entry_head_b = match self.backward.get_mut(&head) {
            Some(entry_head_b) => {
                match entry_head_b.get_mut(&tail) {
                    Some(entry_tail_b) => {
                        entry_tail_b.0 &= !stages;
                    },
                    None => return,
                };

                entry_head_b
            },
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

    pub fn has_vertex(&self, v: u128, stage: usize) -> bool {
        if let Some(heads) = self.forward.get(&v) {
            for (stages, _) in heads.values() {
                if ((stages >> stage) & 0x1) == 1 {
                    return true
                }
            }
        }

        if stage > 0 {
            if let Some(tails) = self.backward.get(&v) {
                for (stages, _) in tails.values() {
                    if ((stages >> (stage-1)) & 0x1) == 1 {
                        return true
                    }
                }  
            }  
        } 

        false
    }


    pub fn get_edge(&self, tail: u128, head: u128) -> u64 {
        if let Some(heads) = self.forward.get(&tail) {
            if let Some(&(edge, _)) = heads.get(&head) {
                return edge;
            }
        }

        0
    }

    pub fn has_edge(&self, tail: u128, head: u128) -> bool {
        if let Some(heads) = self.forward.get(&tail) {
            if heads.contains_key(&head) {
                return true
            } else {
                return false
            }
        }

        false
    }

    fn has_predecessors(&self, v: u128) -> u64 {
        if let Some(entry) = self.backward.get(&v) {
            return entry.values().fold(0, |sum, x| sum | x.0) << 1
        }

        0
    }

    fn has_successors(&self, v: u128) -> u64 {
        if let Some(entry) = self.forward.get(&v) {
            return entry.values().fold(0, |sum, x| sum | x.0) >> 1
        }

        0
    }

    pub fn prune(&mut self, start: usize, stop: usize) {
        let mask = !0 & !((1 << start) - 1) & ((1 << stop) - 1);

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
                    let targets = (edges.0 & no_successors) & !(1 << (stop-1));
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

    pub fn num_edges(&self) -> usize {
        self.forward.values().fold(0, |e, v| 
            e + v.values().fold(0, |e, &v| e + hw(v.0))
        ) as usize
    }

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
                    if ((stages >> (stage-1)) & 0x1) == 1 {
                        count += 1;
                        break;
                    }
                }
            }
        }

        count
    }

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

                    if entry_head.1 != length {
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
                let entry_head = self.backward.get_mut(&head).expect("This shouldn't happen.");

                for (tail, (stages, length)) in tails.drain() {
                    let entry_tail = entry_head.entry(tail).or_insert((0, length));

                    if entry_tail.1 != length {
                        panic!("Lengths are incompatible.");
                    }

                    entry_tail.0 |= stages;   
                }
            }
        }
    }
}