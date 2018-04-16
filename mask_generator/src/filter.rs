use std::collections::HashSet;

pub fn compress(x: u64, block_size: usize) -> u64 {
    let blocks = 64 / block_size;
    let mask = (1 << block_size) - 1;
    let mut out = 0;

    for i in 0..blocks {
        let block_value = (x >> (i*block_size)) & mask;

        if block_value != 0 {
            out ^= 1 << i;
        }
    }

    out
}

#[derive(Clone)]
pub struct Filter {
    layers: Vec<HashSet<u64>>,
    start_block: usize,
}

impl Filter {
    pub fn new(start_block: usize) -> Filter {
        let layers = vec![];

        Filter {
            layers: layers,
            start_block: start_block
        }
    }

    pub fn add_layer(&mut self) {
        if self.layers.len() >= 6 {
            panic!("A filter can have at most 6 layers.");
        }

        self.layers.push(HashSet::new());
    }

    pub fn check(&self, x: u64) -> bool {
        for (i, layer) in self.layers.iter().enumerate() {
            let block_size = self.start_block >> (i+1);

            if !layer.contains(&compress(x, block_size)) {
                return false;
            }
        }

        true
    }

    /*fn check_previous(&self, x: u64) -> bool {
        let num_layers = self.layers.len();

        for (i, layer) in self.layers.iter().take(num_layers-1).enumerate() {
            let block_size = self.start_block >> (i+1);

            if !layer.contains(&compress(x, block_size)) {
                return false;
            }
        }

        true
    }

    pub fn add_value(&mut self, x: u64) {
        if self.check_previous(x) {
            let block_size = self.start_block >> self.layers.len();
            let num_layers = self.layers.len();
            self.layers[num_layers-1].insert(compress(x, block_size));
        }
    }*/

    pub fn add_plain_value(&mut self, x: u64) {
        let num_layers = self.layers.len();
        self.layers[num_layers-1].insert(x);
    }

    pub fn block_size(&self) -> usize {
        self.start_block >> self.layers.len()
    }
}
