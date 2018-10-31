//! Extra functions for handling Prince-like ciphers.

use fnv::FnvHashSet;

use crate::cipher::*;
use crate::search::graph::MultistageGraph;

/// Special graph pruning for Prince-like ciphers. The last layer is also pruned with regards to the
/// reflection function. 
pub fn prince_pruning_new(cipher: &dyn Cipher,
                      graph: &mut MultistageGraph) {
    let num_stages = graph.stages();
    let mut pruned = true;

    while pruned {
        pruned = false;

        let reflections: FnvHashSet<_> = graph.get_vertices_incoming(num_stages).iter()
                                              .map(|&x| cipher.reflection_layer(x as u128))
                                              .collect();
        let mut remove = Vec::new();

        for (&tail, heads) in graph.forward_edges() {
            for (&head, (stages, _)) in heads {
                if ((stages >> (num_stages-1)) & 0x1) == 1 && !reflections.contains(&head) {
                    remove.push((tail, head, 1 << (num_stages-1)));
                }
            }
        }

        for (tail, head, stages) in remove {
            graph.remove_edges(tail, head, stages);
            pruned = true;
        }        

        graph.prune(0, num_stages);
    }
}