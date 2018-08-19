//! Extra functions for handling Prince-like ciphers.

use fnv::FnvHashSet;
use indexmap::IndexMap;

use cipher::*;
use search::graph::MultistageGraph;

/// Special graph pruning for Prince-like ciphers. The last layer is also pruned with regards to the
/// reflection function. 
pub fn prince_pruning(cipher: &dyn Cipher,
                      graph: &mut MultistageGraph) {
    let mut pruned = true;

    while pruned {
        pruned = false;

        let stages = graph.stages();
        let reflections: FnvHashSet<_>;
        let remove: FnvHashSet<_>;
        {
            reflections = graph.get_stage(stages-1).unwrap()
                               .keys()
                               .map(|&x| cipher.reflection_layer(x as u128))
                               .collect();
            remove = graph.get_stage(stages-1).unwrap()
                          .keys()
                          .filter(|&x| !reflections.contains(&(*x as u128)))
                          .cloned()
                          .collect();
        }

        for &label in &remove {
            graph.remove_vertex(stages-1, label);
            pruned = true;
        }

        graph.prune(0, stages);
    }
}

/// Creates a Prince-like graph from a normal SPN graph, i.e. it reflects the graph and connects 
/// the two halves through a reflection layer.
pub fn prince_modification(cipher: &dyn Cipher, 
                           graph_first: &mut MultistageGraph)
                           -> MultistageGraph {
    let stages = graph_first.stages();
    
    // Get other half of the graph
    let mut graph_second = graph_first.clone();
    graph_second.reverse();

    // Stitch the two halfs together 
    let mut graph = MultistageGraph::new(stages*2);
    graph.vertices.splice(0..stages, graph_first.vertices.iter().cloned());
    graph.vertices.splice(stages..2*stages, graph_second.vertices.iter().cloned());

    // Add reflection edges
    let mut edges = IndexMap::new();

    for &input in graph.get_stage(stages-1).unwrap().keys() {
        edges.insert((stages-1, input, cipher.reflection_layer(input as u128)), 1.0);
    }

    graph.add_edges(&edges);
    graph.prune(0, 2*stages);
    graph
}