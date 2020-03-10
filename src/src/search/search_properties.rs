//! Main functions for searching for properties of a cipher.

use fnv::FnvHashSet;
use std::fs::{File, OpenOptions};
use std::io::{Write, BufReader, BufRead};

use std::time::Instant;

use crate::cipher::Cipher;
use crate::search::find_properties::parallel_find_properties;
use crate::search::graph::MultistageGraph;
use crate::search::graph_generate::generate_graph;
use crate::property::{Property, PropertyType};

/// Dumps a graph to file for plotting with python graph-tool.
fn dump_to_graph_tool(graph: &MultistageGraph,
                      path: &str) {
    let mut path = path.to_string();
    path.push_str(".graph");

    // Contents of previous files are overwritten
    let mut file = OpenOptions::new()
                               .write(true)
                               .truncate(true)
                               .create(true)
                               .open(path)
                               .expect("Could not open file.");

    let stages = graph.stages();

    for (tail, heads) in graph.forward_edges() {
        for (head, (edges, _)) in heads {
            for i in 0..stages {
                if (edges >> i) & 0x1 == 1 {
                    writeln!(file, "{},{},{},{}", i, tail, i+1, head)
                        .expect("Could not write to file.");
                }
            }
        }
    }
}

/// Dumps all vertices of a graph to the file <file_mask_out>.set.
fn dump_masks(graph: &MultistageGraph,
              file_mask_out: &str) {
    let mut file_set_path = file_mask_out.to_string();
    file_set_path.push_str(".set");

    // Collect edges and vertices
    let mut mask_set = FnvHashSet::<u128>::default();
    mask_set.extend(graph.forward_edges().keys());
    mask_set.extend(graph.backward_edges().keys());

    // Contents of previous files are overwritten
    let mut file = OpenOptions::new()
                               .write(true)
                               .truncate(true)
                               .create(true)
                               .open(file_set_path)
                               .expect("Could not open file.");

    for mask in &mask_set {
        writeln!(file, "{:032x}", mask).expect("Could not write to file.");
    }
}

/// Dumps a vector of properties to <file_mask_out>.app.
fn dump_results(properties: &[Property],
                file_mask_out: &str) {
    let mut file_set_path = file_mask_out.to_string();
    file_set_path.push_str(".app");

    // Contents of previous files are overwritten
    let mut file = OpenOptions::new()
                               .write(true)
                               .truncate(true)
                               .create(true)
                               .open(file_set_path)
                               .expect("Could not open file.");

    for property in properties {
        writeln!(file, "{:?},{},{}", property, property.trails, property.value.log2())
            .expect("Could not write to file.");
    }
}

/// Reads a file of allowed input and output values and stores them in a hash set.
/// The values in the files are assumed to be in hexadecimals, without the '0x' prefix, and
/// input/output masks should be separated by a comma.
fn read_allowed(file_mask_in: &str) -> FnvHashSet<(u128, u128)> {
    let file = File::open(file_mask_in).expect("Could not open file.");
    let mut allowed = FnvHashSet::default();

    for line in BufReader::new(file).lines() {
        let s = line.expect("Error reading file");
        let split: Vec<_> = s.split(',').collect();
        let alpha = u128::from_str_radix(split.get(0).expect("Could not read input data"), 16)
                        .expect("Could not parse integer. Is it in hexadecimals?");
        let beta  = u128::from_str_radix(split.get(1).expect("Could not read input data"), 16)
                        .expect("Could not parse integer. Is it in hexadecimals?");
        allowed.insert((alpha, beta));
    }

    allowed
}

/// Searches for properties over a given number of rounds for a given cipher.
///
/// # Parameters
/// * `cipher`: The cipher to investigate.
/// * `property_type`: The type of property to search for.
/// * `rounds`: The number of rounds to consider.
/// * `patterns`: The number of S-box patterns to generate. Relates to the number of properties generate per round.
/// * `file_mask_in`: Prefix of two files which restict the input/output values of the properties.
/// * `file_mask_out`: Prefix of two files to which results are dumped.
/// * `file_graph`: Prefix of a file to which raw graph data is dumped.
#[cfg_attr(clippy, allow(too_many_arguments))]
pub fn search_properties(cipher: &dyn Cipher,
                         property_type: PropertyType,
                         rounds: usize,
                         patterns: usize,
                         anchors: Option<usize>,
                         file_mask_in: Option<String>,
                         file_mask_out: Option<String>,
                         num_keep: Option<usize>,
                         file_graph: Option<String>) {
    println!("\tCipher: {}.", cipher.name());
    match property_type {
        PropertyType::Linear       => println!("\tProperty: Linear"),
        PropertyType::Differential => println!("\tProperty: Differential")
    }
    println!("\tRounds: {}.", rounds);
    println!("\tS-box patterns: {}", patterns);
    match anchors {
        Some(a) => println!("\tMaximum anchors: 2^{}", a),
        None    => println!("\tMaximum anchors: 2^17"),
    }
    println!();


    let start = Instant::now();
    // Restrict the number of results printed
    let keep = match num_keep {
        Some(x) => x,
        None => 20,
    };

    let allowed = match file_mask_in {
        Some(path) => {
            read_allowed(&path)
        },
        None => {
            FnvHashSet::default()
        }
    };

    println!("\n--------------------------------------- GENERATING GRAPH ---------------------------------------\n");

    let graph = generate_graph(cipher, property_type, rounds, patterns,
                               anchors, &allowed);

    if let Some(path) = file_graph {
        dump_to_graph_tool(&graph, &path);
    }

    if let Some(path) = &file_mask_out {
        dump_masks(&graph, path);
    }

    println!("\n------------------------------------- FINDING PROPERTIES ---------------------------------------\n");

    let (result, min_value, paths) = parallel_find_properties(cipher, &graph, property_type,
                                                              &allowed, keep);

    println!("\n------------------------------------------ RESULTS ---------------------------------------------\n");

    println!("Search finished. [{:?} s]", start.elapsed());

    if !result.is_empty() {
        println!("Smallest value: {}", min_value.log2());
        println!("Largest value:  {}\n", result[0].value.log2());
        println!("Total number of trails:  {}", paths);
    }

    for &property in &result {
        if property.input == 0 && property.output == 0 {
            continue
        }

        print!("Approximation: {:?} ", property);
        println!("[{}, {}]", property.trails, property.value.log2());
    }

    if num_keep.is_some() && file_mask_out.is_some() {
        dump_results(&result, &file_mask_out.unwrap());
    }
}
