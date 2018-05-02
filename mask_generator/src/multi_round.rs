use fnv::FnvHashSet;
use std::fs::{File, OpenOptions};
use std::io::{Write, BufReader, BufRead};
use time;

use cipher::Cipher;
use find_properties::parallel_find_properties;
use graph::MultistageGraph;
use graph_generate::generate_graph;
use property::PropertyType;

/**
Dumps a graph to file for plotting with python graph-tool. 

graph       The input graph to dump.
path        Prefix of the path of the output file. Gets appended with ".graph".
*/
fn dump_to_graph_tool(graph: &MultistageGraph,
                      path: &String) {
    let mut path = path.clone();
    path.push_str(".graph");

    // Contents of previous files are overwritten
    let mut file = OpenOptions::new()
                               .write(true)
                               .truncate(true)
                               .create(true)
                               .open(path)
                               .expect("Could not open file.");

    let stages = graph.stages();

    for i in 0..stages {
        for (j, _) in graph.get_stage(i).unwrap() {
            write!(file, "{},{}\n", i, j).expect("Could not write to file.");
        }
    }        

    for i in 0..stages-1 {
        for (j, vertex_ref) in graph.get_stage(i).unwrap() {
            for (k, _) in &vertex_ref.successors {
                write!(file, "{},{},{},{}\n", i, j, i+1, k).expect("Could not write to file.");       
            }
        }
    }   
}

/**
Dumps all edges of a graph to the file <file_mask_out>.app and all vertices to the file
<file_mask_out>.set. 

graph           The input graph to dump.
file_mask_out   Prefix of the path of the two files created.
*/
fn dump_masks(graph: &MultistageGraph, 
              file_mask_out: String) {
    let mut file_app_path = file_mask_out.clone();
    file_app_path.push_str(".app");
    let mut file_set_path = file_mask_out.clone();
    file_set_path.push_str(".set");

    // Collect edges and vertices
    let mut property_set = FnvHashSet::default();
    let mut mask_set = FnvHashSet::default();
    let stages = graph.stages();

    for stage in 0..stages-1 {
        for (&input, vertex_ref) in graph.get_stage(stage).unwrap() {
            for (&output, _) in &vertex_ref.successors {
                property_set.insert((input,output));
                mask_set.insert(input);
                mask_set.insert(output);
            }
        }
    }

    // Contents of previous files are overwritten
    let mut file = OpenOptions::new()
                               .write(true)
                               .truncate(true)
                               .create(true)
                               .open(file_app_path)
                               .expect("Could not open file.");


    for (input, output) in &property_set {
        write!(file, "{:016x},{:016x}\n", input, output).expect("Could not write to file.");
    }

    let mut file = OpenOptions::new()
                               .write(true)
                               .truncate(true)
                               .create(true)
                               .open(file_set_path)
                               .expect("Could not open file.");
    
    for mask in &mask_set {
        write!(file, "{:016x}\n", mask).expect("Could not write to file.");
    }
}

/**
Reads two files of allowed input and output values and stores them in hash sets. The used 
are <file_mask_in>.input and <file_mask_in>.output. The values in the files are assumed to be in
hexadecimals, without the '0x' prefix. 

file_mask_in        Prefix of the path of the two files used.
*/
fn read_allowed(file_mask_in: String) 
                -> (FnvHashSet<u64>,FnvHashSet<u64>) {
    let mut file_input_path = file_mask_in.clone();
    file_input_path.push_str(".input");
    let mut file_output_path = file_mask_in.clone();
    file_output_path.push_str(".output");

    let file = File::open(file_input_path).expect("Could not open file.");
    let input_allowed = BufReader::new(file).lines()
                            .map(|x| u64::from_str_radix(&x.expect("Error reading file."), 16)
                                         .expect("Could not parse integer. Is it in hexadecimals?"))
                            .collect();

    let file = File::open(file_output_path).expect("Could not open file.");
    let output_allowed = BufReader::new(file).lines()
                           .map(|x| u64::from_str_radix(&x.expect("Error reading file."), 16)
                                        .expect("Could not parse integer. Is it in hexadecimals?"))
                           .collect();
    (input_allowed, output_allowed)
}

/**
Searches for properties over a given number of rounds for a given cipher. 

cipher          The cipher to investigate. 
property_type   The type of property to search for.
rounds          The number of rounds to consider.
patterns        The number of S-box patterns to generate. Relates to the number of
                properties generate per round. 
file_mask_in    Prefix of two files which restict the input/output values of the properties.
file_mask_out   Prefix of two files to which results are dumped.
file_graph      Prefix of a file to which raw graph data is dumped.
*/
pub fn find_properties(cipher: Box<Cipher>, 
                       property_type: PropertyType,
                       rounds: usize, 
                       patterns: usize,
                       file_mask_in: Option<String>,
                       file_mask_out: Option<String>,
                       file_graph: Option<String>) {
    let start = time::precise_time_s();
    // Restrict the number of results printed
    let num_keep = 50;

    let (input_allowed, output_allowed) = match file_mask_in {
        Some(path) => {
            read_allowed(path)
        },
        None => {  
            (FnvHashSet::default(), FnvHashSet::default())
        }
    };

    let graph = generate_graph(cipher, property_type, rounds, 
                               patterns, &input_allowed, &output_allowed);

    match file_graph {
        Some(path) => {
            dump_to_graph_tool(&graph, &path);
        },
        None => {}
    }

    match file_mask_out {
        Some(path) => {
            dump_masks(&graph, path);
        },
        None => { }
    }
    
    let result = parallel_find_properties(&graph,&input_allowed, &output_allowed, num_keep);
    
    println!("Search finished. [{} s]", time::precise_time_s()-start);

    for &property in &result {
        if property.input == 0 && property.output == 0 {
            continue
        }

        print!("Approximation:   {:?} ", property);
        println!("[{}, {}]", property.trails, property.value.log2());
    }
}
