
use fnv::FnvHashSet;
use std::fs::{File, OpenOptions};
use std::io::{Write, BufReader, BufRead};
use time;


use cipher::Cipher;
use find_hulls::parallel_find_hulls;
use graph::MultistageGraph;
use graph_generate::generate_graph;
use property::PropertyType;

/* Prints a graph for plotting with python graph-tool */
fn print_to_graph_tool (
    graph: &MultistageGraph,
    path: &String) {
    let mut path = path.clone();
    path.push_str(".graph");
    let mut file = OpenOptions::new()
                               .write(true)
                               .truncate(true)
                               .create(true)
                               .open(path)
                               .expect("Could not open file.");

    let stages = graph.stages();

    for i in 0..stages {
        for (j, _) in graph.get_stage(i).unwrap() {
            write!(file, "{},{}\n", i, j).expect("Write error");
        }
    }        

    for i in 0..stages-1 {
        for (j, vertex_ref) in graph.get_stage(i).unwrap() {
            for (k, _) in &vertex_ref.successors {
                write!(file, "{},{},{},{}\n", i, j, i+1, k).expect("Write error");       
            }
        }
    }   
}

fn dump_masks(file_mask_out: String, graph: &MultistageGraph) {
    let mut file_app_path = file_mask_out.clone();
    file_app_path.push_str(".app");
    let mut file_set_path = file_mask_out.clone();
    file_set_path.push_str(".set");

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

    let mut file = OpenOptions::new()
                               .write(true)
                               .truncate(true)
                               .create(true)
                               .open(file_app_path)
                               .expect("Could not open file.");


    for (input, output) in &property_set {
        write!(file, "{:016x}, {:016x}\n", input, output).expect("Could not write to file.");
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

fn read_allowed(file_mask_in: String) -> (FnvHashSet<u64>,FnvHashSet<u64>) {
    let mut file_input_path = file_mask_in.clone();
    file_input_path.push_str(".input");
    let mut file_output_path = file_mask_in.clone();
    file_output_path.push_str(".output");

    let file = File::open(file_input_path).expect("Could not open file.");
    let input_allowed = BufReader::new(file).lines()
                                            .map(|x| u64::from_str_radix(&x.expect("Error reading file"), 16)
                                                         .expect("Could not parse integer"))
                                            .collect();

    let file = File::open(file_output_path).expect("Could not open file.");
    let output_allowed = BufReader::new(file).lines()
                                           .map(|x| u64::from_str_radix(&x.expect("Error reading file"), 16)
                                                        .expect("Could not parse integer"))
                                           .collect();
    (input_allowed, output_allowed)
}

pub fn find_approximations (
    cipher: Box<Cipher>, 
    property_type: PropertyType,
    rounds: usize, 
    patterns: usize,
    file_mask_in: Option<String>,
    file_mask_out: Option<String>,
    file_graph: Option<String>) {
    let start = time::precise_time_s();
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
            print_to_graph_tool(&graph, &path);
        },
        None => {}
    }

    // Dump union of all hull sets if path is specified
    match file_mask_out {
        Some(path) => {
            dump_masks(path, &graph);
        },
        None => { }
    }
    
    let result = parallel_find_hulls(&graph,&input_allowed, &output_allowed, num_keep);
    
    println!("Search finished. [{} s]", time::precise_time_s()-start);

    for &property in &result {
        if property.input == 0 && property.output == 0 {
            continue
        }

        print!("Approximation:   {:?} ", property);
        println!("[{}, {}]", property.trails, property.value.log2());
    }
}
