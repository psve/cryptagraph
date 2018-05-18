use property::PropertyType;

#[derive(Clone, StructOpt)]
#[structopt(name = "Cipher Property Search")]
pub struct CliArgs {
    #[structopt(short = "c", long = "cipher")]
    /**
    Name of the cipher to analyse. Current available ciphers are: 
    fly, gift, khazad, klein, led, mantis, mibs, midori, present, pride, prince, puffin, qarma, rectangle, skinny, twine
    */
    pub cipher: String,

    #[structopt(short = "t", long = "type")]
    /**
    The type of property to analyse. Currently supported are:
    linear, differential
    */
    pub property_type: PropertyType,

    #[structopt(short = "r", long = "rounds")]
    /**
    The number of rounds the analyse.
    */
    pub rounds: usize,

    #[structopt(short = "p", long = "patterns")]
    /**
    The number of S-box patterns to generate. The number of patterns determine how many different properties over a single round are analysed. 
    */
    pub num_patterns: usize,

    #[structopt(short = "x", long = "percentage")]
    /**
    If provided, this parameter is used to restrict the graph before searching for properties. 
    */
    pub percentage: Option<f64>,

    #[structopt(short = "a", long = "anchors")]
    /**
    If provided, this parameter parameter overrides the default number of anchors. The number of anchors is 2^(<a>). 
    */
    pub anchors: Option<usize>,

    #[structopt(short = "i", long = "mask_in")]
    /**
    Prefix of a path to a set of two files which restrict the input and output values of the property. The two files are assumed to be <file_mask_in>.input and <file_mask_in>.output.
    */
    pub file_mask_in: Option<String>,

    #[structopt(short = "o", long = "mask_out")]
    /**
    Prefix of a path to a set of two files in which to dump the discovered properties as well as the set of their inputs and outputs. The two files generated are <file_mask_out>.app and <file_mask_out>.set.
    */
    pub file_mask_out: Option<String>,

    #[structopt(short = "g", long = "file_graph")]
    /**
    Prefix of a path to dump the graph data to. The file generate is <file_graph>.graph.
    */
    pub file_graph: Option<String>,    
}
