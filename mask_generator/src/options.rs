#[derive(Clone, StructOpt)]
#[structopt(name = "CLI arguments")]
pub struct CliArgs {
    #[structopt(short = "c", long = "cipher", help = "Name of the cipher to analyse. Current available ciphers:\n\tpresent\n\tgift\n\ttwine\n\tpuffin\n\tskinny\n\tmidori\n\tled\n\trectangle\n\tmibs")]
    pub cipher: String,

    #[structopt(short = "r", long = "rounds", help = "Number of rounds.")]
    pub rounds: Option<usize>,

    #[structopt(short = "p", long = "patterns", help = "Number of patterns to generate.")]
    pub num_patterns: Option<usize>,

    #[structopt(short = "f", long = "file_mask", help = "File to dump mask set to.")]
    pub file_name_mask: Option<String>,

    #[structopt(short = "g", long = "file_graph", help = "File to dump graph data to.")]
    pub file_name_graph: Option<String>,    
}
