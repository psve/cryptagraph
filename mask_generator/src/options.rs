#[derive(Clone, StructOpt)]
#[structopt(name = "CLI arguments")]
pub struct CliArgs {
    #[structopt(short = "c", long = "cipher", help = "Name of the cipher to analyse. Current available ciphers:\n\tpresent\n\tgift\n\ttwine\n\tpuffin\n\tskinny\n\tmidori\n\tled\n\trectangle\n\tmibs")]
    pub cipher: String,

    #[structopt(short = "m", long = "mode", help = "Which mode to run. Current available modes:\n\tsearch\n\tprobe")]
    pub mode: String,

    #[structopt(short = "r", long = "rounds", help = "Number of rounds.")]
    pub rounds: Option<usize>,

    #[structopt(short = "p", long = "patterns", help = "Number of patterns to generate.")]
    pub pattern_limit: Option<usize>,

    #[structopt(short = "x", long = "falsepositive", help = "False positive rate used for Bloom filters.")]
    pub false_positive: Option<f64>,

    #[structopt(short = "f", long = "file", help = "File to dump mask set to in single mode.")]
    pub file_path: Option<String>,
}
