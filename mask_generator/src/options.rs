use std::num::ParseIntError;

fn parse_hex(src: &str) -> Result<u64, ParseIntError> {
    u64::from_str_radix(src, 16)
}

#[derive(Clone, StructOpt)]
#[structopt(name = "CLI arguments")]
pub struct CliArgs {
    #[structopt(short = "c", long = "cipher", help = "Name of the cipher to analyse. Current available ciphers:\n\tpresent\n\tgift")]
    pub cipher: String,

    #[structopt(short = "m", long = "mode", help = "Which mode to run. Current available modes:\n\tsingle\n\tsearch")]
    pub mode: String,

    #[structopt(short = "r", long = "rounds", help = "Number of rounds.")]
    pub rounds: usize,

    #[structopt(short = "i", long = "input", help = "Input mask for single search.", parse(try_from_str = "parse_hex"))]
    pub alpha: Option<u64>,

    #[structopt(short = "p", long = "patterns", help = "Number of patterns to generate.")]
    pub pattern_limit: usize,

    #[structopt(short = "a", long = "approximations", help = "Number of single round approximations to generate.")]
    pub approximation_limit: usize,

    #[structopt(short = "s", long = "search", help = "Number of approximations to search in search mode.")]
    pub search_limit: Option<usize>,

    #[structopt(short = "f", long = "file", help = "File to dump mask set to in single mode.")]
    pub file_path: Option<String>,
}
