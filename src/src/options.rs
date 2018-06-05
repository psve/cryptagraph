use property::PropertyType;

#[derive(Clone, StructOpt)]
#[structopt(name = "Cryptagraph", about = "Search for linear and differential properties of block ciphers.")]
pub enum CryptagraphOptions {
    #[structopt(name = "search")]
    Search {
        #[structopt(short = "c", long = "cipher")]
        /**
        Name of the cipher to analyse. Current available ciphers are: 
        fly, gift, khazad, klein, led, mantis, mibs, midori, present, pride, prince, puffin, qarma, rectangle, skinny, twine
        */
        cipher: String,

        #[structopt(short = "t", long = "type")]
        /**
        The type of property to analyse. Currently supported are:
        linear, differential
        */
        property_type: PropertyType,

        #[structopt(short = "r", long = "rounds")]
        /**
        The number of rounds the analyse.
        */
        rounds: usize,

        #[structopt(short = "p", long = "patterns")]
        /**
        The number of S-box patterns to generate. The number of patterns determine how many different properties over a single round are analysed. 
        */
        num_patterns: usize,

        #[structopt(short = "a", long = "anchors")]
        /**
        If provided, this parameter parameter overrides the default number of anchors. The number of anchors is 2^(<a>). 
        */
        anchors: Option<usize>,

        #[structopt(short = "i", long = "mask_in")]
        /**
        Prefix of a path to a set of two files which restrict the input and output values of the property. The two files are assumed to be <file_mask_in>.input and <file_mask_in>.output.
        */
        file_mask_in: Option<String>,

        #[structopt(short = "o", long = "mask_out")]
        /**
        Prefix of a path to a set of two files in which to dump the discovered properties as well as the set of their inputs and outputs. The two files generated are <file_mask_out>.app and <file_mask_out>.set.
        */
        file_mask_out: Option<String>,

        #[structopt(short = "g", long = "file_graph")]
        /**
        Prefix of a path to dump the graph data to. The file generate is <file_graph>.graph.
        */
        file_graph: Option<String>,
    },

    #[structopt(name = "dist")]
    Dist {
        #[structopt(short = "c", long = "cipher", help = "Name of cipher to analyse.")]
        cipher: String,

        #[structopt(short = "a", long = "alpha", help = "Input masks (file path)")]
        alpha: String,

        #[structopt(short = "b", long = "beta", help = "Output masks (file path)")]
        beta: String,

        #[structopt(short = "r", long = "rounds", help = "Number of rounds to enumerate")]
        rounds: usize,

        #[structopt(short = "k", long = "keys", help = "Number of keys to enumerate")]
        keys: usize,

        #[structopt(short = "m", long = "masks", help = "Path to file of masks")]
        masks: String,

        #[structopt(short = "o", long = "output", help = "Pattern to save correlations: save.cipher.keys.input.output.corrs")]
        output: String,
    }
}