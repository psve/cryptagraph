use crate::property::PropertyType;

#[derive(Clone, StructOpt)]
#[structopt(name = "Cryptagraph", about = "Search for linear and differential properties of block ciphers.")]
pub enum CryptagraphOptions {
    #[structopt(name = "search")]
    Search {
        #[structopt(short = "c", long = "cipher")]
        /**
        Name of the cipher to analyse. Current available ciphers are: 
        aes, boron, des, epcbc48, epcbc96, fly, gift64, gift128, halka, iceberg, khazad, klein, led, mantis, mcrypton, mibs, midori, present, pride, prince, puffin, qarma, rectangle, skinny64, skinny128, twine
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
        Path to a file which restrict the input and output values of the property. Each line of the file must be of the form '<input>,<output>'.
        */
        file_mask_in: Option<String>,

        #[structopt(short = "o", long = "mask_out")]
        /**
        Prefix of a path to a set of two files in which to dump the discovered properties as well as the set of their inputs and outputs. The two files generated are <file_mask_out>.app and <file_mask_out>.set.
        */
        file_mask_out: Option<String>,

        #[structopt(short = "n", long = "num_keep")]
        /**
        The number of properties to display as output. If specified together with <mask_out>, the 
        results are also written to the file <mask_out>.app.
        */
        num_keep: Option<usize>,

        #[structopt(short = "g", long = "file_graph")]
        /**
        Prefix of a path to dump the graph data to. The file generate is <file_graph>.graph.
        */
        file_graph: Option<String>,
    },

    #[structopt(name = "dist")]
    Dist {
        #[structopt(short = "c", long = "cipher")]
        /**
        Name of the cipher to analyse. Current available ciphers are: 
        aes, epcbc48, epcbc96, fly, gift64, gift128, khazad, klein, led, mantis, mibs, midori, present, pride, prince, puffin, qarma, rectangle, skinny64, skinny128, twine
        */
        cipher: String,

        #[structopt(short = "i", long = "mask_in")]
        /**
        Path to a file which restrict the input and output values of the property. Each line of the file must be of the form '<input>,<output>'.
        */
        file_mask_in: String,

        #[structopt(short = "r", long = "rounds")]
        /**
        Number of rounds to generate correlations for.
        */
        rounds: usize,

        #[structopt(short = "k", long = "keys")]
        /**
        Number of keys to generation correlations for.
        */
        keys: usize,

        #[structopt(short = "m", long = "masks")]
        /**
        Path to a file containing intermediate masksk.
        */
        masks: String,

        #[structopt(short = "o", long = "output")]
        /**
        Name of output file. File name is <output>.corrs
        */
        output: String,
    }
}