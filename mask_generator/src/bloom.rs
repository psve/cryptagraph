use rand::{self, Rng};

/* Hash function specifically for 64 bit integers. Taken from: 
 * https://stackoverflow.com/questions/664014/what-integer-hash-function-are-good-that-accepts-an-integer-hash-key#12996028
 *
 * input        Value to hash.
 * key          A key to randomise the hash function.
 */
fn hash(input: u64, key: u64) -> u64 {
    let mut output = input;
    
    output ^= key;
    output = (output ^ (output >> 30)).wrapping_mul(0xbf58476d1ce4e5b9_u64);
    output = (output ^ (output >> 27)).wrapping_mul(0x94d049bb133111eb_u64);
    output = output ^ (output >> 31);

    output
}

/* Simple Bloom filter using double hashing.
 * 
 * state        The state of the Bloom filter.
 * k            The number of hash functions used by the filter. 
 * size         The number of bits in the state.
 * rand         Random values used to generate two independent hash functions.
 */ 
#[derive(Clone)]
pub struct BloomFilter {
    state: Vec<u64>,
    k: usize,
    size: usize,
    rand: (u64, u64),
}

impl BloomFilter {
    /* Create new Bloom filter. 
     *
     * num_elements         Number of elements to be inserted.
     * false_positive_rate  The desired false positive rate of the filter.
     */
    pub fn new(num_elements: usize, false_positive_rate: f64) -> BloomFilter {
        let mut rng = rand::thread_rng();
        let rand = (rng.gen::<u64>(), rng.gen::<u64>());
        let k = (-false_positive_rate.log2()).ceil() as usize;
        let size = (-1.44*false_positive_rate.log2() * (num_elements as f64)).ceil() as usize;
        let state_size = ((size as f64) / 64.0).ceil() as usize;
        let state = vec![0; state_size];

        BloomFilter{state: state, k: k, size: size, rand: rand}
    }

    /* Insert an element into the Bloom filter. 
     *
     * element      Element to insert.
     */
    pub fn insert(&mut self, element: u64) {
        let h1 = hash(element, self.rand.0);
        let h2 = hash(element, self.rand.1);

        for i in 0..self.k {
            let index = h1.wrapping_add(h2.wrapping_mul(i as u64)) % self.size as u64;
            self.state[(index / 64) as usize] |= 1 << (index % 64);
        }
    }

    /* Check if the Bloom filter contains a specific element. 
     *
     * element      Element to look up.
     */
    pub fn contains(&self, element: u64) -> bool {
        let mut result = true;

        let h1 = hash(element, self.rand.0);
        let h2 = hash(element, self.rand.1);

        for i in 0..self.k {
            let index = h1.wrapping_add(h2.wrapping_mul(i as u64)) % self.size as u64;
            let bit = (self.state[(index / 64) as usize] >> (index % 64)) & 0x1;

            if bit == 0 {
                result = false;
                break;
            }
        }

        result
    }
}