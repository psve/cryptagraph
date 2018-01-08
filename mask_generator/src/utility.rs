/* Finds the parity of <input, alpha> ^ <outout, beta>, where <_,_> is the inner product
 * over F_2. 
 * Taken from http://www.graphics.stanford.edu/~seander/bithacks.html#ParityMultiply
 */
pub fn parity(input: u64, output: u64, alpha: u64, beta: u64) -> u64 {
    let mut y = (input & alpha) | ((output & beta) << 32);

    y ^= y >> 1;
    y ^= y >> 2;
    y = (y & 0x1111111111111111) * 0x1111111111111111;
    (y >> 60) & 1
}