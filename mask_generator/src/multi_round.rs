use single_round::SortedApproximations;

fn find_approximation(cipher: &Cipher, num_patterns: usize) {
    let patterns = SortedApproximations::new(cipher, num_patterns);
}