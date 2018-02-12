use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

/* A structure representing a linear approximation.
 *
 * alpha    The input mask.
 * beta     The output mask.
 * value    Squared correlation of the approximation.
 */
#[derive(Clone)]
pub struct Approximation {
    pub alpha: u64,
    pub beta: u64,
    pub value: f64,
}

impl Approximation {
    /* Generates a new linear approximation.
     *
     * alpha    The input mask.
     * beta     The output mask.
     */
    pub fn new(alpha: u64, beta: u64, value: Option<f64>) -> Approximation {
        match value {
            Some(x) => {
                return Approximation{alpha: alpha, beta: beta, value: x};
            },
            None => {
                return Approximation{alpha: alpha, beta: beta, value: 1.0};
            }
        }
    }
}

impl Ord for Approximation {
    fn cmp(&self, other: &Approximation) -> Ordering {
        if self.alpha == other.alpha {
            self.beta.cmp(&other.beta)
        } else {
            self.alpha.cmp(&other.alpha)
        }
    }
}

impl PartialOrd for Approximation {
    fn partial_cmp(&self, other: &Approximation) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Approximation {
    fn eq(&self, other: &Approximation) -> bool {
        (self.alpha == other.alpha) && (self.beta == other.beta)
    }
}

impl Eq for Approximation {}

impl Hash for Approximation {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.alpha.hash(state);
        self.beta.hash(state);
    }
}

impl fmt::Debug for Approximation {
    /* Formats the approximation in a nice way for printing */
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({:016x},{:016x})", self.alpha, self.beta)
    }
}
