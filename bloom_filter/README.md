# Bloom Filter

[![Build Status](https://travis-ci.org/jeromefroe/bloom_filter.svg?branch=master)](https://travis-ci.org/jeromefroe/bloom_filter)
[![codecov](https://codecov.io/gh/jeromefroe/bloom_filter/branch/master/graph/badge.svg)](https://codecov.io/gh/jeromefroe/bloom_filter)
[![crates.io](https://img.shields.io/crates/v/bloom_filter.svg)](https://crates.io/crates/bloom_filter/)
[![docs.rs](https://docs.rs/bloom_filter/badge.svg)](https://docs.rs/bloom_filter/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/jeromefroe/bloom_filter/master/LICENSE)

[Documentation](https://docs.rs/bloom_filter/)

An implementation of a bloom filter as as described in
[Space/Time Trade-offs in Hash Coding with Allowable Errors](http://dmod.eu/deca/ft_gateway.cfm.pdf).

## Example

``` rust,no_run
extern crate bloom_filter;

use bloom_filter::BloomBuilder;

fn main() {
    let elements = 2u64.pow(20);
    let fpr = 0.01;
    let mut bloom = BloomBuilder::new(elements).with_fpr(fpr).finish().unwrap();

    bloom.insert("foo");
    bloom.insert("bar");
    bloom.insert("baz");

    if bloom.lookup("foo") {
        println!("found foo in the bloom filter");
    }
}
```