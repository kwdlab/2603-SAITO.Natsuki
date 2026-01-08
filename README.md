# 2603-SAITO.Natsuki
2026年3月卒業  西藤なつき
# Overview
This project is a benchmark program that compares the execution performance of SHA-256 and SHA-512 implemented in software and using AArch64 dedicated instructions, implemented in Rust.
# Description
・The program repeatedly computes SHA-256 and SHA-512 hashes and measures and compares the execution time of software-based and hardware-accelerated implementations<br>
・Execution time is measured using a high-resolution timer provided by Rust’s standard library (std::time::Instant)
# Requirements
・rustc 1.92.0 <br>
・cargo 1.92.0
# Install / Usage
$ RUSTFLAGS="-C target-cpu=native" sudo nice -n -20 cargo run --release
# Author
Natsuki Saito
# References
・https://doc.rust-lang.org/std/ <br>
・https://csrc.nist.gov/files/pubs/fips/180-2/final/docs/fips180-2.pdf 
# License
MIT
