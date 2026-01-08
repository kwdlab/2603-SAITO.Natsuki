// src/main.rs
// SHA-512 純Rust版テストプログラム

use sha512_arm::{Sha512State, sha512_transform_generic};
use std::time::Instant;
use std::hint::black_box;

fn main() {
    
    println!("=== SHA-512 汎用実装 ===\n");
    
    test_custom_values();
}

fn print_state(label: &str, state: &Sha512State) {
    println!("{}:", label);
    for &val in &state.h {
        println!("  {:016x}", val);
    }
}


fn test_custom_values() {
    
    // 初期状態
    let initial_state = Sha512State {
        h: [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ],
    };
    
    // テスト用の128バイトデータブロック (メッセージ "abc" をパディングしたもの)
    let block: [u8; 128] = [
        0x61, 0x62, 0x63, 0x80, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x18,
    ];
    
    // 初期状態表示
    print_state("初期状態", &initial_state);
    println!();
    
    // 動作確認のため、最初の1回だけ実行して結果を表示
    let mut state = initial_state.clone();
    let start = Instant::now();
    sha512_transform_generic(black_box(&mut state), black_box(&block));  // data → block に修正
    let duration = start.elapsed();
    
    print_state("最終状態", &state);
    println!();
    println!("実行時間: {:.10}秒\n", duration.as_secs_f64());
    

const ITERATIONS: usize = 10_000_000;

// 空回し (ウォームアップ) ---
println!("CPUウォームアップ中({}回)...", ITERATIONS);
let mut warmup_state = initial_state.clone();
for i in 0..ITERATIONS {
    sha512_transform_generic(black_box(&mut warmup_state), black_box(&block));  // 配列を削除してblockを直接渡す
    
    black_box(warmup_state);
    black_box(i);
}

// 1000万回の繰り返し測定ループ
// 2^24 = 16_777_216 で10_000_000に近い
const ITERATIONS_1: usize = 16384; // 2^14
const ITERATIONS_2: usize = 1024; // 2^10
let mut times: Vec<u128> = Vec::with_capacity(ITERATIONS_1);

for i in 0..ITERATIONS_1 {
    let mut state = initial_state.clone();
    let start = Instant::now();

    for j in 0..ITERATIONS_2 {
         // 最適化で消されないよう black_box を介して実行
        sha512_transform_generic(black_box(&mut state), black_box(&block));  // 配列を削除してblockを直接渡す
        
        black_box(j);// ループ変数を black_box に入れることでループ自体の最適化を抑制
    }

    let elapsed = start.elapsed().as_nanos();
    times.push(elapsed);
    black_box(i);
}

let total_ns: u128 = times.iter().sum();
let total_calls: u128 = (ITERATIONS_1 * ITERATIONS_2) as u128;

let avg_ns = total_ns as f64 / total_calls as f64;
let avg_sec = avg_ns / 1e9;

println!("1回あたりの平均実行時間: {:.12} 秒", avg_sec);

}