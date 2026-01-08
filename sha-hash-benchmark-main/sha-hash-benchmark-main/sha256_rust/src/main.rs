// src/main.rs
// SHA-256 純Rust版テストプログラム
use sha256_arm::{Sha256State, sha256_transform_generic};
use std::time::Instant;
use std::hint::black_box;

fn main() {
    
    println!("=== SHA-256 汎用実装 ===\n");
    
    // 特定の入力値を用いた正当性の検証とベンチマークの実行
    test_custom_values();
}


/// SHA-256の内部状態をフォーマットして表示
fn print_state(label: &str, state: &Sha256State) {
    println!("{}:", label);
    for &val in &state.h {
        println!("  {:08x}", val);
    }
}

fn test_custom_values() {
    
    // SHA-256 初期状態
     
    let initial_state = Sha256State {
     h: [
           0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
           0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
      ],
    };
    
    // 入力データ: "abc" + パディング
    let block_bytes: [u8; 64] = [
        0x61, 0x62, 0x63, 0x80,
        0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0,
        0,0,0,0x18,
    ];
    let blocks = [block_bytes];
    
    print_state("初期状態", &initial_state);
    println!();
 
    // 動作確認のため、最初の1回だけ実行して結果を表示
let mut state = initial_state.clone();


let start = Instant::now();
// コンパイラによる最適化削除を防ぎつつ実行
sha256_transform_generic(black_box(&mut state), black_box(&block_bytes));  // 配列を削除
let duration = start.elapsed();

print_state("最終状態", &state);
println!("実行時間: {:.10}秒", duration.as_secs_f64());
const ITERATIONS: usize = 10_000_000;

// 空回し (ウォームアップ) ---
// 空回し (ウォームアップ) ---
println!("CPUウォームアップ中({}回)...", ITERATIONS);
let mut warmup_state = initial_state.clone();
for i in 0..ITERATIONS {
    sha256_transform_generic(black_box(&mut warmup_state), black_box(&block_bytes));  // unsafeと配列を削除
    
    black_box(warmup_state);
    black_box(i);
}

// 1000万回の繰り返し測定ループ
// 2^24 = 16_777_216 で10_000_000に近い
const ITERATIONS_1: usize = 16384; // 2^14
const ITERATIONS_2: usize = 1024; // 2^10
let mut times: Vec<u128> = Vec::with_capacity(ITERATIONS_1);


for i in 0..ITERATIONS_1 {
  
    let start = Instant::now();

    for j in 0..ITERATIONS_2 {
         // 最適化で消されないよう black_box を介して実行
        sha256_transform_generic(black_box(&mut state), black_box(&block_bytes));  // unsafeと配列を削除
        
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