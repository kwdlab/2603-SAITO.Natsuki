// src/main.rs
// SHA-512 純Rust版テストプログラム

use sha512_arm::{Sha512State, sha512_transform_generic};
use std::time::Instant;
use std::hint::black_box;

fn main() {
    // タイマー分解能の測定
    println!("=== タイマー分解能の測定 ===");
    let mut timer_deltas = Vec::new();
    for _ in 0..1000 {
        let t1 = Instant::now();
        let t2 = Instant::now();
        let delta = t2.duration_since(t1).as_nanos();
        if delta > 0 {
            timer_deltas.push(delta);
        }
    }
    if !timer_deltas.is_empty() {
        timer_deltas.sort();
        println!("タイマーの最小刻み幅: {} ナノ秒", timer_deltas[0]);
        println!("タイマーの中央値: {} ナノ秒", timer_deltas[timer_deltas.len() / 2]);
    }
    println!();

    println!("=== SHA-512 純Rust版 テスト ===\n");
    
    test_custom_values();
}

fn print_state(label: &str, state: &Sha512State) {
    println!("{}:", label);
    for &val in &state.h {
        println!("  {:016x}", val);
    }
}

/// カスタム値でのテスト
fn test_custom_values() {
    println!("【テスト】カスタム値\n");
    
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
    let data: [u8; 128] = [
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
    sha512_transform_generic(black_box(&mut state), black_box(&data));
    let duration = start.elapsed();
    
    print_state("最終状態", &state);
    println!();
    println!("実行時間: {:.9}秒\n", duration.as_secs_f64());
    
    // パフォーマンスの統計測定を開始
    println!("=== 同じ計算を10000000回繰り返し実行（統計測定） ===");
    println!("測定中...");
    
    const ITERATIONS: usize = 10_000_000;
    let mut times = Vec::with_capacity(ITERATIONS);
    let mut zero_count = 0;
    
    let total_start = Instant::now();
    
    // 1000万回の繰り返し測定ループ
    for i in 0..ITERATIONS {
        let mut state = initial_state.clone();
        let start = Instant::now();
        // 最適化で消されないよう black_box を介して実行
        sha512_transform_generic(black_box(&mut state), black_box(&data));
        let elapsed = start.elapsed();
        let time_ns = elapsed.as_nanos();
        let time_sec = elapsed.as_secs_f64();
        
        if time_ns == 0 {
            zero_count += 1;
        }
        
        // ループ変数を black_box に入れることでループ自体の最適化を抑制
        black_box(i);
        
        times.push(time_sec);
    }
    
    let total_duration = total_start.elapsed().as_secs_f64();
    
    // 測定結果のサマリー
    println!("ゼロとして測定された回数: {} / {} ({:.2}%)", 
             zero_count, ITERATIONS, (zero_count as f64 / ITERATIONS as f64) * 100.0);
    
    // 統計計算のためにソート
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    
    // 最小値、最大値、中央値の取得
    let min = times[0];
    let max = times[ITERATIONS - 1];
    let median = if ITERATIONS % 2 == 0 {
        (times[ITERATIONS / 2 - 1] + times[ITERATIONS / 2]) / 2.0
    } else {
        times[ITERATIONS / 2]
    };
    
    // 平均値の計算
    let sum: f64 = times.iter().sum();
    let mean = sum / ITERATIONS as f64;
    
    // 分散と標準偏差の計算
    let variance: f64 = times.iter()
        .map(|x| {
            let diff = x - mean;
            diff * diff
        })
        .sum::<f64>() / ITERATIONS as f64;
    
    let std_dev = variance.sqrt();
    let throughput = ITERATIONS as f64 / total_duration;
    
    // 非ゼロ値の詳細分析
    let non_zero_times: Vec<f64> = times.iter().copied().filter(|&t| t > 0.0).collect();
    println!("非ゼロ測定値の数: {} / {}", non_zero_times.len(), ITERATIONS);
    if !non_zero_times.is_empty() {
        let nz_min = non_zero_times[0];
        let nz_median = non_zero_times[non_zero_times.len() / 2];
        println!("非ゼロ値の最小値: {:.30} 秒 ({} ナノ秒)", nz_min, (nz_min * 1e9) as u64);
        println!("非ゼロ値の中央値: {:.30} 秒 ({} ナノ秒)", nz_median, (nz_median * 1e9) as u64);
    }
    
    // 最終的な統計レポートの出力
    println!("\n=== 統計結果 ===");
    println!("実行回数: {}", ITERATIONS);
    
    println!("--- 時間統計 (秒) ---");
    println!("最小値: {:.30}", min);
    println!("最大値: {:.30}", max);
    println!("中央値: {:.30}", median);
    println!("平均値: {:.30}", mean);
    println!("分散: {:.30e}", variance);
    println!("標準偏差: {:.30}", std_dev);
    
    println!("--- 性能指標 ---");
    println!("総実行時間: {:.3}秒", total_duration);
    println!("スループット: {:.2} ops/sec", throughput);
}