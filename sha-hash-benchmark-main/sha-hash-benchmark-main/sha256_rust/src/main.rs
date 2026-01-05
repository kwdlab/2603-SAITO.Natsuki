// src/main.rs
// SHA-256 純Rust版テストプログラム
use sha256_arm::{Sha256State, sha256_transform_generic};
use std::time::Instant;
use std::hint::black_box;

fn main() {
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

    println!("=== SHA-256 Generic版 テスト ===\n");
    
    // 特定の入力値を用いた正当性の検証とベンチマークの実行
    test_custom_values();
}

/// 測定データの統計解析を管理する構造体
struct Statistics {
    min: f64,      // 最小実行時間
    max: f64,      // 最大実行時間
    mean: f64,     // 平均値
    median: f64,   // 中央値
    variance: f64, // 分散
    stddev: f64,   // 標準偏差
}

impl Statistics {
    /// 与えられた時間データのベクトルから統計指標を算出
    fn calculate(times: &mut Vec<f64>) -> Self {
        // 統計計算のためにソート
        times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        
        let min = times[0];
        let max = times[times.len() - 1];
        
        // 合計および平均の計算
        let sum: f64 = times.iter().sum();
        let mean = sum / times.len() as f64;
        
        // 中央値の計算
        let median = if times.len() % 2 == 0 {
            (times[times.len() / 2 - 1] + times[times.len() / 2]) / 2.0
        } else {
            times[times.len() / 2]
        };
        
        // 分散の計算
        let variance = times.iter()
            .map(|&t| {
                let diff = t - mean;
                diff * diff
            })
            .sum::<f64>() / times.len() as f64;
        
        // 標準偏差の計算（分散の平方根）
        let stddev = variance.sqrt();
        
        Self {
            min,
            max,
            mean,
            median,
            variance,
            stddev,
        }
    }
}

/// SHA-256の内部状態をフォーマットして表示
fn print_state(label: &str, state: &Sha256State) {
    println!("{}:", label);
    println!("  {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}",
        state.h[0], state.h[1], state.h[2], state.h[3],
        state.h[4], state.h[5], state.h[6], state.h[7]);
}

fn test_custom_values() {
    println!("【テスト】カスタム値\n");
    
    // SHA-256規格で定められた初期ハッシュ値
    let initial_state = Sha256State {
        h: [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ],
    };
    
    // テストデータ: 文字列 "abc" に対してパディングを施した1ブロック分（64バイト）
    // 0x61('a'), 0x62('b'), 0x63('c'), 0x80(パディング開始ビット)... 最終8バイトはビット長(0x18 = 24bits)
    let data: [u8; 64] = [
        0x61, 0x62, 0x63, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
    ];
    
    print_state("初期状態", &initial_state);
    println!();
    
    // 動作確認のため、最初の1回だけ実行して結果を表示
    let mut state = initial_state.clone();
    let start = Instant::now();
    sha256_transform_generic(black_box(&mut state), black_box(&data));
    let duration = start.elapsed();
    
    print_state("最終状態", &state);
    println!();
    println!("実行時間: {:.9} 秒\n", duration.as_secs_f64());
    
    // パフォーマンスの統計測定を開始
    println!("=== 同じ計算を10000000回繰り返し実行（統計測定） ===");
    println!("測定中...");
    
    // 1000万回の繰り返し測定ループ
    const ITERATIONS: usize = 10_000_000;
    let mut times = Vec::with_capacity(ITERATIONS);
    let mut zero_count = 0;
    
    let total_start = Instant::now();
    
    for i in 0..ITERATIONS {
        let mut state = initial_state.clone();
        let start = Instant::now();
        // 最適化で消されないよう black_box を介して実行
        sha256_transform_generic(black_box(&mut state), black_box(&data));
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
    
    // 非ゼロ値の詳細分析
    println!("ゼロとして測定された回数: {} / {} ({:.2}%)", 
              zero_count, ITERATIONS, (zero_count as f64 / ITERATIONS as f64) * 100.0);
    
    // 統計指標の算出
    let stats = Statistics::calculate(&mut times);
    
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
    println!("最小値: {:.30}", stats.min);
    println!("最大値: {:.30}", stats.max);
    println!("中央値: {:.30}", stats.median);
    println!("平均値: {:.30}", stats.mean);
    println!("分散: {:.30e}", stats.variance);
    println!("標準偏差: {:.30}", stats.stddev);
    
    println!("--- 性能指標 ---");
    println!("総実行時間: {:.3}秒", total_duration);
    println!("スループット: {:.2} ops/sec", ITERATIONS as f64 / total_duration);
}