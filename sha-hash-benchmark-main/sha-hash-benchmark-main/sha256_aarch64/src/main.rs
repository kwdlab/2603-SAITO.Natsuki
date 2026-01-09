// SHA-256 AArch64版テストプログラム
use core::arch::asm;
use core::arch::aarch64::*;
use std::time::Instant;
use std::hint::black_box;

/// SHA-256 ラウンド定数 (K)
/// 最初の64個の素数の3乗根の小数部分から生成された32bit定数。
static K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// --- AArch64 ハードウェア命令のラッパー関数群 ---
// これらの関数は、コンパイラが自動で最適化できないCPU固有の「SHA256命令」を直接呼び出します。

#[inline(always)]
unsafe fn vsha256hq_u32(
    mut hash_efgh: uint32x4_t,
    hash_abcd: uint32x4_t,
    wk: uint32x4_t,
) -> uint32x4_t {
    unsafe {
        // SHA256H: abcd と wk を使って efgh の状態を更新するハードウェア命令
        asm!(
            "SHA256H {0:q}, {1:q}, {2:v}.4S",
            inout(vreg) hash_efgh, in(vreg) hash_abcd, in(vreg) wk,
            options(pure, nomem, nostack, preserves_flags)
        );
    }
    hash_efgh
}

#[inline(always)]
unsafe fn vsha256h2q_u32(
    mut hash_efgh: uint32x4_t,
    hash_abcd: uint32x4_t,
    wk: uint32x4_t,
) -> uint32x4_t {
    unsafe {
        // SHA256H2: 圧縮関数の第2段階（中間変数の算出）を行うハードウェア命令
        asm!(
            "SHA256H2 {0:q}, {1:q}, {2:v}.4S",
            inout(vreg) hash_efgh, in(vreg) hash_abcd, in(vreg) wk,
            options(pure, nomem, nostack, preserves_flags)
        );
    }
    hash_efgh
}

#[inline(always)]
unsafe fn vsha256su0q_u32(mut w0_3: uint32x4_t, w4_7: uint32x4_t) -> uint32x4_t {
    unsafe {
        // SHA256SU0: メッセージスケジュールの拡張（前半）を加速
        asm!(
            "SHA256SU0 {0:v}.4S, {1:v}.4S",
            inout(vreg) w0_3, in(vreg) w4_7,
            options(pure, nomem, nostack, preserves_flags)
        );
    }
    w0_3
}

#[inline(always)]
unsafe fn vsha256su1q_u32(
    mut tw0_3: uint32x4_t,
    w8_11: uint32x4_t,
    w12_15: uint32x4_t,
) -> uint32x4_t {
    unsafe {
        // SHA256SU1: メッセージスケジュールの拡張（後半）を加速
        asm!(
            "SHA256SU1 {0:v}.4S, {1:v}.4S, {2:v}.4S",
            inout(vreg) tw0_3, in(vreg) w8_11, in(vreg) w12_15,
            options(pure, nomem, nostack, preserves_flags)
        );
    }
    tw0_3
}

/// 外部公開用の圧縮関数インターフェース
pub fn compress256(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    // 安全のため unsafe 境界をここで管理
    unsafe { sha256_compress(state, blocks) }
}

/// AArch64 SHA命令を使用したメインの圧縮ロジック
unsafe fn sha256_compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    // メモリ上の状態（abcd, efgh）をSIMDレジスタ（128bit幅）にロード
    let mut abcd = unsafe { vld1q_u32(state.as_ptr()) };
    let mut efgh = unsafe { vld1q_u32(state[4..].as_ptr()) };

    for block in blocks {
        // 各ブロック処理の最後に元の状態を加算するため、初期値を保存
        let abcd_orig = abcd;
        let efgh_orig = efgh;

        // メッセージブロック（512bit = 64byte）をロードし、
        // ビッグエンディアンからCPUのネイティブ形式へ変換（バイトスワップ）
        let mut s0 = unsafe { vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr()))) };
        let mut s1 = unsafe { vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block[16..].as_ptr()))) };
        let mut s2 = unsafe { vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block[32..].as_ptr()))) };
        let mut s3 = unsafe { vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block[48..].as_ptr()))) };

        // 4ラウンド分の計算を一括で行うマクロ
        macro_rules! round4 {
            ($s:expr, $t:expr) => {{
                // メッセージスケジュール(W)と定数(K)を事前に加算
                let tmp = unsafe { vaddq_u32($s, vld1q_u32(K32[$t..].as_ptr())) };
                let prev = abcd;
                // ハードウェア命令により、ソフトウェア実装では数十行かかる処理を2命令で完了
                abcd = unsafe { vsha256hq_u32(prev, efgh, tmp) };
                efgh = unsafe { vsha256h2q_u32(efgh, prev, tmp) };
            }};
        }

        // 最初の16ラウンド（入力メッセージをそのまま使用）
        round4!(s0, 0);
        round4!(s1, 4);
        round4!(s2, 8);
        round4!(s3, 12);

        // 残りの48ラウンド（メッセージを拡張しながら処理）
        for t in (16..64).step_by(16) {
            // メッセージスケジュールの拡張をハードウェア命令で実行
            s0 = unsafe { vsha256su1q_u32(vsha256su0q_u32(s0, s1), s2, s3) };
            round4!(s0, t);

            s1 = unsafe { vsha256su1q_u32(vsha256su0q_u32(s1, s2), s3, s0) };
            round4!(s1, t + 4);

            s2 = unsafe { vsha256su1q_u32(vsha256su0q_u32(s2, s3), s0, s1) };
            round4!(s2, t + 8);

            s3 = unsafe { vsha256su1q_u32(vsha256su0q_u32(s3, s0), s1, s2) };
            round4!(s3, t + 12);
        }

        // ブロック処理後の状態に、処理前の状態を加算（SHA-256の仕様）
        abcd = unsafe { vaddq_u32(abcd, abcd_orig) };
        efgh = unsafe { vaddq_u32(efgh, efgh_orig) };
    }

    // 更新された最終的な状態をメモリ（state配列）へ書き戻す
    unsafe {
        vst1q_u32(state.as_mut_ptr(), abcd);
        vst1q_u32(state[4..].as_mut_ptr(), efgh);
    }
}

/// 内部状態（H0〜H7）を16進数で表示する補助関数
fn print_state(label: &str, state: &[u32; 8]) {
    println!("{}:", label);
    for x in state {
        println!("{:08x}", x);
    }
}

fn main() {
    println!("=== SHA-256 AArch64実装 ===\n");

    // SHA-256 初期状態
    let initial_state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

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

    // 動作確認のため、最初の1回だけ実行して結果を表示
    let mut state = initial_state;
    print_state("初期状態", &initial_state);
    println!();
    let start = Instant::now();
    // コンパイラによる最適化削除を防ぎつつ実行
    compress256(black_box(&mut state), black_box(&blocks));
    let duration = start.elapsed();
    
    print_state("最終状態", &state);
    println!("実行時間: {:.10}秒", duration.as_secs_f64());


const ITERATIONS: usize = 10_000_000;

// 空回し (ウォームアップ) ---
println!("CPUウォームアップ中({}回)...", ITERATIONS);
let mut warmup_state = initial_state;
let warmup_data = [block_bytes];
for i in 0..ITERATIONS {
    unsafe{compress256(black_box(&mut warmup_state), black_box(&warmup_data));}
    
    black_box(warmup_state);
    black_box(i);
}

// 1000万回の繰り返し測定ループ
// 2^24 = 16_777_216 で10_000_000に近い
const ITERATIONS_1: usize = 16384; // 2^14
const ITERATIONS_2: usize = 1024; // 2^10
let mut times: Vec<u128> = Vec::with_capacity(ITERATIONS_1);

for i in 0..ITERATIONS_1 {
    let mut state = initial_state;
    let data = [block_bytes];  
    let start = Instant::now();

    for j in 0..ITERATIONS_2 {
         // 最適化で消されないよう black_box を介して実行
        unsafe {
            compress256(black_box(&mut state), black_box(&data));
        }    
        
        black_box(j);// ループ変数を black_box に入れることでループ自体の最適化を抑制
    }

    let elapsed = start.elapsed().as_nanos();
    times.push(elapsed);
    black_box(i);
}

// 統計計算用の関数を追加
fn calculate_stats(times: &[u128]) -> (f64, f64, f64) {
    let n = times.len() as f64;
    
    // 平均値
    let sum: u128 = times.iter().sum();
    let mean = sum as f64 / n;
    
    // 中央値
    let mut sorted = times.to_vec();
    sorted.sort_unstable();
    let median = if sorted.len() % 2 == 0 {
        let mid = sorted.len() / 2;
        (sorted[mid - 1] + sorted[mid]) as f64 / 2.0
    } else {
        sorted[sorted.len() / 2] as f64
    };
    
    // 標準偏差
    let variance: f64 = times.iter()
        .map(|&x| {
            let diff = x as f64 - mean;
            diff * diff
        })
        .sum::<f64>() / n;
    let std_dev = variance.sqrt();
    
    (mean, median, std_dev)
}

// 元のループの後を以下に置き換え
let (mean_ns, median_ns, std_dev_ns) = calculate_stats(&times);

println!("=== 統計情報（{}回の処理あたり） ===", ITERATIONS_2);
println!("平均値:   {:.12} 秒", mean_ns / 1e9);
println!("中央値:   {:.12} 秒", median_ns / 1e9);
println!("標準偏差: {:.12} 秒", std_dev_ns / 1e9);
println!();

// 全体の合計をu128で計算してからf64に変換
let total_ns: u128 = times.iter().sum();
let total_calls: u128 = (ITERATIONS_1 * ITERATIONS_2) as u128;  // 2^24 = 16777216
let avg_ns = total_ns as f64 / total_calls as f64;
let avg_sec = avg_ns / 1e9;

println!("=== 1回あたりの平均実行時間 ===");
println!("{:.12} 秒", avg_sec);

}