// SHA-512 AArch64版テストプログラム
#![cfg(target_arch = "aarch64")]

// AArch64固有のネイティブ型や関数を使用するためのインポート
use core::arch::aarch64::*;
// 実行時間の測定に使用
use std::time::Instant;
// コンパイラの最適化によるコードの削除を防ぐために使用
use std::hint::black_box;

// SHA-512 アルゴリズムで使用される 80 個の 64ビット定数（K定数）
const K64: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

// SHA-512ハードウェアアクセラレーション機能（SHA3拡張に含まれる）を有効化
#[target_feature(enable = "sha3")]
unsafe fn sha512_compress_hw(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
    use core::arch::asm;
    
    // ARMv8.2-A SHA-512 高速化命令 SHA512H のラッパー
    #[inline(always)]
    unsafe fn vsha512hq_u64(
        mut hash_ed: uint64x2_t,
        hash_gf: uint64x2_t,
        kwh_kwh2: uint64x2_t,
    ) -> uint64x2_t {
        unsafe {
            asm!(
                "SHA512H {:q}, {:q}, {:v}.2D",
                inout(vreg) hash_ed, in(vreg) hash_gf, in(vreg) kwh_kwh2,
                options(pure, nomem, nostack, preserves_flags)
            );
        }
        hash_ed
    }

    // ARMv8.2-A SHA-512 高速化命令 SHA512H2 のラッパー
    #[inline(always)]
    unsafe fn vsha512h2q_u64(
        mut sum_ab: uint64x2_t,
        hash_c_: uint64x2_t,
        hash_ab: uint64x2_t,
    ) -> uint64x2_t {
        unsafe {
            asm!(
                "SHA512H2 {:q}, {:q}, {:v}.2D",
                inout(vreg) sum_ab, in(vreg) hash_c_, in(vreg) hash_ab,
                options(pure, nomem, nostack, preserves_flags)
            );
        }
        sum_ab
    }

    // メッセージスケジュールの更新に使用する SHA512SU0 命令
    #[inline(always)]
    unsafe fn vsha512su0q_u64(mut w0_1: uint64x2_t, w2_: uint64x2_t) -> uint64x2_t {
        unsafe {
            asm!(
                "SHA512SU0 {:v}.2D, {:v}.2D",
                inout(vreg) w0_1, in(vreg) w2_,
                options(pure, nomem, nostack, preserves_flags)
            );
        }
        w0_1
    }

    // メッセージスケジュールの更新に使用する SHA512SU1 命令
    #[inline(always)]
    unsafe fn vsha512su1q_u64(
        mut s01_s02: uint64x2_t,
        w14_15: uint64x2_t,
        w9_10: uint64x2_t,
    ) -> uint64x2_t {
        unsafe {
            asm!(
                "SHA512SU1 {:v}.2D, {:v}.2D, {:v}.2D",
                inout(vreg) s01_s02, in(vreg) w14_15, in(vreg) w9_10,
                options(pure, nomem, nostack, preserves_flags)
            );
        }
        s01_s02
    }

    // 現在のハッシュ状態 (A-H) を 128ビットレジスタ (uint64x2_t) 4つにロード
    let mut ab = unsafe { vld1q_u64(state[0..2].as_ptr()) };
    let mut cd = unsafe { vld1q_u64(state[2..4].as_ptr()) };
    let mut ef = unsafe { vld1q_u64(state[4..6].as_ptr()) };
    let mut gh = unsafe { vld1q_u64(state[6..8].as_ptr()) };

    // 各 128バイト（1024ビット）のブロックに対して圧縮処理を行う
    for block in blocks {
        // ブロック処理前の状態を保存（最後に加算するため）
        let ab_orig = ab;
        let cd_orig = cd;
        let ef_orig = ef;
        let gh_orig = gh;

        // メッセージブロックを読み込み、エンディアン変換（Big Endian）を行う
        // s0-s7 はそれぞれ 128ビットレジスタ（64ビット値×2）
        let mut s0 = unsafe { vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block[0..16].as_ptr()))) };
        let mut s1 = unsafe { vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block[16..32].as_ptr()))) };
        let mut s2 = unsafe { vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block[32..48].as_ptr()))) };
        let mut s3 = unsafe { vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block[48..64].as_ptr()))) };
        let mut s4 = unsafe { vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block[64..80].as_ptr()))) };
        let mut s5 = unsafe { vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block[80..96].as_ptr()))) };
        let mut s6 = unsafe { vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block[96..112].as_ptr()))) };
        let mut s7 = unsafe { vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block[112..128].as_ptr()))) };

        // 以下、最初の 16ラウンド分の処理 (メッセージスケジュール生成前)
        
        // ラウンド 0-1
        let mut initial_sum = unsafe { vaddq_u64(s0, vld1q_u64(&K64[0])) };
        let mut sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh) };
        let mut intermed = unsafe { vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1)) };
        gh = unsafe { vsha512h2q_u64(intermed, cd, ab) };
        cd = unsafe { vaddq_u64(cd, intermed) };

        // ラウンド 2-3
        initial_sum = unsafe { vaddq_u64(s1, vld1q_u64(&K64[2])) };
        sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef) };
        intermed = unsafe { vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1)) };
        ef = unsafe { vsha512h2q_u64(intermed, ab, gh) };
        ab = unsafe { vaddq_u64(ab, intermed) };

        // ラウンド 4-5
        initial_sum = unsafe { vaddq_u64(s2, vld1q_u64(&K64[4])) };
        sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd) };
        intermed = unsafe { vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1)) };
        cd = unsafe { vsha512h2q_u64(intermed, gh, ef) };
        gh = unsafe { vaddq_u64(gh, intermed) };

        // ラウンド 6-7
        initial_sum = unsafe { vaddq_u64(s3, vld1q_u64(&K64[6])) };
        sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab) };
        intermed = unsafe { vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1)) };
        ab = unsafe { vsha512h2q_u64(intermed, ef, cd) };
        ef = unsafe { vaddq_u64(ef, intermed) };

        // ラウンド 8-9
        initial_sum = unsafe { vaddq_u64(s4, vld1q_u64(&K64[8])) };
        sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh) };
        intermed = unsafe { vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1)) };
        gh = unsafe { vsha512h2q_u64(intermed, cd, ab) };
        cd = unsafe { vaddq_u64(cd, intermed) };

        // ラウンド 10-11
        initial_sum = unsafe { vaddq_u64(s5, vld1q_u64(&K64[10])) };
        sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef) };
        intermed = unsafe { vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1)) };
        ef = unsafe { vsha512h2q_u64(intermed, ab, gh) };
        ab = unsafe { vaddq_u64(ab, intermed) };

        // ラウンド 12-13
        initial_sum = unsafe { vaddq_u64(s6, vld1q_u64(&K64[12])) };
        sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd) };
        intermed = unsafe { vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1)) };
        cd = unsafe { vsha512h2q_u64(intermed, gh, ef) };
        gh = unsafe { vaddq_u64(gh, intermed) };

        // ラウンド 14-15
        initial_sum = unsafe { vaddq_u64(s7, vld1q_u64(&K64[14])) };
        sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab) };
        intermed = unsafe { vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1)) };
        ab = unsafe { vsha512h2q_u64(intermed, ef, cd) };
        ef = unsafe { vaddq_u64(ef, intermed) };

        // 残りのラウンド (16から79まで、16ラウンドずつのループ)
        for t in (16..80).step_by(16) {
            // メッセージスケジュールの更新と並行してハッシュ計算を行う
            
            // ラウンド 16-17 (+t)
            s0 = unsafe { vsha512su1q_u64(vsha512su0q_u64(s0, s1), s7, vextq_u64(s4, s5, 1)) };
            initial_sum = unsafe { vaddq_u64(s0, vld1q_u64(&K64[t])) };
            sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh) };
            intermed = unsafe { vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1)) };
            gh = unsafe { vsha512h2q_u64(intermed, cd, ab) };
            cd = unsafe { vaddq_u64(cd, intermed) };

            // ラウンド 18-19 (+t)
            s1 = unsafe { vsha512su1q_u64(vsha512su0q_u64(s1, s2), s0, vextq_u64(s5, s6, 1)) };
            initial_sum = unsafe { vaddq_u64(s1, vld1q_u64(&K64[t + 2])) };
            sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef) };
            intermed = unsafe { vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1)) };
            ef = unsafe { vsha512h2q_u64(intermed, ab, gh) };
            ab = unsafe { vaddq_u64(ab, intermed) };

            // ラウンド 20-21 (+t)
            s2 = unsafe { vsha512su1q_u64(vsha512su0q_u64(s2, s3), s1, vextq_u64(s6, s7, 1)) };
            initial_sum = unsafe { vaddq_u64(s2, vld1q_u64(&K64[t + 4])) };
            sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd) };
            intermed = unsafe { vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1)) };
            cd = unsafe { vsha512h2q_u64(intermed, gh, ef) };
            gh = unsafe { vaddq_u64(gh, intermed) };

            // ラウンド 22-23 (+t)
            s3 = unsafe { vsha512su1q_u64(vsha512su0q_u64(s3, s4), s2, vextq_u64(s7, s0, 1)) };
            initial_sum = unsafe { vaddq_u64(s3, vld1q_u64(&K64[t + 6])) };
            sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab) };
            intermed = unsafe { vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1)) };
            ab = unsafe { vsha512h2q_u64(intermed, ef, cd) };
            ef = unsafe { vaddq_u64(ef, intermed) };

            // ラウンド 24-25 (+t)
            s4 = unsafe { vsha512su1q_u64(vsha512su0q_u64(s4, s5), s3, vextq_u64(s0, s1, 1)) };
            initial_sum = unsafe { vaddq_u64(s4, vld1q_u64(&K64[t + 8])) };
            sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh) };
            intermed = unsafe { vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1)) };
            gh = unsafe { vsha512h2q_u64(intermed, cd, ab) };
            cd = unsafe { vaddq_u64(cd, intermed) };

            // ラウンド 26-27 (+t)
            s5 = unsafe { vsha512su1q_u64(vsha512su0q_u64(s5, s6), s4, vextq_u64(s1, s2, 1)) };
            initial_sum = unsafe { vaddq_u64(s5, vld1q_u64(&K64[t + 10])) };
            sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef) };
            intermed = unsafe { vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1)) };
            ef = unsafe { vsha512h2q_u64(intermed, ab, gh) };
            ab = unsafe { vaddq_u64(ab, intermed) };

            // ラウンド 28-29 (+t)
            s6 = unsafe { vsha512su1q_u64(vsha512su0q_u64(s6, s7), s5, vextq_u64(s2, s3, 1)) };
            initial_sum = unsafe { vaddq_u64(s6, vld1q_u64(&K64[t + 12])) };
            sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd) };
            intermed = unsafe { vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1)) };
            cd = unsafe { vsha512h2q_u64(intermed, gh, ef) };
            gh = unsafe { vaddq_u64(gh, intermed) };

            // ラウンド 30-31 (+t)
            s7 = unsafe { vsha512su1q_u64(vsha512su0q_u64(s7, s0), s6, vextq_u64(s3, s4, 1)) };
            initial_sum = unsafe { vaddq_u64(s7, vld1q_u64(&K64[t + 14])) };
            sum = unsafe { vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab) };
            intermed = unsafe { vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1)) };
            ab = unsafe { vsha512h2q_u64(intermed, ef, cd) };
            ef = unsafe { vaddq_u64(ef, intermed) };
        }

        // 計算結果をブロック前のハッシュ状態に加算 (Davies-Meyer構造)
        ab = unsafe { vaddq_u64(ab, ab_orig) };
        cd = unsafe { vaddq_u64(cd, cd_orig) };
        ef = unsafe { vaddq_u64(ef, ef_orig) };
        gh = unsafe { vaddq_u64(gh, gh_orig) };
    }

    // 更新されたレジスタ値をメモリ上の状態配列に書き戻す
    unsafe {
        vst1q_u64(state[0..2].as_mut_ptr(), ab);
        vst1q_u64(state[2..4].as_mut_ptr(), cd);
        vst1q_u64(state[4..6].as_mut_ptr(), ef);
        vst1q_u64(state[6..8].as_mut_ptr(), gh);
    }
}

// ハッシュ状態（8個のu64）を16進数で表示する補助関数
fn print_state(label: &str, state: &[u64; 8]) {
    println!("{}:", label);
    for (i, &val) in state.iter().enumerate() {
        println!("  {:016x}", val);
    }
}

fn main() {

    println!("=== SHA-512 AArch64実装 ===\n");
    
    // 実行CPUがSHA3拡張（SHA-512高速化命令を含む）をサポートしているかチェック
    if !std::arch::is_aarch64_feature_detected!("sha3") {
        println!("エラー: このCPUではSHA3ハードウェアアクセラレーションが利用できません");
        return;
    }
    
    // SHA-512の標準初期ハッシュ値 (H0-H7)
    let initial_state: [u64; 8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];
    
    // テスト用の128バイトデータブロック (メッセージ "abc" をパディングしたもの)
    let block: [u8; 128] = [
        0x61, 0x62, 0x63, 0x80, 0x00, 0x00, 0x00, 0x00,
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
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
    ];

    // 初期状態表示
    print_state("初期状態", &initial_state);
    println!();

    // 動作確認のため、最初の1回だけ実行して結果を表示
    let mut state = initial_state;
    let start = Instant::now();
    unsafe { sha512_compress_hw(black_box(&mut state), black_box(&[block])); }
    let elapsed = start.elapsed();
    
    print_state("最終状態", &state);
    println!();
    println!("実行時間: {:.10}秒", elapsed.as_secs_f64());
    println!();



const ITERATIONS: usize = 10_000_000;

// 空回し (ウォームアップ) ---
println!("CPUウォームアップ中（{}回）...", ITERATIONS);
let mut warmup_state = initial_state;
let warmup_data = [block];
for i in 0..ITERATIONS {
    unsafe {
        sha512_compress_hw(black_box(&mut warmup_state), black_box(&warmup_data));
    }
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
    let data = [block];
    let start = Instant::now();

    for j in 0..ITERATIONS_2 {
         // 最適化で消されないよう black_box を介して実行
        unsafe {
            sha512_compress_hw(black_box(&mut state), black_box(&data));
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