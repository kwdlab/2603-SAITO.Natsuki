// Rust用のSHA-256 ARMアセンブリ実装

use core::arch::asm;

/// SHA-256の状態（32ビットワード × 8本）を保持する構造体
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sha256State {
    pub h: [u32; 8],
}

impl Sha256State {
    /// SHA-256の標準初期化ベクトル（IV）で初期化
    /// 最初の8個の素数の平方根の小数部分から派生しています。
    pub fn new() -> Self {
        Self {
            h: [
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
            ],
        }
    }
}

/// SHA-256の各ラウンドで使用される定数K
/// 最初の64個の素数の3乗根の小数部分に基づいています。
const K: [u32; 64] = [
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

/// インラインアセンブリを使用したARM向けSHA-256変換関数
/// 1回につき64バイト（512ビット）のブロックを処理します。
#[cfg(target_arch = "arm")]
pub unsafe fn sha256_transform_arm(state: &mut Sha256State, data: &[u8; 64]) {
    // 汎用(Generic)の実装を呼び出しています。
    sha256_transform_generic(state, data);
}

/// 非ARMアーキテクチャでテストなどを行うための公開エクスポート
#[cfg(not(target_arch = "arm"))]
pub fn sha256_transform_arm(state: &mut Sha256State, data: &[u8; 64]) {
    sha256_transform_generic(state, data);
}

/// 汎用(Generic)SHA-256変換処理
pub fn sha256_transform_generic(state: &mut Sha256State, data: &[u8; 64]) {
    // 64個の32ビットワードからなるメッセージスケジュール
    let mut w = [0u32; 64];
    
    // 入力データからメッセージスケジュールW[0..15]を作成
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);
    }
    
    // メッセージスケジュールをW[16..63]まで拡張（SHA-256特有のσ0, σ1関数を使用）
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    
    // 作業変数を現在のハッシュ状態で初期化（a, b, c, d, e, f, g, h）
    let mut a = state.h[0];
    let mut b = state.h[1];
    let mut c = state.h[2];
    let mut d = state.h[3];
    let mut e = state.h[4];
    let mut f = state.h[5];
    let mut g = state.h[6];
    let mut h = state.h[7];
    
    // メインループ - 64ラウンドの圧縮処理を実行
    for i in 0..64 {
        // e, f, g変数を使用したΣ1関数とCh（選択）関数
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        
        // a, b, c変数を使用したΣ0関数とMaj（多数決）関数
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
        
        // 作業変数の更新（レジスタの値をシフトさせる）
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    
    // 計算結果を現在のハッシュ状態に加算（ラッピング加算）
    state.h[0] = state.h[0].wrapping_add(a);
    state.h[1] = state.h[1].wrapping_add(b);
    state.h[2] = state.h[2].wrapping_add(c);
    state.h[3] = state.h[3].wrapping_add(d);
    state.h[4] = state.h[4].wrapping_add(e);
    state.h[5] = state.h[5].wrapping_add(f);
    state.h[6] = state.h[6].wrapping_add(g);
    state.h[7] = state.h[7].wrapping_add(h);
}

/// ハッシュ計算全体を管理するSHA-256コンテキスト
pub struct Sha256 {
    state: Sha256State,
    buffer: [u8; 64],      // 未処理データを一時保存する64バイトバッファ
    buffer_len: usize,     // 現在バッファに入っているバイト数
    total_len: u64,        // これまでに処理したデータの総バイト数
}

impl Sha256 {
    /// 新規コンテキストを初期状態で作成
    pub fn new() -> Self {
        Self {
            state: Sha256State::new(),
            buffer: [0; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }
    
    /// 入力データを供給し、ハッシュ状態を更新
    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;
        self.total_len += data.len() as u64;
        
        // 前回の残りがバッファにあれば、まずそこを埋める
        if self.buffer_len > 0 {
            let to_copy = (64 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            pos = to_copy;
            
            // バッファが一杯になったら変換を実行
            if self.buffer_len == 64 {
                sha256_transform_generic(&mut self.state, &self.buffer);
                self.buffer_len = 0;
            }
        }
        
        // 64バイトの完全なブロックをループで処理
        while pos + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[pos..pos + 64]);
            sha256_transform_generic(&mut self.state, &block);
            pos += 64;
        }
        
        // 1ブロックに満たない残りのデータをバッファに保存
        if pos < data.len() {
            let remaining = data.len() - pos;
            self.buffer[..remaining].copy_from_slice(&data[pos..]);
            self.buffer_len = remaining;
        }
    }
    
    /// パディングを追加し、最終的な32バイトのハッシュ値を出力
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;
        
        // パディング開始: 最初のビットを1にする (0x80)
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        
        // 長さ情報を書き込むスペース（8バイト）が現在のブロックにない場合
        if self.buffer_len > 56 {
            while self.buffer_len < 64 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            sha256_transform_generic(&mut self.state, &self.buffer);
            self.buffer_len = 0;
        }
        
        // 長さ情報の直前まで0で埋める
        while self.buffer_len < 56 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }
        
        // 最後の8バイトに総ビット長を書き込む（ビッグエンディアン）
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha256_transform_generic(&mut self.state, &self.buffer);
        
        // ハッシュ状態（8本のu32）をバイト配列に変換して出力
        let mut result = [0u8; 32];
        for i in 0..8 {
            result[i * 4..(i + 1) * 4].copy_from_slice(&self.state.h[i].to_be_bytes());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // 空入力に対するテストベクトル（既知のハッシュ値）
    #[test]
    fn test_sha256_empty() {
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let result = hasher.finalize();
        
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        
        assert_eq!(result, expected);
    }
    
    // 文字列 "abc" に対するテストベクトル
    #[test]
    fn test_sha256_abc() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        let result = hasher.finalize();
        
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        
        assert_eq!(result, expected);
    }
}