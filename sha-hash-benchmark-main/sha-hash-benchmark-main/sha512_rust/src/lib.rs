// Rust用 SHA-512 ARMアセンブリ実装

/// SHA-512の状態を保持する構造体（64ビットワード × 8本）
/// メッセージダイジェストの途中経過や最終結果（H0〜H7）を格納します。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sha512State {
    pub h: [u64; 8],
}

impl Sha512State {
    /// SHA-512の標準初期化ベクトル（IV）で初期状態を生成します。
    /// これらの定数は、最初の8個の素数の平方根の小数部分から派生しています。
    pub fn new() -> Self {
        Self {
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
        }
    }
}

/// SHA-512の各ラウンドで使用される80個の定数K
/// 最初の80個の素数の3乗根の小数部分に基づいています。
const K: [u64; 80] = [
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

/// インラインアセンブリを使用したSHA-512変換関数
/// 
/// 1回につき128バイト（1024ビット）のブロックを処理します。
#[cfg(target_arch = "arm")]
pub unsafe fn sha512_transform_arm(state: &mut Sha512State, data: &[u8; 128]) {
    // 注: 現時点ではアセンブリのプレースホルダとして汎用実装を呼び出しています。
    // 本来はここにlibgcryptから移植した最適化済みARMアセンブリを記述します。
    
    sha512_transform_generic(state, data);
}

/// 非ARM環境向けの公開エクスポート（テスト等の互換性用）
#[cfg(not(target_arch = "arm"))]
pub fn sha512_transform_arm(state: &mut Sha512State, data: &[u8; 128]) {
    sha512_transform_generic(state, data);
}

/// 汎用（Generic）SHA-512変換処理（アセンブリを使用しないフォールバック実装）
pub fn sha512_transform_generic(state: &mut Sha512State, data: &[u8; 128]) {
    // 80個の64ビット語からなるメッセージスケジュール
    let mut w = [0u64; 80];
    
    // --- メッセージスケジュールの準備 ---
    // 最初の16語を入力データから生成（ビッグエンディアンとして読み込み）
    for i in 0..16 {
        w[i] = u64::from_be_bytes([
            data[i * 8],
            data[i * 8 + 1],
            data[i * 8 + 2],
            data[i * 8 + 3],
            data[i * 8 + 4],
            data[i * 8 + 5],
            data[i * 8 + 6],
            data[i * 8 + 7],
        ]);
    }
    
    // 残りの64語を既存のスケジュールから計算して拡張
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    
    // 圧縮関数のための作業変数を現在の状態から初期化
    let mut a = state.h[0];
    let mut b = state.h[1];
    let mut c = state.h[2];
    let mut d = state.h[3];
    let mut e = state.h[4];
    let mut f = state.h[5];
    let mut g = state.h[6];
    let mut h = state.h[7];
    
    // --- メインループ（80ラウンドの撹拌処理） ---
    for i in 0..80 {
        // e, f, gを使用したCh（選択）関数とS1関数
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        
        // a, b, cを使用したMaj（多数決）関数とS0関数
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
        
        // 変数の更新（レジスタを1つずつシフトさせる）
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    
    // 計算された値を現在のハッシュ状態に加算（ラッピング加算を使用）
    state.h[0] = state.h[0].wrapping_add(a);
    state.h[1] = state.h[1].wrapping_add(b);
    state.h[2] = state.h[2].wrapping_add(c);
    state.h[3] = state.h[3].wrapping_add(d);
    state.h[4] = state.h[4].wrapping_add(e);
    state.h[5] = state.h[5].wrapping_add(f);
    state.h[6] = state.h[6].wrapping_add(g);
    state.h[7] = state.h[7].wrapping_add(h);
}

/// 完全なハッシュ値を算出するためのSHA-512コンテキスト
pub struct Sha512 {
    state: Sha512State,    // 現在のハッシュ状態
    buffer: [u8; 128],     // 未処理データを一時保持するバッファ
    buffer_len: usize,     // バッファ内のデータ長
    total_len: u128,       // これまでに処理したデータの総バイト長
}

impl Sha512 {
    /// 新しいSHA-512コンテキストを初期状態で作成します。
    pub fn new() -> Self {
        Self {
            state: Sha512State::new(),
            buffer: [0; 128],
            buffer_len: 0,
            total_len: 0,
        }
    }
    
    /// 任意の長さのデータを受け取り、内部状態を更新します。
    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;
        self.total_len += data.len() as u128;
        
        // すでにバッファにデータがある場合、まずはそこを埋める
        if self.buffer_len > 0 {
            let to_copy = (128 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            pos = to_copy;
            
            // バッファが1ブロック分（128バイト）埋まったら変換実行
            if self.buffer_len == 128 {
                sha512_transform_generic(&mut self.state, &self.buffer);
                self.buffer_len = 0;
            }
        }
        
        // 128バイト単位の完全なブロックを直接処理（高速化）
        while pos + 128 <= data.len() {
            let mut block = [0u8; 128];
            block.copy_from_slice(&data[pos..pos + 128]);
            sha512_transform_generic(&mut self.state, &block);
            pos += 128;
        }
        
        // 1ブロックに満たない残りのデータをバッファに格納
        if pos < data.len() {
            let remaining = data.len() - pos;
            self.buffer[..remaining].copy_from_slice(&data[pos..]);
            self.buffer_len = remaining;
        }
    }
    
    /// パディング処理を施し、最終的な64バイトのハッシュ値を返します。
    pub fn finalize(mut self) -> [u8; 64] {
        let bit_len = self.total_len * 8;
        
        // --- パディングの開始 ---
        // 最初のビットとして 0x80 (10000000) を追加
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        
        // 長さ情報を書き込むスペース（16バイト）がない場合、一旦現在のブロックを処理
        if self.buffer_len > 112 {
            while self.buffer_len < 128 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            sha512_transform_generic(&mut self.state, &self.buffer);
            self.buffer_len = 0;
        }
        
        // 長さ情報の直前まで0で埋める
        while self.buffer_len < 112 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }
        
        // 最後の128ビット（16バイト）に、データの総ビット長（ビッグエンディアン）を書き込む
        self.buffer[112..128].copy_from_slice(&bit_len.to_be_bytes());
        sha512_transform_generic(&mut self.state, &self.buffer);
        
        // --- 最終ハッシュ値の出力 ---
        // 内部状態（8個のu64）をバイト配列に変換
        let mut result = [0u8; 64];
        for i in 0..8 {
            result[i * 8..(i + 1) * 8].copy_from_slice(&self.state.h[i].to_be_bytes());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // 空文字 "" のSHA-512期待値テスト
    #[test]
    fn test_sha512_empty() {
        let mut hasher = Sha512::new();
        hasher.update(b"");

        let result = hasher.finalize();
        
        let expected = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
            0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
            0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
            0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
            0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
            0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
            0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        
        assert_eq!(result, expected);
    }
    
    // 文字列 "abc" のSHA-512期待値テスト
    #[test]
    fn test_sha512_abc() {
        let mut hasher = Sha512::new();
        hasher.update(b"abc");
        let result = hasher.finalize();
        
        let expected = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
            0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
            0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
            0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
            0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
            0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
            0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];
        
        assert_eq!(result, expected);
    }
}