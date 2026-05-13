use bytes::Bytes;
use rand::Rng;
use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

/// 32字节的正整数ID (256位)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id32 {
    bytes: [u8; 32],
}

impl Id32 {
    /// 创建一个全零的ID
    pub fn zero() -> Self {
        Self { bytes: [0; 32] }
    }

    /// 从字节数组创建
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// 获取字节数组的引用
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Bytes {
        Bytes::from(self.bytes.to_vec())
    }

    /// 从u64创建（小端序）
    pub fn from_u64(val: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&val.to_le_bytes());
        Self { bytes }
    }

    /// 从u128创建（小端序）
    pub fn from_u128(val: u128) -> Self {
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&val.to_le_bytes());
        Self { bytes }
    }

    /// 转换为u64（仅低64位）
    pub fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.bytes[..8].try_into().unwrap())
    }

    /// 转换为u128（仅低128位）
    pub fn to_u128(&self) -> u128 {
        u128::from_le_bytes(self.bytes[..16].try_into().unwrap())
    }

    /// 递增ID（返回新ID）
    pub fn increment(self) -> Self {
        let mut bytes = self.bytes;
        let mut carry = 1u16;

        for byte in bytes.iter_mut() {
            let sum = *byte as u16 + carry;
            *byte = sum as u8;
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }

        Self { bytes }
    }

    /// 检查是否为零
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    /// 基于时间戳创建ID（纳秒级）
    /// 前16字节：纳秒级时间戳
    /// 后16字节：随机数（如果启用rand feature）或全零
    pub fn from_timestamp() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos();

        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&timestamp.to_le_bytes());

        let mut rng = rand::thread_rng();
        rng.fill(&mut bytes[16..]);

        Self { bytes }
    }

    /// 基于时间戳创建ID（纯时间戳版本，后16字节为零）
    pub fn from_timestamp_pure() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos();

        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&timestamp.to_le_bytes());

        Self { bytes }
    }

    /// 基于时间戳和计数器创建ID
    pub fn from_timestamp_with_counter(counter: u128) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos();

        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&timestamp.to_le_bytes());
        bytes[16..].copy_from_slice(&counter.to_le_bytes());

        Self { bytes }
    }

    pub fn random() -> Self {
        let mut bytes = [0; 32];
        rand::thread_rng().fill(&mut bytes);
        Self { bytes }
    }

    /// 提取时间戳（如果ID是基于时间戳创建的）
    pub fn extract_timestamp(&self) -> u128 {
        u128::from_le_bytes(self.bytes[..16].try_into().unwrap())
    }

    /// 提取计数器（如果ID是基于时间戳+计数器创建的）
    pub fn extract_counter(&self) -> u128 {
        u128::from_le_bytes(self.bytes[16..].try_into().unwrap())
    }
}

impl Default for Id32 {
    fn default() -> Self {
        Self::zero()
    }
}

impl fmt::LowerHex for Id32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        for byte in self.bytes.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Id32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        for byte in self.bytes.iter() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Display for Id32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl From<[u8; 32]> for Id32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<Id32> for [u8; 32] {
    fn from(id: Id32) -> Self {
        id.bytes
    }
}

impl From<u64> for Id32 {
    fn from(val: u64) -> Self {
        Self::from_u64(val)
    }
}

impl From<u128> for Id32 {
    fn from(val: u128) -> Self {
        Self::from_u128(val)
    }
}

impl FromStr for Id32 {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let s = s.strip_prefix("0X").unwrap_or(s);

        // 补零到64字符
        let s = format!("{:0>64}", s);

        let mut bytes = [0; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
        }

        Ok(Self::from_bytes(bytes))
    }
}

impl std::ops::Add for Id32 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut bytes = [0; 32];
        let mut carry = 0u16;

        for i in (0..32).rev() {
            let sum = self.bytes[i] as u16 + rhs.bytes[i] as u16 + carry;
            bytes[i] = sum as u8;
            carry = sum >> 8;
        }

        Self { bytes }
    }
}

impl std::ops::AddAssign for Id32 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

pub struct TimestampIdGenerator {
    counter: u64,        // 8字节计数器
    last_timestamp: u64, // 上次生成ID的时间戳（微秒）
}

impl TimestampIdGenerator {
    pub fn new() -> Self {
        Self {
            counter: 0,
            last_timestamp: 0,
        }
    }

    pub fn next_id(&mut self) -> Id32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_micros() as u64; // 微秒级时间戳，8字节足够用到公元5855年

        // 时间回拨处理（可选策略：阻塞等待或直接递增计数器）
        if now == self.last_timestamp {
            self.counter += 1;
        } else {
            self.counter = 0;
            self.last_timestamp = now;
        }

        // 生成16字节随机数
        let mut random_bytes = [0; 16];
        rand::thread_rng().fill(&mut random_bytes);

        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&now.to_le_bytes()); // 8字节时间戳
        bytes[8..16].copy_from_slice(&self.counter.to_le_bytes()); // 8字节计数器
        bytes[16..].copy_from_slice(&random_bytes); // 16字节随机数

        Id32 { bytes }
    }
}

impl Default for TimestampIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}
