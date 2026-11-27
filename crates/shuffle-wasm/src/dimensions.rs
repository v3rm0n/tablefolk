pub const MAX_CARDS: usize = 128;

#[derive(Clone, Copy)]
pub struct Dimensions {
    rows: usize,
    columns: usize,
}

impl Dimensions {
    pub fn new(rows: usize, columns: usize) -> Result<Self, String> {
        if rows < 2 || columns < 2 || rows > MAX_CARDS / columns {
            return Err("Invalid shuffle dimensions".into());
        }
        Ok(Self { rows, columns })
    }

    pub fn rows(self) -> usize {
        self.rows
    }
    pub fn columns(self) -> usize {
        self.columns
    }
    pub fn card_count(self) -> usize {
        self.rows * self.columns
    }
}

// All profile integers and lengths using this helper are bounded by u16::MAX.
pub fn cbor_head(output: &mut Vec<u8>, major: u8, value: usize) {
    match value {
        0..=23 => output.push(major | value as u8),
        24..=255 => output.extend_from_slice(&[major | 24, value as u8]),
        _ => {
            output.push(major | 25);
            output.extend_from_slice(
                &u16::try_from(value)
                    .expect("Bounded CBOR field")
                    .to_be_bytes(),
            );
        }
    }
}
