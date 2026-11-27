

pub struct MxN {
    // TODO:  We should change these usize to u32 maybe.
    pub m: usize,
    pub n: usize,
}

impl From<(usize,usize)> for MxN {
    fn from((m: usize, n: usize)) -> MxN { MxN {m,n} }
}

impl MxN {
    pub fn transcript_append(&self, t: &mut crate::Transcript) {
        let m = self.m as u32;
        t.append(&m);
        let n = self.n as u32;
        t.append(&n);
    }
}


