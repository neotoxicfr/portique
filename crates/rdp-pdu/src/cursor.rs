//! Lecture bornée d'un tampon : aucune lecture ne déborde, tout manque est une erreur.

use crate::Error;

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    pub fn bytes(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.buf.len()).ok_or(Error::Truncated(what))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn skip(&mut self, n: usize, what: &'static str) -> Result<(), Error> {
        self.bytes(n, what).map(|_| ())
    }

    pub fn u8(&mut self, what: &'static str) -> Result<u8, Error> {
        Ok(self.bytes(1, what)?[0])
    }

    pub fn u16_le(&mut self, what: &'static str) -> Result<u16, Error> {
        let b = self.bytes(2, what)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u16_be(&mut self, what: &'static str) -> Result<u16, Error> {
        let b = self.bytes(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32_le(&mut self, what: &'static str) -> Result<u32, Error> {
        let b = self.bytes(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}
