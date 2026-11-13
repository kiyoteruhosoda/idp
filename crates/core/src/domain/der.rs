//! A small read-only DER (ASN.1 encoding rules) reader (task #892. Key Attestation certificate chains).
//!
//! Holds only what is needed to read certificates and the Android Key Attestation extension (`KeyDescription`):
//! slicing out type, length and contents (TLV), context tags (`[n]`, including numbers 31 and above), integers, booleans, object identifiers.
//! No writer. Only definite lengths (DER does not allow indefinite lengths).

/// Kind (class) of a type tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

/// One element (type, length, contents). `raw` is the whole thing including tag and length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerElement<'a> {
    pub class: TagClass,
    pub constructed: bool,
    pub number: u32,
    pub contents: &'a [u8],
    pub raw: &'a [u8],
}

/// Could not be read (malformed or truncated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerError;

pub const TAG_BOOLEAN: u32 = 1;
pub const TAG_INTEGER: u32 = 2;
pub const TAG_BIT_STRING: u32 = 3;
pub const TAG_OCTET_STRING: u32 = 4;
pub const TAG_NULL: u32 = 5;
pub const TAG_OID: u32 = 6;
pub const TAG_ENUMERATED: u32 = 10;
pub const TAG_SEQUENCE: u32 = 16;
pub const TAG_SET: u32 = 17;

/// Length limit (even a single certificate is a few KB. Anything too large is not read).
const MAX_LEN: usize = 64 * 1024;

/// A reader that reads elements in order.
#[derive(Debug, Clone)]
pub struct DerReader<'a> {
    rest: &'a [u8],
}

impl<'a> DerReader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { rest: input }
    }

    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// Reads the next element.
    pub fn next_element(&mut self) -> Result<DerElement<'a>, DerError> {
        let input = self.rest;
        let (&first, mut cursor) = input.split_first().ok_or(DerError)?;
        let class = match first >> 6 {
            0 => TagClass::Universal,
            1 => TagClass::Application,
            2 => TagClass::ContextSpecific,
            _ => TagClass::Private,
        };
        let constructed = first & 0x20 != 0;
        let mut number = u32::from(first & 0x1f);
        if number == 0x1f {
            // Numbers 31 and above: 7 bits at a time, with the high bit 0 only on the last byte.
            number = 0;
            loop {
                let (&b, rest) = cursor.split_first().ok_or(DerError)?;
                cursor = rest;
                if number > (u32::MAX >> 7) {
                    return Err(DerError);
                }
                number = (number << 7) | u32::from(b & 0x7f);
                if b & 0x80 == 0 {
                    break;
                }
            }
        }
        let (&len_byte, rest) = cursor.split_first().ok_or(DerError)?;
        cursor = rest;
        let len = if len_byte & 0x80 == 0 {
            usize::from(len_byte)
        } else {
            let count = usize::from(len_byte & 0x7f);
            if count == 0 || count > 3 || cursor.len() < count {
                return Err(DerError);
            }
            let mut len = 0usize;
            for &b in &cursor[..count] {
                len = (len << 8) | usize::from(b);
            }
            cursor = &cursor[count..];
            len
        };
        if len > MAX_LEN || cursor.len() < len {
            return Err(DerError);
        }
        let header_len = input.len() - cursor.len();
        let contents = &cursor[..len];
        let raw = &input[..header_len + len];
        self.rest = &cursor[len..];
        Ok(DerElement {
            class,
            constructed,
            number,
            contents,
            raw,
        })
    }

    /// Reads the next element after checking it is the universal type `number`.
    pub fn expect(&mut self, number: u32) -> Result<DerElement<'a>, DerError> {
        let element = self.next_element()?;
        if element.class != TagClass::Universal || element.number != number {
            return Err(DerError);
        }
        Ok(element)
    }

    /// Reads the next element if it is the context tag `[number]`; otherwise does not read and returns `None`.
    pub fn optional_context(&mut self, number: u32) -> Result<Option<DerElement<'a>>, DerError> {
        let mut peek = self.clone();
        match peek.next_element() {
            Ok(e) if e.class == TagClass::ContextSpecific && e.number == number => {
                *self = peek;
                Ok(Some(e))
            }
            Ok(_) => Ok(None),
            Err(_) if self.rest.is_empty() => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl<'a> DerElement<'a> {
    /// Reads the contents as a sequence of elements (SEQUENCE, SET, explicit tag).
    pub fn children(&self) -> DerReader<'a> {
        DerReader::new(self.contents)
    }

    /// A non-negative integer (one that fits in u64).
    pub fn unsigned(&self) -> Result<u64, DerError> {
        let bytes = self.contents;
        if bytes.is_empty() || bytes[0] & 0x80 != 0 {
            return Err(DerError);
        }
        let bytes = if bytes[0] == 0 { &bytes[1..] } else { bytes };
        if bytes.len() > 8 {
            return Err(DerError);
        }
        Ok(bytes.iter().fold(0u64, |n, &b| (n << 8) | u64::from(b)))
    }

    pub fn boolean(&self) -> Result<bool, DerError> {
        match self.contents {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(DerError),
        }
    }

    /// Contents of a BIT STRING (only when the number of unused bits is 0).
    pub fn bit_string_bytes(&self) -> Result<&'a [u8], DerError> {
        match self.contents.split_first() {
            Some((0, bytes)) => Ok(bytes),
            _ => Err(DerError),
        }
    }

    /// Formats an object identifier as `1.2.840…`.
    pub fn oid(&self) -> Result<String, DerError> {
        let bytes = self.contents;
        let (&first, rest) = bytes.split_first().ok_or(DerError)?;
        let mut parts = vec![u64::from(first / 40).min(2), 0];
        parts[1] = u64::from(first) - parts[0] * 40;
        let mut value = 0u64;
        let mut pending = false;
        for &b in rest {
            if value > (u64::MAX >> 7) {
                return Err(DerError);
            }
            value = (value << 7) | u64::from(b & 0x7f);
            pending = true;
            if b & 0x80 == 0 {
                parts.push(value);
                value = 0;
                pending = false;
            }
        }
        if pending {
            return Err(DerError);
        }
        Ok(parts
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."))
    }
}

/// Reads `input` after checking it is exactly one element.
pub fn single(input: &[u8]) -> Result<DerElement<'_>, DerError> {
    let mut reader = DerReader::new(input);
    let element = reader.next_element()?;
    if !reader.is_empty() {
        return Err(DerError);
    }
    Ok(element)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_short_and_long_lengths() {
        let mut long = vec![0x04, 0x81, 200];
        long.extend(std::iter::repeat_n(7u8, 200));
        let e = single(&long).unwrap();
        assert_eq!(e.number, TAG_OCTET_STRING);
        assert_eq!(e.contents.len(), 200);
        assert_eq!(e.raw.len(), 203);
    }

    #[test]
    fn reads_high_tag_numbers() {
        // An OCTET STRING wrapped in [709] EXPLICIT (0xBF 0x85 0x45).
        let input = [0xbf, 0x85, 0x45, 0x03, 0x04, 0x01, 0xaa];
        let e = single(&input).unwrap();
        assert_eq!(e.class, TagClass::ContextSpecific);
        assert!(e.constructed);
        assert_eq!(e.number, 709);
        let inner = e.children().expect(TAG_OCTET_STRING).unwrap();
        assert_eq!(inner.contents, &[0xaa]);
    }

    #[test]
    fn reads_oids_and_integers() {
        // 1.3.6.1.4.1.11129.2.1.17
        let oid = [
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11,
        ];
        assert_eq!(
            single(&oid).unwrap().oid().unwrap(),
            "1.3.6.1.4.1.11129.2.1.17"
        );
        assert_eq!(
            single(&[0x02, 0x02, 0x00, 0xff]).unwrap().unsigned(),
            Ok(255)
        );
        assert_eq!(
            single(&[0x02, 0x01, 0x80]).unwrap().unsigned(),
            Err(DerError)
        );
    }

    #[test]
    fn refuses_truncated_and_trailing_input() {
        assert_eq!(single(&[0x04, 0x05, 0x01]), Err(DerError));
        assert_eq!(single(&[0x05, 0x00, 0x05, 0x00]), Err(DerError));
        assert_eq!(single(&[0x04, 0x80]), Err(DerError));
    }

    #[test]
    fn optional_context_leaves_other_elements() {
        let input = [0x02, 0x01, 0x01];
        let mut reader = DerReader::new(&input);
        assert_eq!(reader.optional_context(0).unwrap(), None);
        assert_eq!(reader.expect(TAG_INTEGER).unwrap().unsigned(), Ok(1));
    }
}
