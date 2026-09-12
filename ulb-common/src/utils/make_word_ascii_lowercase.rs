use core::mem::size_of;

const ASCII_HIGH: u64 = u64::from_ne_bytes([0x80; size_of::<u64>()]); // 10000000...
const ASCII_7BIT: u64 = u64::from_ne_bytes([0x7f; size_of::<u64>()]); // 01111111...
const ASCII_GE_A: u64 = u64::from_ne_bytes([0x3f; size_of::<u64>()]); // 00111111...
const ASCII_LE_Z: u64 = u64::from_ne_bytes([0x25; size_of::<u64>()]); // 00100101...

/// Lowercases ASCII uppercase characters in the provided 8-byte word.
///
/// # The SWAR Voodoo
///
/// 1. Clear the 8th bit of every byte to prevent addition carry-over and set
///    MSB for bytes >= `A` (`01000001`):
///
/// ```ignore
/// mask = word & 01111111...
/// ge_a = mask + 00111111...
/// ```
///
/// 2. Clear MSB for bytes <= `Z` and set for bytes > `Z` (`01011010`):
///
/// ```ignore
/// le_z = mask + 00100101...
/// ```
///
/// 3. Set MSB for bytes in the range `A`..=`Z` and ensure the original MSB was
///    `0`:
///
/// ```ignore
/// value = ge_a & !le_z & !word & 10000000...
/// ```
///
/// 4. Right shift 2-bits (converting `0x80` to `0x20`) and `OR` with the word
///    for lowercase:
///
/// ```ignore
/// *word |= (value >> 2)
/// ```
#[inline(always)]
pub fn make_word_ascii_lowercase(word: &mut u64) {
    let masked = *word & ASCII_7BIT;
    let ge_a = masked.wrapping_add(ASCII_GE_A);
    let le_z = masked.wrapping_add(ASCII_LE_Z);
    *word |= (ge_a & !le_z & !*word & ASCII_HIGH) >> 2;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn makes_word_lowercase() {
        let cases = [
            // all upper/lower
            (b"ABCDEFGH", b"abcdefgh"),
            (b"abcdefgh", b"abcdefgh"),
            // mixed
            (b"A!b@Z[0\0", b"a!b@z[0\0"),
            // outside A-Z
            (b"        ", b"        "),
            (b"12345678", b"12345678"),
            // ascii boundaries
            (b"@AZ[\\`az", b"@az[\\`az"),
            // non-ascii
            (
                b"\xFF\x00\x7F\x80\x41\x5A\x40\x5B",
                b"\xFF\x00\x7F\x80\x61\x7A\x40\x5B",
            ),
            // uppercase at every byte
            (b"Axxxxxxx", b"axxxxxxx"),
            (b"xAxxxxxx", b"xaxxxxxx"),
            (b"xxAxxxxx", b"xxaxxxxx"),
            (b"xxxAxxxx", b"xxxaxxxx"),
            (b"xxxxAxxx", b"xxxxaxxx"),
            (b"xxxxxAxx", b"xxxxxaxx"),
            (b"xxxxxxAx", b"xxxxxxax"),
            (b"xxxxxxxA", b"xxxxxxxa"),
        ];

        for (input, expected) in cases {
            let mut word = u64::from_ne_bytes(*input);
            make_word_ascii_lowercase(&mut word);
            assert_eq!(word.to_ne_bytes(), *expected);
        }
    }

    #[test]
    fn makes_all_byte_values_lowercase() {
        for byte in 0..=u8::MAX {
            // isolated byte at every pos
            for pos in 0..8 {
                let mut input = [0u8; 8];
                input[pos] = byte;
                let mut expected = input;
                expected[pos] = byte.to_ascii_lowercase();
                let mut word = u64::from_ne_bytes(input);
                make_word_ascii_lowercase(&mut word);
                assert_eq!(word.to_ne_bytes(), expected,);
            }

            // flood with byte
            let input = [byte; 8];
            let mut expected = input;
            for c in &mut expected {
                c.make_ascii_lowercase();
            }

            let mut word = u64::from_ne_bytes(input);
            make_word_ascii_lowercase(&mut word);
            assert_eq!(word.to_ne_bytes(), expected,);
        }
    }
}
