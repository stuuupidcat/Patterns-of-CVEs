# CVEs

## CVE-2017-1000430

### Information

- MITRE: [CVE-2017-1000430](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000430).
- NVD: [CVE-2017-1000430](https://nvd.nist.gov/vuln/detail/CVE-2017-1000430).
- Repository: [rust-base64](https://github.com/marshallpierce/rust-base64).
- Issue: [encoded_size fixes](https://github.com/marshallpierce/rust-base64/issues/28).
- Commit SHA: [21a9389](https://github.com/marshallpierce/rust-base64/tree/21a9389) (before) -> [24ead98](https://github.com/marshallpierce/rust-base64/tree/24ead98) (after).

### Description

The `encoded_size` function in `lib.rs` in `rust-base64` before 0.3.0 is vulnerable to a buffer overflow. It is caused by the lack of proper validation of the input. An attacker can use this vulnerability to cause a denial of service or execute arbitrary code.

### Code Snippet

before:

```rust
pub fn encode_config<T: ?Sized + AsRef<[u8]>>(input: &T, config: Config) -> String {
    let mut buf = String::with_capacity(encoded_size(input.as_ref().len(), config));

    encode_config_buf(input, config, &mut buf);

    buf
}

/// calculate the base64 encoded string size, including padding
fn encoded_size(bytes_len: usize, config: Config) -> usize {
    let rem = bytes_len % 3;

    let complete_input_chunks = bytes_len / 3;
    let complete_output_chars = complete_input_chunks * 4;
    let printing_output_chars = if rem == 0 {
        complete_output_chars
    } else {
        complete_output_chars + 4
    };
    let line_ending_output_chars = match config.line_wrap {
        LineWrap::NoWrap => 0,
        LineWrap::Wrap(n, LineEnding::CRLF) => printing_output_chars / n * 2,
        LineWrap::Wrap(n, LineEnding::LF) => printing_output_chars / n,
    };

    return printing_output_chars + line_ending_output_chars;
}
```

after:

```rust

pub fn encode_config<T: ?Sized + AsRef<[u8]>>(input: &T, config: Config) -> String {
    let mut buf = match encoded_size(input.as_ref().len(), config) {
        Some(n) => String::with_capacity(n),
        None => panic!("integer overflow when calculating buffer size")
    };

    encode_config_buf(input, config, &mut buf);

    buf
}

/// calculate the base64 encoded string size, including padding
fn encoded_size(bytes_len: usize, config: Config) -> Option<usize> {
    let printing_output_chars = bytes_len
        .checked_add(2)
        .map(|x| x / 3)
        .and_then(|x| x.checked_mul(4));

    //TODO this is subtly wrong but in a not dangerous way
    //pushing patch with identical to previous behavior, then fixing
    let line_ending_output_chars = match config.line_wrap {
        LineWrap::NoWrap => Some(0),
        LineWrap::Wrap(n, LineEnding::CRLF) =>
            printing_output_chars.map(|y| y / n).and_then(|y| y.checked_mul(2)),
        LineWrap::Wrap(n, LineEnding::LF) =>
            printing_output_chars.map(|y| y / n),
    };

    printing_output_chars.and_then(|x|
        line_ending_output_chars.and_then(|y| x.checked_add(y))
    )
}
```

### Pattern

When initializing a `buf` with a capacity, an unchecked `usize` is passed in.

```yaml
rules:
  - id: CVE-2017-1000430
    languages: [rust]
    pattern: |
      let $BUF = String::with_capacity($LEN);
    message: |
      The `String::with_capacity` method is used to create a new string with a
      specific capacity. Check the `$LEN` to ensure it is not overflown.
    severity: WARNING
```
