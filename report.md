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

## CVE-2018-20992

### Information

- MITRE: [CVE-2018-20992](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20992).
- NVD: [CVE-2018-20992](https://nvd.nist.gov/vuln/detail/CVE-2018-20992).
- Repository: [claxon](https://github.com/ruuda/claxon).
- Issue: [Contents of uninitialized memory are leaked into the output on malformed inputs](https://github.com/ruuda/claxon/issues/10).
- Commit SHA: [cd82be3](https://github.com/ruuda/claxon/tree/cd82be3) (before) -> [8f28ec2](https://github.com/ruuda/claxon/tree/8f28ec2) (after).

### Description

When calculating the size of the buffer, the code does not consider the case when the input length is not a power of 2.

### Code Snippet

before:

```rust
let n_partitions = 1u32 << order;
let n_samples = block_size >> order;
let n_warm_up = block_size - buffer.len() as u16;

// The partition size must be at least as big as the number of warm-up
// samples, otherwise the size of the first partition is negative.
if n_warm_up > n_samples {
    return fmt_err("invalid residual");
}

// Finally decode the partitions themselves.
match partition_type {
    RicePartitionType::Rice => {
        let mut start = 0;
        let mut len = n_samples - n_warm_up;
        for _ in 0..n_partitions {
            let slice = &mut buffer[start..start + len as usize];
            try!(decode_rice_partition(input, slice));
            start = start + len as usize;
            len = n_samples;
        }
    }
    RicePartitionType::Rice2 => {
        let mut start = 0;
        let mut len = n_samples - n_warm_up;
        for _ in 0..n_partitions {
            let slice = &mut buffer[start..start + len as usize];
            try!(decode_rice2_partition(input, slice));
            start = start + len as usize;
            len = n_samples;
        }
    }
}
```

## CVE-2018-20996

### Information

- MITRE: [CVE-2018-20996](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20996).
- NVD: [CVE-2018-20996](https://nvd.nist.gov/vuln/detail/CVE-2018-20996).
- Repository: [crossbeam](https://github.com/crossbeam-rs/crossbeam).
- Issue: [Segfault](https://github.com/crossbeam-rs/crossbeam-epoch/issues/82).
- Pull request: [Use ManuallyDrop in queues](https://github.com/crossbeam-rs/crossbeam/pull/184).
- Commit SHA: [8f353c5](https://github.com/crossbeam-rs/crossbeam/tree/8f353c5) (before) -> [e6b3b98](https://github.com/crossbeam-rs/crossbeam/tree/e6b3b98) (after).

### Description

There is a double free because of destructor mishandling.

### Code Snippet

https://docs.rs/crossbeam/0.4.0/src/crossbeam/seg_queue.rs.html#24

> Multiple threads, complex mechanism, can't understand.

## CVE-2018-21000

### Information

- MITRE: [CVE-2018-21000](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-21000).
- NVD: [CVE-2018-21000](https://nvd.nist.gov/vuln/detail/CVE-2018-21000).
- Repository: [safe-transmute-rs](https://github.com/nabijaczleweli/safe-transmute-rs).
- Pull request: [Fix vec-to-vec conversion primitives](https://github.com/nabijaczleweli/safe-transmute-rs/pull/36).
- Commit SHA: [c79ebfd](https://github.com/nabijaczleweli/safe-transmute-rs/tree/c79ebfd) (before) -> [a134e06](https://github.com/nabijaczleweli/safe-transmute-rs/tree/a134e06) (after).
- Advisory: [safe-transmute's vec-to-vec transmutations could lead to heap overflow/corruption](https://github.com/rustsec/advisory-db/pull/89).

### Description

When calling `Vec::from_raw_parts`, the positions of `len` and `capaciity` are reversed.

### Code Snippet

before:

```rust
Vec::from_raw_parts(ptr as *mut T, capacity, len)
```

after:

```rust
Vec::from_raw_parts(ptr as *mut T, len, capacity)
```
