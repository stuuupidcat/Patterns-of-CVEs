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

after:

```rust
// most 2^16 - 1 samples in the block. No values have been marked as
// invalid by the specification though.
let n_partitions = 1u32 << order;
let n_samples_per_partition = block_size >> order;

// The partitions together must fill the block. If the block size is not a
// multiple of 2^order; if we shifted off some bits, then we would not fill
// the entire block. Such a partition order is invalid for this block size.
if block_size & (n_partitions - 1) as u16 != 0 {
    return fmt_err("invalid partition order")
}

// NOTE: the check above checks that block_size is a multiple of n_partitions
// (this works because n_partitions is a power of 2). The check below is
// equivalent but more expensive.
debug_assert_eq!(n_partitions * n_samples_per_partition as u32, block_size as u32);

let n_warm_up = block_size - buffer.len() as u16;

// The partition size must be at least as big as the number of warm-up
// samples, otherwise the size of the first partition is negative.
if n_warm_up > n_samples_per_partition {
    return fmt_err("invalid residual");
}

// Finally decode the partitions themselves.
match partition_type {
    RicePartitionType::Rice => {
        let mut start = 0;
        let mut len = n_samples_per_partition - n_warm_up;
        for _ in 0..n_partitions {
            let slice = &mut buffer[start..start + len as usize];
            try!(decode_rice_partition(input, slice));
            start = start + len as usize;
            len = n_samples_per_partition;
        }
    }
    RicePartitionType::Rice2 => {
        let mut start = 0;
        let mut len = n_samples_per_partition - n_warm_up;
        for _ in 0..n_partitions {
            let slice = &mut buffer[start..start + len as usize];
            try!(decode_rice2_partition(input, slice));
            start = start + len as usize;
            len = n_samples_per_partition;
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

### Pattern

```yaml
rules:
  - id: CVE-2018-21000
    languages: [rust]
    pattern: |
      Vec::from_raw_parts($PTR, $LEN, $CAP);
    message: |
      The `Vec::from_raw_parts` method is used to create a new vector from a
      given raw pointer, length, and capacity. Check the `$LEN` and `$CAP` to
      ensure they are in the correct parameter positions. (The signature is
      `Vec::from_raw_parts(ptr: *mut T, length: usize, capacity: usize) -> Vec<T>`.)
    severity: WARNING
```

## CVE-2019-15548

### Information

- MITRE: [CVE-2019-15548](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15548).
- NVD: [CVE-2019-15548](https://nvd.nist.gov/vuln/detail/CVE-2019-15548).
- Repository: [ncurses-rs](https://github.com/jeaye/ncurses-rs).
- Issue: [instr and mvwinstr are never safe to use](https://github.com/jeaye/ncurses-rs/issues/186).
- Commit SHA: [55be2ec](https://github.com/jeaye/ncurses-rs/tree/55be2ec) (before) -> [7fcee59](https://github.com/jeaye/ncurses-rs/tree/7fcee59) (after).

### Description

The `instr` and `mvwinstr` functions are never safe to use.

### Code Snippet

before:

```rust
pub fn instr(s: &mut String) -> i32
{
  /* XXX: This is probably broken. */
  unsafe
  {
    let buf = s.as_bytes().as_ptr();
    let ret = ll::instr(mem::transmute(buf));

    let capacity = s.capacity();
    match s.find('\0')
    {
      Some(index) => s.as_mut_vec().set_len(index as usize),
      None => s.as_mut_vec().set_len(capacity),
    }

    ret
  }
}

pub fn mvwinstr(w: WINDOW, y: i32, x: i32, s: &mut String) -> i32
{
  /* XXX: This is probably broken. */
  unsafe
  {
    let buf = s.as_bytes().as_ptr();
    let ret = ll::mvwinstr(w, y, x, mem::transmute(buf));

    let capacity = s.capacity();
    match s.find('\0')
    {
      Some(index) => s.as_mut_vec().set_len(index as usize),
      None => s.as_mut_vec().set_len(capacity),
    }

    ret
  }
}
```

### Pattern

```yaml
rules:
  - id: CVE-2019-15548_1
    languages: [rust]
    patterns:
      - pattern-either:
          - pattern: $MOD::instr(...)
          - pattern: instr(...)
      - pattern-inside: |
          pub fn $FUNC(...) {
            ...
          }
      - pattern-not-inside: |
          pub unsafe fn $FUNC(...) {
            ...
          }
    message: |
      Check the function `$FUNC` which calls the `instr` method and is marked as `safe`. 
      Mark the function as `unsafe` to prevent potential memory safety issues.
    severity: ERROR
  - id: CVE-2019-15548_2
    languages: [rust]
    patterns:
      - pattern-either:
          - pattern: $MOD::mvwinstr(...)
          - pattern: mvwinstr(...)
      - pattern-inside: |
          pub fn $FUNC(...) {
            ...
          }
      - pattern-not-inside: |
          pub unsafe fn $FUNC(...) {
            ...
          }
    message: |
      Check the function `$FUNC` which calls the `mvwinstr` method and is marked as `safe`. 
      Mark the function as `unsafe` to prevent potential memory safety issues.
    severity: ERROR
```

## CVE-2019-16138

### Information

- MITRE: [CVE-2019-16138](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16138).
- NVD: [CVE-2019-16138](https://nvd.nist.gov/vuln/detail/CVE-2019-16138).
- Repository: [image](https://github.com/image-rs/image).
- Issue: [Unnecessary unsafety in HDR decoder](https://github.com/image-rs/image/issues/980).
- Commit SHA: [984e092](https://github.com/image-rs/image/tree/984e092).

### Description

Vec::set_len is called on an uninitialized vector, leading to a use-after-free and arbitrary code execution.

### Code Snippet

before:

```rust
let mut ret = Vec::with_capacity(pixel_count);
unsafe {
    // RGBE8Pixel doesn't implement Drop, so it's Ok to drop half-initialized ret
    ret.set_len(pixel_count);
} // ret contains uninitialized data, so now it's my responsibility to return fully initialized ret
```

### Pattern

```yaml
rules:
  - id: CVE-2019-16138
    languages: [rust]
    pattern: |
      let $MAYBE_UNINIT_VEC = Vec::with_capacity(...);
      ...
      $MAYBE_UNINIT_VEC.set_len(...);
    message: |
      The `Vec::set_len` method is used to set the length of a vector.
      Ensure that the vector `$MAYBE_UNINIT_VEC` is initialized before calling `set_len` or
      will be fully initialized after calling `set_len` to prevent potential
      memory safety issues.
    severity: WARNING
```

## CVE-2019-16139

### Information

- MITRE: [CVE-2019-16139](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16139).
- NVD: [CVE-2019-16139](https://nvd.nist.gov/vuln/detail/CVE-2019-16139).
- Repository: [compact_arena](https://github.com/llogiq/compact_arena).
- Issue: [Generativity mechanism is unsound](https://github.com/llogiq/compact_arena/issues/22).
- Commit SHA: [947fa6e](https://github.com/llogiq/compact_arena/tree/947fa6e) (before) -> [eb413b3](https://github.com/llogiq/compact_arena/tree/eb413b3) (after).

### Description

Generativity is mishandled, leading to an out-of-bounds write or read.
Tricky lifetime issues.
**Rejected by rustc after fixing the issue.**

### Code Snippet

```rust
fn main() {
    compact_arena::mk_arena!(a, 0);
    compact_arena::mk_arena!(b, 0);
    let mut a: compact_arena::SmallArena<'_, usize> = a;
    let b: compact_arena::SmallArena<'_, usize> = b;

    let ix = a.add(0);
    dbg!(b[ix]);
}
// [dependencies]
// compact_arena = { git = "https://github.com/llogiq/compact_arena/", rev = "eb413b3d47baea8e8a0b9ce2ccd8299b354d3b74" }
```

## CVE-2020-13759

### Information

- MITRE: [CVE-2020-13759](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13759).
- NVD: [CVE-2020-13759](https://nvd.nist.gov/vuln/detail/CVE-2020-13759).
- Repository: [vm-memory](https://github.com/rust-vmm/vm-memory).
- Issue: [DoS issue when using virtio with rust-vmm/vm-memory](https://github.com/rust-vmm/vm-memory/issues/93).
- Pull request: [DoS issue when using virtio with rust-vmm/vm-memory](https://github.com/rust-vmm/vm-memory/pull/98).
- Commit SHA: [0934351](https://github.com/rust-vmm/vm-memory/tree/0934351) (before) -> [cbac816](https://github.com/rust-vmm/vm-memory/tree/cbac816) (after).
- Advisory: [Assigned RUSTSEC-2020-0157 to vm-memory, RUSTSEC-2021-0107 to ckb](https://github.com/rustsec/advisory-db/pull/1033).


### Description

rust-vmm vm-memory before 0.1.1 and 0.2.x before 0.2.1 allows attackers to cause a denial of service (loss of IP networking) because read_obj and write_obj do not properly access memory. This affects aarch64 (with musl or glibc) and x86_64 (with musl).

### Memory Safety Related

I don't know think this is a memory safety issue.

The functions read_obj and write_obj are not doing **atomic accesses** for all combinations of platform and libc implementations. These reads and writes translate to memcpy, which may be performing byte-by-byte copies, resulting in DoS.

## CVE-2020-25016

### Information

- MITRE: [CVE-2020-25016](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25016).
- NVD: [CVE-2020-25016](https://nvd.nist.gov/vuln/detail/CVE-2020-25016).
- Repository: [rust-rgb](https://github.com/kornelski/rust-rgb).
- Issue: [ComponentBytes is unsound](https://github.com/kornelski/rust-rgb/issues/35).
- Commit SHA: [8075972](https://github.com/kornelski/rust-rgb/tree/8075972) (before) -> [3c70362](https://github.com/kornelski/rust-rgb/tree/3c70362) (after).
- Advisory: [File advisories for vulnerabilities with upcoming fixes](https://github.com/rustsec/advisory-db/pull/327).

### commit sha?

ffa7935 -> 2691083

### Description

A safety violation was discovered in the rgb crate before 0.8.20 for Rust, leading to (for example) dereferencing of arbitrary pointers or disclosure of uninitialized memory. This occurs because structs can be treated as bytes for read and write operations.

### Code Snippet

before

```rust
/// Casting a slice of `RGB/A` values to a slice of `u8`
pub trait ComponentBytes<T: Copy + Send + Sync + 'static> where Self: ComponentSlice<T> {
    /// The components interpreted as raw bytes, in machine's native endian. In `RGB` bytes of the red component are first.
    #[inline]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        let slice = self.as_mut_slice();
        unsafe {
            core::slice::from_raw_parts_mut(slice.as_mut_ptr() as *mut _, slice.len() * core::mem::size_of::<T>())
        }
    }
}
```

attacked code

```Rust
use rgb::ComponentBytes;
use rgb::FromSlice;

fn main() {
    let component: &'static str = "Hello, World!";
    let mut not_rgb = [component; 3];
    let bytes = FromSlice::as_rgb_mut(&mut not_rgb[..]).as_bytes_mut();
    // Just write over this reference internals, lol.
    bytes[0] += component.len() as u8;
    // XXX: on most architectures this points after the original static now
    // e.g. into some different static or executable memory
    println!("{}", not_rgb[0]);
}
```


