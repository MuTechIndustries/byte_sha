# ByteSha
## Purpose
ByteSha is a rust crate that can perform SHA256 on a Vec<u8> and return a Vec<u8>
## Namespace
ByteSha houses all functions at the top level of the crate. There are only three public functions and all are under the byte_sha namespace.
```rust
let result: Vec<u8> = *sah256_of_message_as_u8_vec(&mut message);
```
## Performing SHA256
```rust
extern crate byte_sha;

let mut message: Vec<u8> = vec![77, 117, 32, 83, 104, 97, 108, 108, 32, 82, 105, 115, 101, 33, 32, 65, 110, 100, 32, 119, 105, 116, 104, 32, 105, 116, 32, 115, 111, 32, 115, 104, 97, 108, 108, 32, 116, 111, 111, 44, 32, 115, 119, 101, 101, 116, 32, 108, 105, 98, 101, 114, 116, 121, 32, 101, 99, 104, 111, 32, 116, 104, 114, 111, 117, 103, 104, 32, 116, 104, 101, 32, 99, 104, 97, 109, 98, 101, 114, 32, 104, 97, 108, 108, 115, 44, 32, 98, 111, 116, 104, 32, 104, 105, 103, 104, 32, 97, 110, 100, 32, 108, 111, 119, 44, 32, 97, 110, 100, 32, 98, 105, 103, 32, 97, 110, 100, 32, 115, 109, 97, 108, 108, 46];
let result: Vec<u8> = *byte_sha::sha256_of_message_as_u8_vec(&mut message);
let expected: Vec<u8> = vec![61, 186, 202, 92, 52, 61, 155, 63, 150, 130, 106, 106, 206, 202, 234, 155, 196, 116, 142, 225, 90, 173, 181, 137, 94, 173, 27, 211, 63, 132, 41, 112];
assert_eq!(result, expected);
```
With any message in the form of Vec<u8> execute the function sha256_of_message_as_u8_vec with the mutable reference of a Vec<u8> as it's input. Notice you have to dereference because it returns a Box. This is to avoid unessisary copying.