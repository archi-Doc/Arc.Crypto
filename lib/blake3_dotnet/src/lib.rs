extern crate libc;

use zeroize::Zeroize;

// Creates a new instance of Blake3 Hasher
#[no_mangle]
pub extern "C" fn blake3_new() -> *mut blake3::Hasher {
  return Box::into_raw(Box::new(blake3::Hasher::new()));
}

// Creates a Blake3 Hasher in keyed hash mode from a 32-byte key.
#[no_mangle]
pub extern "C" fn blake3_new_keyed(ptr: *const u8) -> *mut blake3::Hasher {
    let array = ptr as *const [u8; 32];
    return Box::into_raw(Box::new(blake3::Hasher::new_keyed(unsafe { &*array })));
}

// Creates a Blake3 Hasher in key derivation mode; invalid UTF-8 in the context is replaced with U+FFFD.
// The managed wrapper rejects invalid UTF-8 before calling this.
#[no_mangle]
pub extern "C" fn blake3_new_derive_key(ptr: *const u8, size: libc::size_t) -> *mut blake3::Hasher {
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, size as usize) };
    let st = std::string::String::from_utf8_lossy(slice).into_owned();
    return Box::into_raw(Box::new(blake3::Hasher::new_derive_key(&st)));
}

// Deletes a Blake3 Hasher created by one of the blake3_new* functions, zeroing its state (key, buffered input) first.
#[no_mangle]
pub extern "C" fn blake3_delete(hasher: *mut blake3::Hasher) {
  let mut hasher = unsafe { Box::from_raw(hasher) };
  hasher.zeroize();
  drop(hasher);
}

// Resets Blake3 hasher
#[no_mangle]
pub extern "C" fn blake3_reset(
  hasher: *mut blake3::Hasher)
{
  let hasher = unsafe { &mut *hasher };
  hasher.reset();  
}

// Blake3::hash
#[no_mangle]
pub extern "C" fn blake3_hash(
  ptr: *const u8,
  size: libc::size_t,
  ptr_out: *const u8)
{
  let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, size as usize) };
  unsafe { *(ptr_out as *mut blake3::Hash) = blake3::hash(slice); }
}

// Updates Blake3 hash with data
#[no_mangle]
pub extern "C" fn blake3_update(
  hasher: *mut blake3::Hasher,
  ptr: *const u8,
  size: libc::size_t)
{
  let hasher = unsafe { &mut *hasher };
  let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, size as usize) };
  hasher.update(slice);  
}

// Updates Blake3 hash with data using Rayon multi-threading (requires the "rayon" feature).
#[cfg(feature = "rayon")]
#[no_mangle]
pub extern "C" fn blake3_update_rayon(
  hasher: *mut blake3::Hasher,
  ptr: *const u8,
  size: libc::size_t)
{
  let hasher = unsafe { &mut *hasher };
  let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, size as usize) };
  hasher.update_rayon(slice);  
}

// Finalize to a 32 byte hash
#[no_mangle]
pub extern "C" fn blake3_finalize(
  hasher: *mut blake3::Hasher,
  ptr_out: *mut u8)
{
  let hasher = unsafe { &mut *hasher };
  unsafe { *(ptr_out as *mut blake3::Hash) = hasher.finalize(); }
}

// Finalize the hash and put the result into output.
#[no_mangle]
pub extern "C" fn blake3_finalize_xof(
  hasher: *mut blake3::Hasher,
  ptr_out: *mut u8,
  size: libc::size_t)
{
  let hasher = unsafe { &mut *hasher };
  let slice = unsafe { std::slice::from_raw_parts_mut(ptr_out as *mut u8, size as usize) };
  hasher.finalize_xof().fill(slice);
}

// Finalize the hash, seek to the offset in the hash stream and put the result into output.
#[no_mangle]
pub extern "C" fn blake3_finalize_seek_xof(
  hasher: *mut blake3::Hasher,
  offset: u64,
  ptr_out: *mut u8,
  size: libc::size_t)
{
  let hasher = unsafe { &mut *hasher };
  let slice = unsafe { std::slice::from_raw_parts_mut(ptr_out as *mut u8, size as usize) };
  let mut reader = hasher.finalize_xof();
  reader.set_position(offset);
  reader.fill(slice);
}