Fixed reading the object behind a pointer that is narrower than an address, such as an RL78 near pointer: it was read as an address-sized value, taking the bytes after it as part of it.
