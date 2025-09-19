Encounter Cliff Notes

- Cookie decryption oracle → admin
  - A reflected notification value decrypted the stay-logged-in cookie. Posted crafted plaintext (`administrator:<ts>`) via notification to get a properly padded encrypted token, trimmed/padded to cipher block size, then set as the stay-logged-in cookie to log in as admin.

- Integer overflow pricing
  - Cart total overflowed 32-bit int when adding many items, wrapping negative. Added enough items to hit negative range, then another item to land within available credit and purchase below normal price.


