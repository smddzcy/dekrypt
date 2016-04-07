# dekrypt
A decrypter&amp;decoder with multiple algorithm support

## Usage
This can only be used from terminal for now, maybe I'll add a web UI later (or maybe you can!).
```
Usage: php dekrypt.php [TYPE] [HASH|HASHFILE] [opts]

Supported encoding types
 base64 rot13 caesar hex bin decimal uuencode xor
Supported encryption types (for online database check)
 md5
Supported block cipher types (key and -if available- IV required)
 aes blowfish des rc2

Options:
 -b,                  add for base64 encoded hashes
 key::[KEY|KEYFILE],  *required* for block ciphers and xor
 iv::[IV],            add -if available- for block ciphers, otherwise null bytes will be used 

Notes:
 Use 'all' for checking all types
 Key|hash files must be in the same directory as this script
 Also multiple keys|hashes in those files must be separated by new lines
```

## Contributing
Fork it, create a branch, commit your changes, push, request a pull. It's that easy :D

I accept and would be happy about all kinds of contribution, send me an e-mail & contact me on Twitter or just reach me on Github if you see some stuff which can be better or if you want to add something.
