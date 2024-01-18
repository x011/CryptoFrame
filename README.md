# Crypto Frame

## Description

CryptoFrame is a command-line utility designed for highly secure video steganography. It enables users to embed hidden text messages into video files using multi-layered encryption techniques. The tool leverages seven layers of AES-256 encryption in CBC mode, further secured with RSA encryption, ensuring the confidentiality and integrity of the hidden data.

Supported input video formats include AVI, MKV, MOV, MP4, OGG, WMV, and WEBM. The output is confined to lossless formats such as AVI, MOV, and MKV to prevent the corruption of steganographically hidden data.

The tool offers two lossless codecs for output videos:

- **FFV1**: Provides a trade-off between file size and universal playback support, typically resulting in smaller file sizes.
- **HFYU (Huffyuv)**: Generates larger files but guarantees broad compatibility with most media players.

## Command Line Examples

### Hiding a String Message:

```bash
python CryptoFrame.py hide --input input.mp4 --output output.avi --message "Secret Message" --codec FFV1 --public_key public_key.pem
```

### Hiding a Message from a Text File:

```bash
python CryptoFrame.py hide --input input.mp4 --output output.mkv --message message.txt --codec HFYU --public_key public_key.pem
```

### Unhiding a Message:

```bash
python CryptoFrame.py unhide --input output.avi --private_key private_key.pem --passphrase "YourPassphrase"
```

## Requirements and Installation

Ensure Python 3.x is installed on your system. Install all required dependencies with:

`pip install -r requirements.txt`

## Generating RSA Key Pair

To generate a 4096-bit RSA key pair:

1.  **Private Key:**
    
-  `openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:4096 -pass pass:YourPassPhraseHere`
    
2   **Public Key:**
    
 - `openssl rsa -pubout -in private_key.pem -out public_key.pem -passin pass:YourPassPhraseHere `
   

Be sure to keep your private key secure and do not share it.

## Understanding LSB (Least Significant Bit) Steganography

LSB steganography involves modifying the least significant bits of pixel values in video frames to embed hidden information. This method relies on the imperceptibility of the changes to the naked eye and necessitates the use of lossless codecs to avoid corruption of the data by compression.

## Output File Size Note

The use of lossless codecs for steganography results in larger output file sizes. While lossy compression may reduce the size, it compromises the integrity of the steganographic data due to alterations in pixel values, making lossless codecs a necessary choice for CryptoFrame.

## Disclaimer

This tool is for educational purposes only. The authors do not endorse or promote the use of this software for any illicit activities.

## License

MIT License - see LICENSE file for details.
