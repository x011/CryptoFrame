# CryptoFrame

## Description

CryptoFrame is a command-line utility designed for highly secure video steganography. It enables users to embed hidden text messages into video files using multi-layered encryption techniques. The tool leverages seven layers of AES-256 encryption in CBC mode, further secured with RSA encryption, ensuring the confidentiality and integrity of the hidden data.

Supported input video formats include AVI, MKV, MOV, MP4, OGG, WMV, and WEBM. The output is confined to lossless formats such as AVI, MOV, and MKV to prevent the corruption of steganographically hidden data.

The tool offers two lossless codecs for output videos:

- **FFV1**: Provides a trade-off between file size and universal playback support, typically resulting in smaller file sizes.
- **HFYU (Huffyuv)**: Generates larger files but guarantees broad compatibility with most media players.

## Command Line Examples

### Hiding a String Message:

`python CryptoFrame.py hide input.mp4 --output output.mkv --message "Privacy is a Fundamental Right" --codec FFV1 --public_key public_key.pem`

### Hiding a Message from a Text File:

`python CryptoFrame.py hide input.mp4 --output output.mkv --message message.txt --codec HFYU --public_key public_key.pem`

### Unhiding a Message:

`python CryptoFrame.py unhide output.mkv --private_key private_key.pem --passphrase "YourPassphrase"`

## Installation and Requirements

Ensure Python 3.x is installed on your system.

Clone the CryptoFrame repository to your local machine and install the requirements:

```
git clone https://github.com/x011/CryptoFrame.git
cd CryptoFrame
pip install -r requirements.txt
```

## Installing OpenSSL

Before generating RSA key pairs, ensure that you have OpenSSL installed on your system. Follow the instructions below based on your operating system:


### Windows

1. Download the latest OpenSSL installer from [this page](https://slproweb.com/products/Win32OpenSSL.html).
2. Run the installer and follow the on-screen instructions to complete the installation.


### macOS

OpenSSL should already be installed on macOS. However, if you need to install or upgrade, you can use [Homebrew](https://brew.sh/):

`brew install openssl`


### Linux (Ubuntu/Debian)

```
sudo apt-get update
sudo apt-get install openssl
```

## Generating RSA Key Pair

To generate a 4096-bit RSA key pair:

1. **Private Key:**
    
`openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:4096 -pass pass:YourPassPhraseHere`
    
2. **Public Key:**
    
`openssl rsa -pubout -in private_key.pem -out public_key.pem -passin pass:YourPassPhraseHere `
   
Be sure to choose a strong password and keep your private key secure.

## Output File Size Note

The use of lossless codecs for steganography results in larger output file sizes. While lossy compression (x264, x265, etc.) may reduce the size, it compromises the integrity of the steganographic data due to alterations in pixel values, making lossless codecs a necessary choice for CryptoFrame.

## Understanding LSB (Least Significant Bit) Steganography

LSB steganography is a digital hiding technique where the least significant bit—essentially the last bit in a byte of data—of a pixel's color value is altered to encode information. In videos, each frame is composed of a multitude of pixels, each pixel containing color data typically represented by three values (red, green, and blue). By tweaking the LSB of these values, CryptoFrame injects the message directly into the image in a way that is nearly undetectable.

This technique takes advantage of the fact that small changes in the LSB of a pixel's color will not significantly alter the perceived color due to the binary weight it carries being minimal. This tiny difference is not perceivable by human vision, making the alteration an invisible carrier of secret information.

The criticality of using lossless codecs for this method cannot be overstressed. Lossy codecs, which compress data and consequently discard some of it for the sake of reducing file size, can potentially distort or obliterate the steganographically embedded bits. Lossless codecs, on the other hand, preserve every bit of information, ensuring that the embedded messages are retained intact throughout the process of saving and viewing the video.

CryptoFrame harnesses LSB steganography in combination with robust encryption to offer a formidable tool in secure and covert communication.

## Disclaimer

This tool is for educational purposes only. The authors do not endorse or promote the use of this software for any illicit activities.

## License

MIT License - see LICENSE file for details.
