import cv2
import numpy as np
from stegano import lsb
from PIL import Image
from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter
import getpass
import os
import zlib
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad


#################################################
#        Privacy is a fundamental right         #
#   Dedicated to the generations yet to come    #
#                  Lobito 2024                  #
#################################################


"""
The CryptoFrame script serves two main functionalities: hiding a message within a video file using encrypted stenography, and later revealing the hidden message from the video. Below is a full description of the command-line options alongside examples for each action.

Command-Line Options:

    action: Specify the action to perform. It can be either hide to hide a message or unhide to reveal a hidden message.
    input: Specify the input video file path. For hide action, it is the original video in which the message will be hidden. For unhide action, it is the video from which to reveal the hidden message.
    --output: (Required for hide action) Specify the base name for the output video file that will contain the hidden message.
    --message: (Required for hide action) Specify the text to hide or path to a text file containing the message.
    --codec: Choose the codec to use for the output video when hiding a message. Supported options are HFYU and FFV1, defaulting to FFV1.
    --public_key: (Required for hide action) Path to the public key file for encrypting the message before hiding it in the video.
    --private_key: (Required for unhide action) Path to the private key file for decrypting the revealed message.
    --passphrase: Passphrase for the private key. Only needed for the unhide action. If omitted, you will be prompted to enter it securely.

Examples:

Hide Action:

python CryptoFrame.py hide --input input.mp4 --output output.mkv --message "Privacy is a fundamental right" --codec FFV1 --public_key path_to_public_key.pem

This command hides the message "Privacy is a fundamental right" in the input.mp4 video, outputs to output.mkv, uses the FFV1 codec for the output video, and encrypts the message with the public key found at path_to_public_key.pem.

python CryptoFrame.py hide --input input.mp4 --output output.mkv --message "./message.txt" --codec FFV1 --public_key path_to_public_key.pem

This command hides the contents of message.txt in the input.mp4 video, outputs to output.mkv, uses the FFV1 codec for the output video, and encrypts the message with the public key found at path_to_public_key.pem.

Unhide Action:

python CryptoFrame.py unhide --input output.mkv --private_key path_to_private_key.pem --passphrase "YourPassphrase"

This command attempts to reveal a hidden message from output.mkv using the private key at path_to_private_key.pem. You will be prompted to enter the passphrase for the private key if it is not provided on the command line.


Installation and requirements:

git clone https://github.com/x011/CryptoFrame.git
cd CryptoFrame
pip install -r requirements.txt
"""

SALT_SIZE = 16
NUM_ITERATIONS = 100000
KEY_SIZE = 32
IV_SIZE = 16
NUM_LAYERS = 7


def encrypt_message(message, public_key_path):
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)

    session_key = get_random_bytes(16)
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(session_key, salt, dkLen=KEY_SIZE, count=NUM_ITERATIONS)

    data = zlib.compress(message)

    for _ in range(NUM_LAYERS):
        iv = get_random_bytes(IV_SIZE)
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        data = cipher_aes.encrypt(pad(data, AES.block_size))
        data = iv + data

    enc_session_key = cipher_rsa.encrypt(session_key)
    enc_session_key_b64 = b64encode(enc_session_key).decode('utf-8')
    salt_b64 = b64encode(salt).decode('utf-8')
    data_b64 = b64encode(data).decode('utf-8')
    return f"{enc_session_key_b64}:{salt_b64}:{data_b64}"


def decrypt_message(encrypted_message, private_key_path, passphrase):
    enc_session_key_b64, salt_b64, data_b64 = encrypted_message.split(':')
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read(), passphrase=passphrase)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    
    session_key = cipher_rsa.decrypt(b64decode(enc_session_key_b64))
    salt = b64decode(salt_b64)
    data = b64decode(data_b64)

    key = PBKDF2(session_key, salt, dkLen=KEY_SIZE, count=NUM_ITERATIONS)

    for _ in range(NUM_LAYERS):
        iv = data[:IV_SIZE]
        data = data[IV_SIZE:]
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        data = unpad(cipher_aes.decrypt(data), AES.block_size)

    # Decompress the data after decrypting
    data = zlib.decompress(data)

    return data.decode('utf-8')



def compress_message(message):
    compressed_data = zlib.compress(message.encode())
    return b64encode(compressed_data).decode()

def decompress_message(compressed_base64_message):
    compressed_data = b64decode(compressed_base64_message.encode())
    return zlib.decompress(compressed_data).decode()


def frame_to_pil_image(frame):
    return Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))


def pil_image_to_opencv(pil_img):
    return cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)


def hide_data_in_video(input_video_path, output_video_path, frame_rate, frame_width, frame_height, codec, message):
    cap = cv2.VideoCapture(input_video_path)
    if not cap.isOpened():
        raise Exception(f"Error opening input video file {input_video_path}.")

    out = cv2.VideoWriter(output_video_path, codec, frame_rate, (frame_width, frame_height))

    if not out.isOpened():
        cap.release()  # Ensure that the capture is released if the output is not opened
        raise Exception(f"Could not open VideoWriter with the specified codec or output file path: {output_video_path}")

    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    message_length_per_frame = len(message) // (total_frames // 2)
    last_index = 0

    while True:
        ret, frame = cap.read()
        if not ret or last_index >= len(message):
            break

        next_index = min(len(message), last_index + message_length_per_frame)
        compressed_message = compress_message(message[last_index:next_index])
        # print(compressed_message)
        pil_img = frame_to_pil_image(frame)
        secret_pil_img = lsb.hide(pil_img, compressed_message)
        frame = pil_image_to_opencv(secret_pil_img)
        out.write(frame)
        last_index = next_index

    cap.release()
    out.release()

def unhide_data_from_video(video_path):
    cap = cv2.VideoCapture(video_path)
    decoded_messages = []

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        pil_img = frame_to_pil_image(frame)
        compressed_base64_message_chunk = lsb.reveal(pil_img)
        
        if compressed_base64_message_chunk:
            decoded_messages.append(decompress_message(compressed_base64_message_chunk))

    cap.release()
    return ''.join(decoded_messages)


def parse_arguments():
    parser = ArgumentParser(description="Hide or reveal text in videos using steganography.",
                            epilog="Examples:\n"
                                   "  Hide a message: python CryptoFrame.py hide --input input.mp4 --output output.mkv --message 'Privacy is a fundamental right' --codec FFV1 --public_key public.pem\n"
                                   "  Hide a message from a file: python CryptoFrame.py hide --input input.mp4 --output output.mkv --message message.txt --codec FFV1 --public_key public.pem\n"
                                   "  Unhide a message: python CryptoFrame.py unhide --input input.mkv --private_key private.pem --passphrase strong_password\n",
                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=['hide', 'unhide'], help="Action to perform: 'hide' or 'unhide'")
    parser.add_argument('input', help="Input video file path.")
    parser.add_argument('--output', help="Output video file path for 'hide' action.")
    parser.add_argument('--message', help="Text to hide or path to a text file containing the message.")
    parser.add_argument('--codec', choices=['HFYU', 'FFV1'], default='FFV1', help="Codec to use for output video.")
    parser.add_argument('--public_key', help="Path to the public key file for encryption.")
    parser.add_argument('--private_key', help="Path to the private key file for decryption.")
    parser.add_argument('--passphrase', nargs='?', default='', help="Passphrase for the private key.")
    args = parser.parse_args()

    if args.action == 'hide' and not args.output:
        parser.error("The --output argument is required for the 'hide' action.")

        # Check if the output file has the correct extension
        allowed_extensions = ['.avi', '.mov', '.mkv']
        file_extension = os.path.splitext(args.output)[1].lower()
        if file_extension not in allowed_extensions:
            parser.error(f"The output file must be one of the following extensions: {', '.join(allowed_extensions)}")

    if args.action == 'hide' and not args.message and not args.message.strip():
        parser.error("The --message argument is required for the 'hide' action.")

    if args.action == 'hide' and not args.public_key:
        parser.error("The --public_key argument is required for the 'hide' action.")



    if args.action == 'unhide' and args.private_key and not args.passphrase:
        args.passphrase = getpass.getpass(prompt="Enter private key passphrase: ")
        if not args.passphrase.strip():  # Using .strip() to catch passphrases that are only whitespace
            parser.error("Passphrase is required to unlock the private key")

    return args




def main():


    args = parse_arguments()

    codec_fourcc = {
        'HFYU': cv2.VideoWriter_fourcc(*'HFYU'),
        'FFV1': cv2.VideoWriter_fourcc(*'FFV1'),
    }
    codec = codec_fourcc[args.codec]

    if args.action == 'hide':

        if not args.message:
            raise ValueError("The --message argument is required for the 'hide' action.")

        message = args.message
        # Check if message is a file path, and read the content if it is a file
        if os.path.isfile(message):
            with open(message, 'r', encoding='utf-8') as file:
                message = file.read().encode('utf-8')
        else:
            message = message.encode('utf-8')

        if not message.strip():
            raise Exception("The --message argument cannot be empty.")

        # Get video properties
        cap = cv2.VideoCapture(args.input)
        if not cap.isOpened():
            raise Exception(f"Error opening input video file {args.input}.")
        frame_rate = cap.get(cv2.CAP_PROP_FPS)
        frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        cap.release()

        encrypted_message = encrypt_message(message, args.public_key)

        hide_data_in_video(args.input, args.output, frame_rate, frame_width, frame_height, codec, encrypted_message)

    elif args.action == 'unhide':

    	# Check if the input file exists
        if not os.path.exists(args.input):
            raise FileNotFoundError(f"The specified input video file does not exist: {args.input}")

        encrypted_message = unhide_data_from_video(args.input)
        # Decrypt the message after revealing it
        decrypted_message = decrypt_message(encrypted_message, args.private_key, args.passphrase)
        print(decrypted_message)


if __name__ == "__main__":
    main()
