# utils/steganography.py

from PIL import Image

def hide_text(input_image_path, output_image_path, text):
    img = Image.open(input_image_path)
    encoded = img.copy()
    width, height = img.size
    index = 0
    termination_sequence = "#####"
    text += termination_sequence
    binary_text = ''.join([format(ord(char), "08b") for char in text])
    total_bits = len(binary_text)
    max_capacity = width * height * 3
    print(f"Total bits to hide: {total_bits}")
    print(f"Image capacity: {max_capacity} bits")
    if total_bits > max_capacity:
        raise ValueError("The image is too small to hold the hidden text.")
    
    for row in range(height):
        for col in range(width):
            if index < total_bits:
                pixel = list(encoded.getpixel((col, row)))
                for n in range(3):  # RGB channels
                    if index < total_bits:
                        original_bit = pixel[n] & 1
                        new_bit = int(binary_text[index])
                        pixel[n] = (pixel[n] & ~1) | new_bit
                        index += 1
                encoded.putpixel((col, row), tuple(pixel))
            else:
                break
        if index >= total_bits:
            break
    encoded.save(output_image_path)
    print(f"Hidden text embedded successfully in {output_image_path}")

def extract_text(image_path):
    img = Image.open(image_path)
    binary_text = ""
    width, height = img.size
    for row in range(height):
        for col in range(width):
            pixel = img.getpixel((col, row))
            for n in range(3):  # RGB channels
                binary_text += str(pixel[n] & 1)
    
    # Convert from bits to characters
    all_bytes = [binary_text[i:i+8] for i in range(0, len(binary_text), 8)]
    decoded_text = ""
    for byte in all_bytes:
        try:
            decoded_text += chr(int(byte, 2))
        except ValueError:
            # Handle cases where byte is not valid
            continue
        if decoded_text.endswith("#####"):
            print("Termination sequence found.")
            return decoded_text[:-5]
    print("No termination sequence found.")
    return None
