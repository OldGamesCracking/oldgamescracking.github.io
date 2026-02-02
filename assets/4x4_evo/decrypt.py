def is_alpha(c):
    return (ord('A') <= c and c <= ord('Z')) or (ord('a') <= c and c <= ord('z'))

def obfuscate(data):

    for i in range(len(data)):
        
        if i == 0:
            running_key = data[0]
            round_key = ord('\r')
        else:
            running_key = ((running_key * 0xE51D) + 0x3619) & 0xffff
            round_key = running_key % 26
        
        if is_alpha(data[i]):
            low_part = data[i] & 0x1f # Since we are dealing with letters, this will be 1..26
            letter = low_part - 1 # Map to 0..25
            new_letter = ((letter + round_key) % 26) + 1

            high_part = data[i] & 0xe0  # This will be 0x60 (Lowercase) or 0x40 (Uppercase)

            new_letter += high_part
            
            data[i] = new_letter

def encrypt(data):

    running_key = len(data)

    for i in range(len(data)):
        running_key = ((running_key * 0xE51D) + 0x3619) & 0xffffffff

        if data[i] == ord('\n'):
            data[i] ^= (running_key & 0x7f)
            # Clear MSB
            data[i] &= 0x7f
        else:
            data[i] ^= (running_key & 0x7f)
            # Set MSB
            data[i] |= 0x80

def decrypt(data):

    running_key = len(data)

    for i in range(len(data)):
        running_key = ((running_key * 0xE51D) + 0x3619) & 0xffffffff

        data[i] ^= running_key
        data[i] &= 0x7f

def deobfuscate(data):

    for i in range(len(data)):
        
        if i == 0:
            running_key = None
            round_key = ord('\r')
        else:
            running_key = ((running_key * 0xE51D) + 0x3619) & 0xffff
            round_key = running_key % 26
        
        if is_alpha(data[i]):
            low_part = data[i] & 0x1f # Since we are dealing with letters, this will be 1..26
            letter = low_part - 1 # Map to 0..25
            new_letter = ((letter - round_key) % 26) + 1

            high_part = data[i] & 0xe0  # This will be 0x60 (Lowercase) or 0x40 (Uppercase)

            new_letter += high_part
            
            data[i] = new_letter

        if i == 0:
            running_key =  data[i]

with open(r"A:\CL.LOG", "rb") as f:
    raw_data = f.read()

chunk = []

for b in raw_data:
    chunk.append(b)

    if b & 0x80 == 0:
        decrypt(chunk)
        #print(bytes(chunk).decode("utf-8").strip())
        deobfuscate(chunk)
        print(bytes(chunk).decode("utf-8").strip())
        chunk = []