# S-box used in the SubBytes step of AES
S_box = [
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
]

# S-box inverse used in the InvSubBytes step of AES
Inv_S_box = [
    0x52,
    0x09,
    0x6A,
    0xD5,
    0x30,
    0x36,
    0xA5,
    0x38,
    0xBF,
    0x40,
    0xA3,
    0x9E,
    0x81,
    0xF3,
    0xD7,
    0xFB,
    0x7C,
    0xE3,
    0x39,
    0x82,
    0x9B,
    0x2F,
    0xFF,
    0x87,
    0x34,
    0x8E,
    0x43,
    0x44,
    0xC4,
    0xDE,
    0xE9,
    0xCB,
    0x54,
    0x7B,
    0x94,
    0x32,
    0xA6,
    0xC2,
    0x23,
    0x3D,
    0xEE,
    0x4C,
    0x95,
    0x0B,
    0x42,
    0xFA,
    0xC3,
    0x4E,
    0x08,
    0x2E,
    0xA1,
    0x66,
    0x28,
    0xD9,
    0x24,
    0xB2,
    0x76,
    0x5B,
    0xA2,
    0x49,
    0x6D,
    0x8B,
    0xD1,
    0x25,
    0x72,
    0xF8,
    0xF6,
    0x64,
    0x86,
    0x68,
    0x98,
    0x16,
    0xD4,
    0xA4,
    0x5C,
    0xCC,
    0x5D,
    0x65,
    0xB6,
    0x92,
    0x6C,
    0x70,
    0x48,
    0x50,
    0xFD,
    0xED,
    0xB9,
    0xDA,
    0x5E,
    0x15,
    0x46,
    0x57,
    0xA7,
    0x8D,
    0x9D,
    0x84,
    0x90,
    0xD8,
    0xAB,
    0x00,
    0x8C,
    0xBC,
    0xD3,
    0x0A,
    0xF7,
    0xE4,
    0x58,
    0x05,
    0xB8,
    0xB3,
    0x45,
    0x06,
    0xD0,
    0x2C,
    0x1E,
    0x8F,
    0xCA,
    0x3F,
    0x0F,
    0x02,
    0xC1,
    0xAF,
    0xBD,
    0x03,
    0x01,
    0x13,
    0x8A,
    0x6B,
    0x3A,
    0x91,
    0x11,
    0x41,
    0x4F,
    0x67,
    0xDC,
    0xEA,
    0x97,
    0xF2,
    0xCF,
    0xCE,
    0xF0,
    0xB4,
    0xE6,
    0x73,
    0x96,
    0xAC,
    0x74,
    0x22,
    0xE7,
    0xAD,
    0x35,
    0x85,
    0xE2,
    0xF9,
    0x37,
    0xE8,
    0x1C,
    0x75,
    0xDF,
    0x6E,
    0x47,
    0xF1,
    0x1A,
    0x71,
    0x1D,
    0x29,
    0xC5,
    0x89,
    0x6F,
    0xB7,
    0x62,
    0x0E,
    0xAA,
    0x18,
    0xBE,
    0x1B,
    0xFC,
    0x56,
    0x3E,
    0x4B,
    0xC6,
    0xD2,
    0x79,
    0x20,
    0x9A,
    0xDB,
    0xC0,
    0xFE,
    0x78,
    0xCD,
    0x5A,
    0xF4,
    0x1F,
    0xDD,
    0xA8,
    0x33,
    0x88,
    0x07,
    0xC7,
    0x31,
    0xB1,
    0x12,
    0x10,
    0x59,
    0x27,
    0x80,
    0xEC,
    0x5F,
    0x60,
    0x51,
    0x7F,
    0xA9,
    0x19,
    0xB5,
    0x4A,
    0x0D,
    0x2D,
    0xE5,
    0x7A,
    0x9F,
    0x93,
    0xC9,
    0x9C,
    0xEF,
    0xA0,
    0xE0,
    0x3B,
    0x4D,
    0xAE,
    0x2A,
    0xF5,
    0xB0,
    0xC8,
    0xEB,
    0xBB,
    0x3C,
    0x83,
    0x53,
    0x99,
    0x61,
    0x17,
    0x2B,
    0x04,
    0x7E,
    0xBA,
    0x77,
    0xD6,
    0x26,
    0xE1,
    0x69,
    0x14,
    0x63,
    0x55,
    0x21,
    0x0C,
    0x7D,
]

# Round constant (Rcon) used in the Key Expansion
Rcon = [
    0x00,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1B,
    0x36,
    0x6C,
    0xD8,
    0xAB,
    0x4D,
    0x9A,
    0x2F,
    0x5E,
    0xBC,
    0x63,
    0xC6,
    0x97,
    0x35,
    0x6A,
    0xD4,
    0xB3,
    0x7D,
    0xFA,
    0xEF,
    0xC5,
    0x91,
    0x39,
]


def text_to_matrix(text):
    """Convert a 16-byte string into a 4x4 matrix."""
    matrix = []  # empty 4x4 matrix
    for i in range(16):
        byte = (text >> (8 * (15 - i))) & 0xFF
        if i % 4 == 0:
            matrix.append([byte])
        else:
            matrix[i // 4].append(byte)
    return matrix


def matrix_to_text(matrix):
    """Convert a 4x4 matrix into a 16-byte string."""
    text = 0
    for i in range(4):
        for j in range(4):
            text |= matrix[i][j] << (120 - 8 * (4 * i + j))
    return text


class FSecure_encryption:
    def __init__(self, master_key):
        self.key_expansion(master_key)

    def key_expansion(self, master_key):
        """Expand the master key into a key schedule and generate permutation secrets."""
        self.round_keys = text_to_matrix(master_key)
        self.permu_secrets = []  # Initialize the list to store permutation secrets

        for i in range(4, 44):
            self.round_keys.append([])
            if i % 4 == 0:
                byte = (
                    self.round_keys[i - 4][0]
                    ^ S_box[self.round_keys[i - 1][1]]
                    ^ Rcon[i // 4]
                )

                self.round_keys[i].append(byte)
                for j in range(1, 4):
                    byte = (
                        self.round_keys[i - 4][j]
                        ^ S_box[self.round_keys[i - 1][(j + 1) % 4]]
                    )
                    self.round_keys[i].append(byte)

                # After generating a new round key, generate the permutation secret for this round
                if i % 4 == 0 and i >= 4:
                    round_key_bytes = [
                        item
                        for sublist in self.round_keys[i - 4 : i]
                        for item in sublist
                    ]  # Flatten the last 4 rows to get the round key
                    permu_secret = []
                    for byte in round_key_bytes:
                        if byte not in permu_secret:
                            permu_secret.append(byte)
                        if len(permu_secret) == 4:
                            break
                    self.permu_secrets.append(permu_secret)
            else:
                for j in range(4):
                    byte = self.round_keys[i - 4][j] ^ self.round_keys[i - 1][j]
                    self.round_keys[i].append(byte)

        return self.round_keys

    def sub_bytes(self, state, s_box):
        """Substitute the values in the state matrix with the corresponding value in the S-box."""
        for i in range(4):
            for j in range(4):
                state[i][j] = s_box[state[i][j]]
        return state

    def inv_sub_bytes(self, state, inv_s_box):
        """Substitute the values in the state matrix with the corresponding value in the inverse S-box."""
        for i in range(4):
            for j in range(4):
                state[i][j] = inv_s_box[state[i][j]]
        return state

    def shift_rows(self, state):
        """Shift the rows in the state matrix."""
        for i in range(1, 4):
            state[i] = state[i][i:] + state[i][:i]
        return state

    def inv_shift_rows(self, state):
        """Shift the rows in the state matrix."""
        for i in range(1, 4):
            state[i] = state[i][-i:] + state[i][:-i]
        return state

    def row_col_transpose(self, state, permu_secret):
        """Transpose the rows and columns of the state matrix based on the permutation secret."""
        # Create a new state matrix to hold the transposed state
        new_state = [[0 for _ in range(4)] for _ in range(4)]

        # Determine the order to read the columns based on the permutation secret
        code_order = sorted(range(4), key=lambda x: permu_secret[x])

        # Rearrange the columns based on the code order
        for i, column_index in enumerate(code_order):
            for row_index in range(4):
                new_state[row_index][i] = state[row_index][column_index]

        # Copy the new state back into the original state matrix
        for i in range(4):
            for j in range(4):
                state[i][j] = new_state[i][j]

    def inverse_row_col_transpose(self, state, permu_secret):
        """Inverse the transpose operation based on the permutation secret."""
        # Create a new state matrix to hold the transposed state
        new_state = [[0 for _ in range(4)] for _ in range(4)]

        # Determine the original order of the columns based on the permutation secret
        original_order = sorted(permu_secret)

        # Rearrange the columns back to their original order
        for i, column_index in enumerate(original_order):
            for row_index in range(4):
                new_state[row_index][permu_secret.index(column_index)] = state[
                    row_index
                ][i]

        # Copy the new state back into the original state matrix
        for i in range(4):
            for j in range(4):
                state[i][j] = new_state[i][j]

    def add_round_key(self, state, key):
        """Add the round key to the state matrix."""
        for i in range(4):
            for j in range(4):
                state[i][j] ^= key[i][j]

    def round_encrypt(self, state, key, permu_secret):
        """Encrypt a single round."""
        self.sub_bytes(state, S_box)
        self.shift_rows(state)
        self.row_col_transpose(state, permu_secret)
        self.add_round_key(state, key)

    def round_decrypt(self, state, key, permu_secret):
        """Decrypt a single round."""
        self.add_round_key(state, key)
        self.inverse_row_col_transpose(state, permu_secret)
        self.inv_shift_rows(state)
        self.inv_sub_bytes(state, Inv_S_box)

    def encrypt_block(self, plaintext):
        """Encrypt a 16-byte plaintext."""
        self.plaintext = text_to_matrix(plaintext)

        self.add_round_key(self.plaintext, self.round_keys[:4])
        for i in range(1, 10):
            self.round_encrypt(
                self.plaintext,
                self.round_keys[4 * i : 4 * (i + 1)],
                self.permu_secrets[i - 1],
            )
        self.sub_bytes(self.plaintext, S_box)
        self.shift_rows(self.plaintext)
        self.add_round_key(self.plaintext, self.round_keys[40:])

        return matrix_to_text(self.plaintext)

    def decrypt_block(self, ciphertext):
        """Decrypt a 16-byte ciphertext."""
        self.plaintext = text_to_matrix(ciphertext)

        self.add_round_key(self.plaintext, self.round_keys[40:])
        self.inv_shift_rows(self.plaintext)
        self.inv_sub_bytes(self.plaintext, Inv_S_box)

        for i in range(9, 0, -1):
            # Retrieve the permutation secret for the current round in reverse order
            permu_secret = self.permu_secrets[i - 1]
            # Pass the permu_secret to the round_decrypt method
            self.round_decrypt(
                self.plaintext, self.round_keys[4 * i : 4 * (i + 1)], permu_secret
            )

        self.add_round_key(self.plaintext, self.round_keys[:4])

        return matrix_to_text(self.plaintext)


def encrypt(plaintext, key):
    """Encrypt a plaintext using the F-Secure encryption algorithm."""
    # Initialize the FSecure_encryption object with the master key
    fsecure = FSecure_encryption(key)
    # Encrypt the plaintext
    ciphertext = fsecure.encrypt_block(plaintext)
    return ciphertext


def decrypt(ciphertext, key):
    """Decrypt a ciphertext using the F-Secure encryption algorithm."""
    # Initialize the FSecure_encryption object with the master key
    fsecure = FSecure_encryption(key)
    # Decrypt the ciphertext
    plaintext = fsecure.decrypt_block(ciphertext)
    return plaintext
