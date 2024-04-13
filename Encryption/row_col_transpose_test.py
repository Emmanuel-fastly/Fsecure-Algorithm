# Just a simple test to demonstrate the custom row-column transposition method included in the algorithm.


def convert_to_matrix(input_string, code):
    """
    Converts a 16-byte string into a 4x4 matrix and reads it in columns based on the provided code.
    """
    if len(input_string) != 16:
        raise ValueError("Input string must be 16 bytes long.")
    if len(code) != 4:
        raise ValueError("Code must be 4 digits long.")

    state = [[0 for _ in range(4)] for _ in range(4)]

    # Write the input string in a row
    for i in range(4):
        for j in range(4):
            state[i][j] = input_string[i * 4 + j]

    # Rearrange the columns based on the code
    code_order = sorted(range(4), key=lambda x: int(code[x]))

    output_string = ""
    for column_index in code_order:
        for row_index in range(4):
            output_string += state[row_index][column_index]

    return output_string


def repeat_conversion(input_string, codes):
    """
    Performs the matrix conversion and column rearrangement multiple times on the input string, using a different code for each round.
    """
    output_string = input_string
    for code in codes:
        output_string = convert_to_matrix(output_string, code)
        print(output_string)
    return output_string


# Example usage
input_string = "comebackheresoon"
codes = ["7250", "2501", "5072", "0725", "1257", "7125", "2570", "5027", "0752", "1702"]
final_output = repeat_conversion(input_string, codes)
