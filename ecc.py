def process_file(input_file_path, output_file_path):
    chunk_size = 2112
    bytes_to_write = 2048

    try:
        with open(input_file_path, 'rb') as input_file, open(output_file_path, 'wb') as output_file:
            while True:
                # Read a chunk of data
                data = input_file.read(chunk_size)
                
                # If less than 2112 bytes are read, it means end of file
                if not data:
                    break

                # Write only the first 2048 bytes to the output file
                output_file.write(data[:bytes_to_write])

    except IOError as e:
        print(f"An error occurred: {e}")

# Example usage
input_file_path = 'READ1.BIN'
output_file_path = 'OUTPUT.BIN'
process_file(input_file_path, output_file_path)