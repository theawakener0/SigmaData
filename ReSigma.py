
import argparse
from art import text2art  # For ASCII art generation
import os
import sys
import logging
import struct
import ctypes
from collections import defaultdict

# --- Constants ---
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB
MAX_FILE_SIZE_MB = 512  # Maximum size for a carved file to prevent runaway reads
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

# --- File Signatures (Header and Footer) ---
# Headers are bytes objects. Footers can be bytes objects or None if variable/complex.
# Note: Footer matching can be complex. These are simplified examples.
#       ZIP footers are particularly tricky due to central directory structure.
FILE_SIGNATURES = {
    "jpg": {
        "ext": "jpg",
        "header": b'\xFF\xD8\xFF',  # Common JPEG start, covers variants like \xE0, \xE1
        "footer": b'\xFF\xD9',
        "max_size": 50 * 1024 * 1024 # 50 MB limit for JPEGs
    },
    "png": {
        "ext": "png",
        "header": b'\x89PNG\r\n\x1a\n',
        "footer": b'IEND\xaeB`\x82', # PNG End chunk
        "max_size": 50 * 1024 * 1024 # 50 MB limit for PNGs
    },
    "pdf": {
        "ext": "pdf",
        "header": b'%PDF-',
        # PDF footer is tricky, often %%EOF followed by newline chars
        # We'll search for %%EOF and read a bit past it.
        "footer": b'%%EOF',
        "max_size": 100 * 1024 * 1024 # 100 MB limit for PDFs
        # Add extra read logic for PDF footers if needed
    },
    "zip": {
        "ext": "zip",
        "header": b'PK\x03\x04', # PKZIP header
        # ZIP footer (End of Central Directory Record) starts with PK\x05\x06
        # Finding the *correct* EOCD record requires more logic than simple search
        # This is a simplified approach.
        "footer": b'PK\x05\x06',
        "max_size": MAX_FILE_SIZE_BYTES # Use general max size
    },
    # Add more signatures here following the same structure
    "gif": {
        "ext": "gif",
        "header": b'GIF87a', # or GIF89a
        "footer": b'\x00\x3B', # GIF trailer
        "max_size": 20 * 1024 * 1024
    },
    "docx": {
        "ext": "docx",
        "header": b'PK\x03\x04', # Same as zip, but check for [Content_Types].xml inside
        "footer": b'PK\x05\x06',
        "max_size": 100 * 1024 * 1024
    },
    "rtf": {
        "ext": "rtf",
        "header": b'{\\rtf1',
        "footer": b'\\par}', # Common, but can vary
        "max_size": 20 * 1024 * 1024
    },
    "mpg": {
        "ext": "mpg",
        "header": b'\x00\x00\x01\xBA',
        "footer": b'\x00\x00\x01\xB9', # MPEG Program Stream end code
        "max_size": MAX_FILE_SIZE_BYTES
    },
    "mp3": {
        "ext": "mp3",
        "header": b'ID3', # Common for MP3 with ID3 tags
        "footer": None, # MP3s often don't have a simple, reliable footer
        "max_size": 30 * 1024 * 1024
    },
    "avi": {
        "ext": "avi",
        "header": b'RIFF....AVI LIST',
        "footer": None, # AVI footers are not simple fixed signatures
        "max_size": MAX_FILE_SIZE_BYTES
    },
    "mov": {
        "ext": "mov",
        "header": b'\x00\x00\x00\x14ftypqt  ', # Or other ftyp variations like ftypmp42
        "footer": None, # MOV footers are complex (moov atom)
        "max_size": MAX_FILE_SIZE_BYTES
    },
    "psd": {
        "ext": "psd",
        "header": b'8BPS',
        "footer": None, # PSDs don't have a simple, reliable footer
        "max_size": 200 * 1024 * 1024
    },
    "rar": { # Older RAR versions
        "ext": "rar",
        "header": b'Rar!\x1a\x07\x00',
        "footer": None, # RAR v4.x footer is complex, v5+ is different
        "max_size": MAX_FILE_SIZE_BYTES
    },
    "7z": {
        "ext": "7z",
        "header": b"7z\xBC\xAF'\x1C",
        "footer": None, # 7z footers are not simple fixed signatures
        "max_size": MAX_FILE_SIZE_BYTES
    },
    "bmp": {
        "ext": "bmp",
        "header": b'BM',
        "footer": None, # BMPs don't have a standard footer signature
        "max_size": 50 * 1024 * 1024
    },
    "exe": {
        "ext": "exe",
        "header": b'MZ', # DOS MZ header
        "footer": None, # EXE files don't have a universal simple footer
        "max_size": 100 * 1024 * 1024
    },
    "mp4": {
        "ext": "mp4",
        "header": b'\x00\x00\x00 ftypisom', # Common start, space for length byte, or ftypmp42, ftypqt. The first byte can vary (e.g. 0x18, 0x20, 0x14 for length)
        "footer": None, # MP4 footers (moov atom) are complex and not fixed. Carving often relies on finding the next 'ftyp' or a max size.
        "max_size": MAX_FILE_SIZE_BYTES
    },
    "wav": {
        "ext": "wav",
        "header": b'RIFF....WAVEfmt ',
        "footer": None, # WAV file size is in the header (bytes 4-7), no simple fixed footer. Recovery often stops at max_size or next known header.
        "max_size": 200 * 1024 * 1024 # 200 MB limit for WAV files
    },
    "mkv": {
        "ext": "mkv",
        "header": b'\x1A\x45\xDF\xA3', # EBML Header
        "footer": None, # MKV footers are not simple fixed signatures. Carving relies on EBML structure or max size.
        "max_size": MAX_FILE_SIZE_BYTES
    },
    "flac": {
        "ext": "flac",
        "header": b'fLaC',
        "footer": None, # FLAC metadata contains length, no simple fixed footer. Stream can end with a metadata block indicating last block.
        "max_size": 100 * 1024 * 1024 # 100 MB limit for FLAC files
    },
    "ogg": {
        "ext": "ogg",
        "header": b'OggS',
        "footer": None, # OGG footers are not simple fixed signatures. Relies on page structure and last page flag.
        "max_size": 100 * 1024 * 1024 # 100 MB limit for OGG files
    },
    "pptx": {
        "ext": "pptx",
        "header": b'PK\x03\x04',
        "footer": b'PK\x05\x06', # Standard ZIP EOCD, but internal structure ([Content_Types].xml) confirms PPTX
        "max_size": 100 * 1024 * 1024 # 100 MB limit for PPTX files
    },
    "xlsx": {
        "ext": "xlsx",
        "header": b'PK\x03\x04',
        "footer": b'PK\x05\x06', # Standard ZIP EOCD, but internal structure ([Content_Types].xml) confirms XLSX
        "max_size": 100 * 1024 * 1024 # 100 MB limit for XLSX files
    }
}

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
        # Optionally add logging.FileHandler('recovery.log')
    ]
)

# --- Platform Specific Functions ---
def is_admin():
    """Check if the script is running with administrative privileges on Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        # Not Windows or ctypes issue
        logging.warning("Admin check failed. Assuming not admin.")
        return False
    except Exception as e:
        logging.error(f"Error checking admin status: {e}")
        return False

def check_raw_device_access(source_path):
    """Check if the source is a raw device and if admin privileges are needed."""
    # On Windows, raw device paths look like \\.\C: or \\.\PhysicalDrive0
    if source_path.startswith('\\\\.\\'):
        logging.info(f"Accessing raw device: {source_path}")
        if not is_admin():
            logging.error(
                "Administrative privileges are required to access raw disk "
                f"devices like '{source_path}'."
            )
            logging.error("Please re-run this script as an administrator.")
            sys.exit(1)
        else:
            logging.info("Running with administrative privileges.")
    else:
        logging.info(f"Accessing file: {source_path}")


# --- Core Carving Logic ---
def _find_next_header(data_to_scan, scan_offset, file_types_to_recover, FILE_SIGNATURES):
    """
    Finds the earliest occurrence of a known file header in the data.

    Args:
        data_to_scan (bytes): The data buffer to search within.
        scan_offset (int): The offset within data_to_scan to start searching.
        file_types_to_recover (list): List of file type keys to look for.
        FILE_SIGNATURES (dict): The dictionary of file signatures.

    Returns:
        tuple: (best_match_type, header_start_index)
               best_match_type (str): The key of the matched file type, or None.
               header_start_index (int): The starting index of the header, or -1.
    """
    earliest_header_pos = len(data_to_scan)
    best_match_type = None
    found_header_start_index = -1

    for type_key in file_types_to_recover:
        sig_info = FILE_SIGNATURES[type_key]
        header = sig_info['header']
        try:
            if not isinstance(header, bytes):
                logging.debug(f"Header for {type_key} is not bytes, skipping: {type(header)}")
                continue

            idx = data_to_scan.find(header, scan_offset)
            if idx != -1 and idx < earliest_header_pos:
                earliest_header_pos = idx
                best_match_type = type_key
                found_header_start_index = idx
        except Exception as e:
            logging.error(f"Unexpected error finding header for {type_key}: {e}")
            continue

    if best_match_type:
        return best_match_type, found_header_start_index
    else:
        return None, -1


def carve_files(source_path, output_dir, file_types_to_recover, chunk_size):
    """
    Scans the source path for file signatures and carves out found files.

    Args:
        source_path (str): Path to the raw device or disk image file.
        output_dir (str): Directory to save recovered files.
        file_types_to_recover (list): List of file type keys (e.g., ['jpg', 'pdf']).
        chunk_size (int): Size of data chunks to read in bytes.
    """
    recovered_counts = defaultdict(int)
    processed_bytes = 0
    buffer = b''
    max_header_len = max(len(sig['header']) for type_key in file_types_to_recover
                         for sig in [FILE_SIGNATURES[type_key]])
    max_footer_len = max(len(sig['footer']) for type_key in file_types_to_recover
                         for sig in [FILE_SIGNATURES[type_key]] if sig['footer'])

    # Ensure output directory exists
    try:
        os.makedirs(output_dir, exist_ok=True)
        logging.info(f"Output directory: {os.path.abspath(output_dir)}")
    except OSError as e:
        logging.error(f"Failed to create output directory '{output_dir}': {e}")
        sys.exit(1)

    try:
        with open(source_path, 'rb') as source_file:
            logging.info(f"Starting scan of '{source_path}'...")
            total_size = None
            try:
                # Attempt to get total size for progress reporting
                source_file.seek(0, os.SEEK_END)
                total_size = source_file.tell()
                source_file.seek(0, os.SEEK_SET)
                logging.info(f"Total size: {total_size / (1024*1024):,.2f} MiB")
            except OSError as e:
                logging.warning(f"Could not determine total size of '{source_path}': {e}")
                logging.info("Progress will be shown in bytes processed.")


            while True:
                try:
                    chunk = source_file.read(chunk_size)
                    if not chunk:
                        logging.info("End of source reached.")
                        break # End of file/device

                    current_pos = source_file.tell() - len(chunk)
                    processed_bytes += len(chunk)

                    # Display progress
                    if total_size:
                        progress = (processed_bytes / total_size) * 100
                        logging.info(
                            f"Processed: {processed_bytes / (1024*1024):,.2f} MiB / "
                            f"{total_size / (1024*1024):,.2f} MiB ({progress:.2f}%)"
                        )
                    else:
                        logging.info(f"Processed: {processed_bytes / (1024*1024):,.2f} MiB")

                    # Combine buffer from previous chunk with new chunk
                    data_to_scan = buffer + chunk

                    found_file_in_chunk = False
                    scan_offset = 0

                    while scan_offset < len(data_to_scan):
                        best_match_type, header_start_index = _find_next_header(
                            data_to_scan, scan_offset, file_types_to_recover, FILE_SIGNATURES
                        )

                        if header_start_index == -1: # No header found
                            # No more headers found in the remaining data_to_scan
                            break # Exit inner loop, need next chunk
                        
                        # --- Header Found ---
                        sig_info = FILE_SIGNATURES[best_match_type]
                        header = sig_info['header']
                        footer = sig_info.get('footer')
                        ext = sig_info['ext']
                        max_size = sig_info.get('max_size', MAX_FILE_SIZE_BYTES)

                        logging.debug(f"Potential {ext.upper()} header found at offset "
                                     f"{current_pos + header_start_index}")

                        if not footer:
                            logging.info(f"No footer defined for {ext.upper()}. Attempting to carve up to max_size ({max_size / (1024*1024):.2f} MiB) or EOF.")
                            
                            # Data from current buffer, starting from the header
                            file_initial_data = data_to_scan[header_start_index:]
                            file_data_list = [file_initial_data] # Use a list to accumulate parts
                            
                            # Save current main file reader position. This is the position *after* the current 'chunk' was read
                            # and before we start reading ahead specifically for this no-footer file.
                            pos_before_readahead_for_this_file = source_file.tell()
                            
                            accumulated_length = len(file_initial_data)
                            
                            # Read ahead from the source_file if current data is less than max_size
                            if accumulated_length < max_size:
                                while True:
                                    bytes_needed = max_size - accumulated_length
                                    if bytes_needed <= 0:
                                        break
                                    
                                    read_amount = min(bytes_needed, chunk_size) # Read up to chunk_size or what's needed
                                    read_data_chunk = source_file.read(read_amount)
                                    
                                    if not read_data_chunk:
                                        logging.debug(f"EOF reached while carving {ext.upper()} (no footer). Total bytes read for this file part: {accumulated_length - len(file_initial_data)}.")
                                        break # EOF
                                    
                                    file_data_list.append(read_data_chunk)
                                    accumulated_length += len(read_data_chunk)
                                    
                                    if accumulated_length >= max_size:
                                        break
                            
                            file_content = b"".join(file_data_list)
                            
                            # Truncate if it's over max_size (e.g. if the last read_data_chunk made it exceed)
                            if len(file_content) > max_size:
                                file_content = file_content[:max_size]
                                logging.debug(f"Truncated {ext.upper()} (no footer) to max_size {max_size} bytes. Original potential size: {accumulated_length} bytes.")

                            # Save the file
                            recovered_counts[ext] += 1
                            sequence = recovered_counts[ext]
                            # Add a suffix to distinguish files carved without a footer
                            filename = f"{ext}_{sequence:05d}_nofooter.{ext}"
                            filepath = os.path.join(output_dir, filename)
                            
                            try:
                                with open(filepath, 'wb') as outfile:
                                    outfile.write(file_content)
                                logging.info(f"Recovered (no footer): {filename} ({len(file_content) / 1024:.2f} KiB) "
                                             f"starting at offset {current_pos + header_start_index}")
                                # found_file_in_chunk = True # Not strictly needed here due to 'continue'
                            except IOError as e:
                                logging.error(f"Failed to write file '{filepath}': {e}")
                            
                            # IMPORTANT: Restore the main file reader's position to what it was 
                            # BEFORE reading ahead for THIS no-footer file.
                            source_file.seek(pos_before_readahead_for_this_file)
                            
                            # Advance scan_offset within the current data_to_scan past this header
                            # to prevent re-detecting it immediately in the current buffer.
                            scan_offset = header_start_index + 1 
                            continue # Continue to the next iteration of the inner while loop (scan_offset loop)

                        # --- Search for Footer ---
                        # Start search after the header
                        search_start = header_start_index + len(header)
                        file_data_list = [data_to_scan[header_start_index:]] # Start accumulating data
                        footer_found_offset = -1
                        total_file_bytes = len(file_data_list[0])
                        found_footer = False
                        read_ahead_chunks = 0

                        # Search within the current data first
                        footer_index_in_current = data_to_scan.find(footer, search_start)

                        if footer_index_in_current != -1:
                             # Footer found within the current data_to_scan buffer
                             footer_end_offset = footer_index_in_current + len(footer)
                             if (footer_end_offset - header_start_index) <= max_size:
                                 file_content = data_to_scan[header_start_index:footer_end_offset]
                                 footer_found_offset = current_pos + footer_end_offset
                                 found_footer = True
                                 logging.debug(f"Footer found within initial data at offset {footer_found_offset}")
                             else:
                                 logging.warning(f"Potential {ext.upper()} file exceeds max size ({max_size} bytes) within buffer. Skipping.")
                                 # Advance scan past this header
                                 scan_offset = header_start_index + 1 # Move past first byte of header
                                 continue # Skip this potential file

                        else:
                            # Footer not in current data, need to read ahead
                            logging.debug(f"Footer for {ext.upper()} not in current buffer, reading ahead...")
                            temp_file_pos = source_file.tell() # Save current file position

                            while total_file_bytes <= max_size:
                                read_ahead_chunk = source_file.read(chunk_size)
                                read_ahead_chunks += 1
                                if not read_ahead_chunk:
                                    logging.debug("EOF reached while searching for footer.")
                                    break # EOF

                                file_data_list.append(read_ahead_chunk)
                                total_file_bytes += len(read_ahead_chunk)

                                # Search for footer in the newly read chunk
                                # Consider overlap with the end of the previous chunk/buffer
                                search_in = file_data_list[-2][-max_footer_len:] + read_ahead_chunk if len(file_data_list) > 1 else read_ahead_chunk
                                footer_index_in_new = search_in.find(footer)

                                if footer_index_in_new != -1:
                                    # Found the footer in the read-ahead data
                                    # Calculate the end position relative to the start of the combined search_in data
                                    relative_footer_end = footer_index_in_new + len(footer)

                                    # Adjust if footer spanned the boundary
                                    if len(file_data_list) > 1 and footer_index_in_new < max_footer_len:
                                         # Footer started in the previous chunk's tail
                                         bytes_in_last_chunk = relative_footer_end - max_footer_len
                                    else:
                                         # Footer fully within the current chunk
                                         bytes_in_last_chunk = relative_footer_end

                                    # Trim the last chunk
                                    file_data_list[-1] = read_ahead_chunk[:bytes_in_last_chunk]
                                    total_file_bytes = sum(len(d) for d in file_data_list) # Recalculate exact size

                                    if total_file_bytes <= max_size:
                                        file_content = b"".join(file_data_list)
                                        footer_found_offset = source_file.tell() - (len(read_ahead_chunk) - bytes_in_last_chunk)
                                        found_footer = True
                                        logging.debug(f"Footer found after reading {read_ahead_chunks} chunk(s) at offset ~{footer_found_offset}")
                                        break # Footer found
                                    else:
                                         logging.warning(f"Potential {ext.upper()} file exceeds max size ({max_size} bytes) while reading ahead. Skipping.")
                                         found_footer = False # Mark as not found due to size
                                         break # Stop reading ahead

                            # Restore file position after read-ahead
                            source_file.seek(temp_file_pos)

                        # --- Save File if Footer Found ---
                        if found_footer:
                            recovered_counts[ext] += 1
                            sequence = recovered_counts[ext]
                            filename = f"{ext}_{sequence:05d}.{ext}"
                            filepath = os.path.join(output_dir, filename)
                            try:
                                with open(filepath, 'wb') as outfile:
                                    outfile.write(file_content)
                                logging.info(f"Recovered: {filename} ({len(file_content) / 1024:.2f} KiB) "
                                             f"[Header @ {current_pos + header_start_index}, "
                                             f"Footer @ ~{footer_found_offset}]")
                                found_file_in_chunk = True
                                # Advance scan offset past the recovered file's *header*
                                # Important: Don't skip past the whole file yet, other files might start within it.
                                scan_offset = header_start_index + 1 # Move past first byte of header
                            except IOError as e:
                                logging.error(f"Failed to write file '{filepath}': {e}")
                                # Still advance scan offset
                                scan_offset = header_start_index + 1
                        else:
                            # Footer not found within limits or read-ahead failed
                            logging.debug(f"Footer not found for potential {ext.upper()} starting at "
                                         f"{current_pos + header_start_index} within size/read limits.")
                            # Advance scan offset past this header to avoid re-detecting immediately
                            scan_offset = header_start_index + 1 # Move past first byte of header

                    # --- Prepare Buffer for Next Chunk ---
                    # Keep the end of the data_to_scan buffer in case a signature
                    # spans across the chunk boundary. The size should be enough
                    # to hold the largest header/footer.
                    buffer_preserve_size = max(max_header_len, max_footer_len)
                    buffer = data_to_scan[-buffer_preserve_size:]

                except MemoryError:
                    logging.error(
                        "Memory Error: The chunk size might be too large or the "
                        "system is running out of memory. Try a smaller chunk size."
                    )
                    sys.exit(1)
                except Exception as e:
                    logging.error(f"An unexpected error occurred during chunk processing: {e}")
                    # Attempt to continue if possible, advance position cautiously
                    try:
                        source_file.seek(chunk_size // 2, os.SEEK_CUR) # Skip half a chunk
                        buffer = b'' # Reset buffer after error
                        logging.warning("Attempting to skip problematic area.")
                    except Exception as seek_e:
                         logging.critical(f"Failed to recover from read error: {seek_e}. Aborting.")
                         break # Cannot continue


    except FileNotFoundError:
        logging.error(f"Source path not found: '{source_path}'")
        sys.exit(1)
    except PermissionError:
        logging.error(f"Permission denied accessing '{source_path}'.")
        if source_path.startswith('\\\\.\\'):
            logging.error("Try running the script as an administrator.")
        sys.exit(1)
    except IOError as e:
        logging.error(f"I/O error accessing '{source_path}': {e}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"An unexpected critical error occurred: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logging.info("-" * 30)
        logging.info("Scan complete.")
        if recovered_counts:
            logging.info("Recovery Summary:")
            for ext, count in recovered_counts.items():
                logging.info(f"  - {ext.upper()}: {count} file(s)")
        else:
            logging.info("No files matching the specified signatures were recovered.")
        logging.info(f"Total bytes processed: {processed_bytes / (1024*1024):,.2f} MiB")
        logging.info("-" * 30)


# --- Main Execution ---
if __name__ == "__main__":
    # Display ASCII Art Title
    # Ensure 'art' library is installed: pip install art
    try:
        ascii_title = text2art("ReSigma", font="graffiti") # You can try other fonts like 'standard', 'graffiti', etc.
        print(f"\033[94m{ascii_title}\033[0m")
        print("Welcome to ReSigma - Your Advanced Data Recovery and File Carving Tool!\n")
    except Exception as e:
        print(f"\033[94m[ReSigma - Data Recovery and File Carving Tool]\033[0m\n") # Fallback if art library fails
        logging.debug(f"Failed to generate ASCII art: {e}")
    parser = argparse.ArgumentParser(
        description="ReSigma: Unleash the power of data recovery! This tool meticulously carves files from raw disk images or devices.",
        epilog="Example usage:\n  python ReSigma.py -s \\\\.\\PhysicalDrive0 -o C:\\recovered_files -t jpg,pdf\n  python ReSigma.py -s my_image.dd -o ./output --log DEBUG\n\nStay vigilant, and may your lost data be found!",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-s", "--source",
        required=True,
        help="Path to the source raw device (e.g., \\\\.\C:) or disk image file (.dd, .img). Must be a valid file or device."
    )
    parser.add_argument(
        "-o", "--output",
        required=True,
        help="Directory to save recovered files. Will be created if it does not exist."
    )
    parser.add_argument(
        "-t", "--types",
        default="jpg,png,pdf,zip,gif,docx",
        help="Comma-separated list of file types to recover (default: jpg,png,pdf,zip,gif,docx)."
    )
    parser.add_argument(
        "-c", "--chunk_size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help="Chunk size in bytes for reading (default: 1048576)."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging."
    )

    args = parser.parse_args()

    # Enhanced input validation
    if not args.source or not isinstance(args.source, str) or not args.source.strip():
        logging.error("Invalid source path provided.")
        sys.exit(1)
    if not args.output or not isinstance(args.output, str) or not args.output.strip():
        logging.error("Invalid output directory provided.")
        sys.exit(1)
    if os.path.abspath(args.output) == os.path.abspath(os.getcwd()):
        logging.error("Output directory must not be the current working directory.")
        sys.exit(1)
    if os.path.exists(args.output) and not os.path.isdir(args.output):
        logging.error("Output path exists and is not a directory.")
        sys.exit(1)
    if os.path.abspath(args.output).startswith(os.path.abspath(os.getcwd())):
        logging.warning("Output directory is inside the current working directory. Consider using a dedicated location.")

    # Validate chunk size
    if args.chunk_size < 4096 or args.chunk_size > (1024 * 1024 * 1024):
        logging.error("Chunk size must be between 4 KiB and 1 GiB.")
        sys.exit(1)

    # Validate file types
    file_types = [ftype.strip().lower() for ftype in args.types.split(",") if ftype.strip()]
    for ftype in file_types:
        if ftype not in FILE_SIGNATURES:
            logging.error(f"Unsupported file type: {ftype}")
            sys.exit(1)

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    check_raw_device_access(args.source)

    try:
        carve_files(args.source, args.output, file_types, args.chunk_size)
    except Exception as e:
        logging.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

