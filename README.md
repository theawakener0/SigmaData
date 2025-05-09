# <div align="center">`ReSigma.py` - Advanced File Carver</div>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status: Active">
</p>

<p align="center">
  <em>"An Open Source tool designed for advanced file carving and digital forensics"</em>
</p>



## 🌟 Overview

`ReSigma.py` is a Python-based file carving tool designed to recover files from raw disk images or storage devices by identifying and extracting data based on known file signatures (headers and footers). It's built for digital forensics, data recovery, and for anyone needing to retrieve lost or deleted files from unallocated space or corrupted file systems.

This tool was born out of a need for a flexible, understandable, and extensible file carving solution that can be easily modified and adapted to new file types and recovery scenarios.

## ✨ Features

*   **Signature-Based Carving**: Identifies files using a comprehensive list of headers and footers for various file types.
*   **Chunk-Based Processing**: Reads data in manageable chunks, making it efficient for large disk images.
*   **Configurable File Types**: Easily extendable to support new file formats by adding their signatures.
*   **Max Size Limits**: Prevents runaway carving for files with missing or ambiguous footers by enforcing maximum file sizes.
*   **Progress Reporting**: Provides real-time feedback on the carving process.
*   **Windows Raw Device Access**: Can directly access raw disk devices (e.g., `\\.\PhysicalDrive0`) with administrative privileges.
*   **Detailed Logging**: Outputs information about found files, errors, and progress.
*   **Open Source**: Freedom to inspect, modify, and improve.

## 🚀 How to Use

`ReSigma.py` is a command-line tool. You'll need Python 3 installed, along with the `art` library for the cool ASCII art title in the script's output.

### Installation

1.  Ensure you have Python 3.7+ installed.
2.  Install the required `art` library:
    ```bash
    pip install art
    ```

### Command-Line Arguments

```
usage: ReSigma.py [-h] -s SOURCE_PATH -o OUTPUT_DIR [-t FILE_TYPES [FILE_TYPES ...]] [-c CHUNK_SIZE]

Advanced File Carver - ReSigma

options:
  -h, --help            show this help message and exit
  -s SOURCE_PATH, --source SOURCE_PATH
                        Path to the raw disk image or device (e.g., /dev/sdb, \\.\PhysicalDrive0, image.dd)
  -o OUTPUT_DIR, --output OUTPUT_DIR
                        Directory to save recovered files.
  -t FILE_TYPES [FILE_TYPES ...], --types FILE_TYPES [FILE_TYPES ...]
                        File types to recover (e.g., jpg png pdf). Default is all known types.
  -c CHUNK_SIZE, --chunk CHUNK_SIZE
                        Chunk size in bytes for reading the source. Default: 1048576 (1MB).
```

*(Note: The help message above is a representation. Run `python ReSigma.py --help` for the exact output.)*

### Examples

1.  **Carve all known file types from a disk image `image.dd` and save to `recovered_files` directory:**
    ```bash
    python ReSigma.py -s image.dd -o recovered_files
    ```

2.  **Carve only JPG and PDF files from a raw device `\\.\PhysicalDrive1` (requires admin rights on Windows):**
    ```bash
    python ReSigma.py -s \\.\PhysicalDrive1 -o C:\RecoveryOutput -t jpg pdf
    ```
    *(Remember to run your command prompt or terminal as Administrator for raw device access on Windows.)*

3.  **Carve files using a custom chunk size of 2MB:**
    ```bash
    python ReSigma.py -s my_data.img -o recovered_stuff -c 2097152
    ```

## 📁 Supported File Types (Default)

`ReSigma.py` comes pre-configured with signatures for a variety of common file types, including but not limited to:

*   **Images**: JPG, PNG, GIF, BMP, PSD
*   **Documents**: PDF, DOCX, RTF, PPTX, XLSX
*   **Archives**: ZIP, RAR, 7Z
*   **Audio**: MP3, WAV, FLAC, OGG
*   **Video**: MPG, AVI, MOV, MP4, MKV
*   **Executables**: EXE

*This list is defined in the `FILE_SIGNATURES` dictionary within the script and can be easily expanded.*

## 💡 Why ReSigma?

I created `ReSigma.py` for several reasons:

1.  **Learning & Exploration**: To deepen my understanding of file systems, data structures, and the intricacies of file carving. It's a hands-on way to learn about how data is stored and recovered.
2.  **Customization**: Existing tools are often powerful but can be black boxes. I wanted a tool where I could easily tweak parameters, add new file signatures quickly, and understand the underlying logic.
3.  **Specific Needs**: Sometimes, you encounter scenarios where generic tools don't quite fit. `ReSigma.py` provides a base that can be tailored for specific forensic investigations or data recovery tasks.
4.  **Educational Tool**: It can serve as an educational resource for others interested in learning about file carving techniques.

## 🌍 Why Open Source?

Making `ReSigma.py` open source was a deliberate choice driven by these principles:

1.  **Collaboration & Improvement**: The collective intelligence of a community can lead to a much better tool. Others can contribute new signatures, improve algorithms, fix bugs, and add features I haven't thought of.
2.  **Transparency & Trust**: In fields like digital forensics and data recovery, it's crucial to understand how tools work. Open source allows anyone to inspect the code, verify its behavior, and trust its results.
3.  **Accessibility**: Making the tool freely available means anyone can use it, regardless of budget. This is particularly important for students, independent researchers, and small organizations.
4.  **Giving Back**: I've benefited immensely from open-source software. This is a way to contribute back to the community.
5.  **Innovation**: Open source fosters innovation. By providing the source code, others can build upon it, adapt it for new purposes, and push the boundaries of what's possible.

## 🤝 Contributing

Contributions are welcome! If you'd like to contribute:

1.  **Fork the repository.**
2.  **Create a new branch** for your feature or bug fix.
3.  **Add your changes** (e.g., new file signatures, improved carving logic, bug fixes).
4.  **Test your changes thoroughly.**
5.  **Submit a pull request** with a clear description of your changes.

Some areas for potential contribution:
*   Adding more file signatures (especially for less common or newer formats).
*   Improving footer detection logic for complex file types.
*   Implementing more advanced carving techniques (e.g., validation of internal file structures).
*   Adding support for carving from fragmented files.
*   Performance optimizations.
*   GUI development.

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

<p align="center">Happy Carving!</p>