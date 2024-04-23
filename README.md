# NFC Card Management Scripts

This project contains scripts for writing data to and verifying data on NTAG215 NFC tags using a Python.

## Prerequisites

* **Python 3**
* **pyscard** (`pip install pyscard`)
* **ndeflib** (`pip install ndeflib`)
* **preferredsoundplayer** (`pip install preferredsoundplayer`) or another module for playing sound files.
* **.env file** (See "Environment Variables" section)

## Usage

1. **Set up environment variables:**
   * Create a `.env` file in the project directory.
   * Add the following variables:
     ```
     NFC_URL=[https://some-random-url.com](https://some-random-url.com)
     PASSPHRASE=YourSecurePassphrase
     ```
   * Replace `https://some-random-url.com` with the actual URL you wish to encode on the NFC tags.
   * Choose a secure passphrase for tag protection.

2. **Writing data to an NFC tag:**
   * Place an NTAG215 tag near your NFC reader.
   * Execute `python write_card.py`

3. **Verifying data on an NFC tag:**
   * Place an NFC tag with the expected URL near your NFC reader.
   * Execute `python check_card.py`
   * The script will play a success or error sound based on whether the tag's data matches.

## Scripts

* **write_card.py**
    * Detects NTAG215 NFC tags.
    * Authenticates with the tag password (if set).
    * Encodes the URL from the `.env` file into an NDEF message.
    * Writes the NDEF message to the tag.
    * Sets a password on the tag for protection.

 * **check_card.py**
    * Detects NTAG215 NFC tags.
    * Reads the NDEF message from the tag.
    * Compares the stored URL with the expected URL from the `.env` file.
    * Plays a success or error sound to indicate the verification result.

## Environment Variables

The scripts use the following environment variables:

* **NFC_URL:** The URL to be written to NFC tags.
* **PASSPHRASE:** The passphrase used to protect NFC tags (optional).

## Notes:

* These scripts are designed specifically for NTAG215 NFC tags.
* The scripts are tested on Windows 11 with an ACR1252U NFC reader.
