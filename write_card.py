
from typing import Dict, List
from dotenv import load_dotenv
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import toHexString
from smartcard.CardConnection import CardConnection
from smartcard.System import *
import hashlib
import os
import ndef

# Load environment variables from .env file
load_dotenv()
# Access variables
NFC_URL: str = os.getenv('NFC_URL', 'https://some-random-url.com')
PASSPHRASE: str = os.getenv('NFC_PASSPHRASE', 'YourSecurePassphrase')




def decode_atr(atr: str) -> Dict[str, str]:
    """Decode the ATR (Answer to Reset) string into readable components.

    Args:
        atr (str): ATR string.

    Returns:
        Dict[str, str]: Dictionary containing readable information about the card.
    """
    atr = atr.split(" ")

    rid = atr[7:12]
    standard = atr[12]
    card_name = atr[13:15]

    card_names = {
        "00 01": "MIFARE Classic 1K",
        "00 38": "MIFARE Plus® SL2 2K",
        "00 02": "MIFARE Classic 4K",
        "00 39": "MIFARE Plus® SL2 4K",
        "00 03": "MIFARE Ultralight®",
        "00 30": "Topaz and Jewel",
        "00 26": "MIFARE Mini®",
        "00 3B": "FeliCa",
        "00 3A": "MIFARE Ultralight® C",
        "FF 28": "JCOP 30",
        "00 36": "MIFARE Plus® SL1 2K",
        "FF[SAK]": "undefined tags",
        "00 37": "MIFARE Plus® SL1 4K",
        "00 07": "SRIX"
    }

    standards = {
        "03": "ISO 14443A, Part 3",
        "11": "FeliCa"
    }

    return {
        "RID": " ".join(rid),
        "Standard": standards.get(standard, "Unknown"),
        "Card Name": card_names.get(" ".join(card_name), "Unknown")
    }


def authenticate_with_password(connection: CardConnection, passphrase: str) -> bool:
    """Authenticate with the NTAG215 NFC tag using the provided passphrase.

    Args:
        connection (CardConnection): Connection to the card.
        passphrase (str): Passphrase for authentication.

    Returns:
        bool: True if authentication is successful, otherwise False.
    """
    password = derive_password(passphrase)

    command = [0xFF, 0x00, 0x00, 0x00, 0x07, 0xD4, 0x42, 0x1B] + password
    response, sw1, sw2 = connection.transmit(command)

    # print(f"Command being sent for authentication: {' '.join(f'{byte:02X}' for byte in command)}")
    # print(f"Response: {' '.join(f'{byte:02X}' for byte in response)}, SW1: {sw1:02X}, SW2: {sw2:02X}")

    if sw1 == 0x90 and sw2 == 0x00:
        # Check if the PACK is part of the response and correctly positioned
        if len(response) >= 5:  # Ensuring the response is long enough
            # Adjust this based on where PACK actually appears
            pack = response[3:5]
            print("Authentication successful, PACK received:",
                  ' '.join(f'{byte:02X}' for byte in pack))
            return True
        else:
            print("PACK not received or incorrectly formatted")
    else:
        print("Authentication failed")
    return False


def create_ndef_record(url: str) -> bytes:
    """Encodes a given URI into a complete NDEF message using ndeflib.

    Args:
        url (str): The URI to be encoded into an NDEF message.

    Returns:
        bytes: The complete NDEF message as bytes, ready to be written to an NFC tag.
    """

    uri_record = ndef.UriRecord(url)

    # Encode the NDEF message
    encoded_message = b''.join(ndef.message_encoder([uri_record]))

    # Calculate total length of the NDEF message (excluding start byte and terminator)
    message_length = len(encoded_message)

    # Create the initial part of the message with start byte, length, encoded message, and terminator
    initial_message = b'\x03' + message_length.to_bytes(1, 'big') + encoded_message + b'\xFE'

    # Calculate padding to align to the nearest block size (assuming 4 bytes per block)
    padding_length = -len(initial_message) % 4
    complete_message = initial_message + (b'\x00' * padding_length)
    return complete_message


def write_ndef_message(connection: CardConnection, ndef_message: bytes) -> bool:
    """Writes the NDEF message to the NFC tag.

    Args:
        connection (CardConnection): The connection to the NFC tag.
        ndef_message (bytes): The NDEF message to be written.

    Returns:
        bool: True if the write operation is successful, False otherwise.
    """
    page = 4
    while ndef_message:
        block_data = ndef_message[:4]
        ndef_message = ndef_message[4:]
        WRITE_COMMAND = [0xFF, 0xD6, 0x00, page, 0x04] + list(block_data)
        response, sw1, sw2 = connection.transmit(WRITE_COMMAND)
        if sw1 != 0x90 or sw2 != 0x00:
            print(f"Failed to write to page {
                  page}, SW1: {sw1:02X}, SW2: {sw2:02X}")
            return False
        print(f"Successfully wrote to page {page}")
        page += 1
    return True


def derive_password(passphrase: str) -> List[int]:
    """Hash passphrase and return first 4 bytes as password for NFC tag authentication.

    Args:
        passphrase (str): Passphrase to hash.

    Returns:
        List[int]: List of the first 4 bytes of the hash.
    """
    hasher = hashlib.sha256()
    hasher.update(passphrase.encode())
    # print(f"Hashed passphrase: {hasher.hexdigest()}")
    # print(f"Password: {list(hasher.digest()[:4])}")
    return list(hasher.digest()[:4])


def set_password(connection: CardConnection, passphrase: str) -> None:
    """
    Set password protection on an NTAG215 NFC tag.

    Args:
        connection (CardConnection): The connection to the NFC tag.
        passphrase (str): The passphrase used to derive the password.
    """
    # Addr 82: LOCK2 - LOCK4
    # Addr 83: CFG 0 (MIROR/AUTH0)
    # Addr 84: CFG 1 (ACCESS)
    # Addr 85: PWD0 - PWD3
    # Addr 86: PACK0 - PACK1

    password = derive_password(passphrase)

    pack = [0x00, 0x00]  # Example PACK, adjust as needed

    # Write password to page 0x85
    connection.transmit([0xFF, 0xD6, 0x00, 0x85, 0x04] + password)

    # Write PACK to page 0x86
    connection.transmit([0xFF, 0xD6, 0x00, 0x86, 0x04] + pack)

    # Set AUTH0 to enable password protection from a specific page
    # Example: Protect from page 4 onwards
    # AUTH0 is at page 0x83, last byte of the 4-byte page
    auth0_command = [0xFF, 0xD6, 0x00, 0x83, 0x04, 0x00, 0x00, 0x00, 0x04]
    connection.transmit(auth0_command)

    # Set ACCESS configuration
    # Example: Enable both read and write protection
    # ACCESS is at page 0x84, typically a single-byte configuration
    # Adjust 0x80 as needed based on datasheet
    access_command = [0xFF, 0xD6, 0x00, 0x84, 0x01, 0x80]
    connection.transmit(access_command)

    print("Password and protection configuration set.")


def remove_password(connection: CardConnection, passphrase: str) -> None:
    """
    Remove password protection from an NTAG215 NFC tag.

    Args:
        connection (CardConnection): The connection to the NFC tag.
        passphrase (str): The passphrase used to derive the password.
    """
    password = derive_password(passphrase)

    # Authenticate with the password first
    # Assuming that the tag requires password authentication for writing
    connection.transmit([0xFF, 0x00, 0x00, 0x00] + password + [0x00])

    # Disable password protection by setting AUTH0 beyond the tag's storage
    # Example: set AUTH0 to 0xFF to disable all protections
    disable_auth0_command = [0xFF, 0xD6, 0x00,
                             0x83, 0x04, 0x00, 0x00, 0x00, 0xFF]
    response, sw1, sw2 = connection.transmit(disable_auth0_command)
    if sw1 == 0x90 and sw2 == 0x00:
        print("Password protection successfully removed.")
    else:
        print(f"Failed to remove password protection, SW1: {sw1}, SW2: {sw2}")


def is_password_set(connection: CardConnection) -> bool:
    """
    Check if a password is set on an NTAG215 tag by reading the AUTH0 register.

    Args:
        connection (CardConnection): The connection to the NFC tag.

    Returns:
        bool: True if a password is set (AUTH0 not 0xFF), otherwise False.
    """
    # Address 0x83 is used for AUTH0 in NTAG215
    # Convert page address to byte address if necessary
    page_address = 0x83
    # APDU for reading one page (4 bytes)
    read_command = [0xFF, 0xB0, 0x00, page_address, 0x04]

    try:
        response, sw1, sw2 = connection.transmit(read_command)
        # print(f"Read AUTH0, Response: {' '.join(f'{byte:02X}' for byte in response)}, SW1: {sw1:02X}, SW2: {sw2:02X}")

        if sw1 == 0x90 and sw2 == 0x00:
            # Response is expected to be 4 bytes, AUTH0 is the last byte
            auth0 = response[3]
            # print(f"AUTH0 register value: {auth0:02X}")

            # Check if AUTH0 is 0xFF for no password protection
            if auth0 == 0xFF:
                # print("No password protection is set.")
                return False
            else:
                # print("Password protection is set.")
                return True
        else:
            print("Failed to read AUTH0 register.")
            return False

    except Exception as e:
        print(f"An error occurred: {e}")
        return False


class NTAG215Observer(CardObserver):
    """Observer class for NFC card detection and processing."""

    def update(self, observable, actions):
        global cards_processed
        (addedcards, _) = actions
        for card in addedcards:
            print(f"Card detected, ATR: {toHexString(card.atr)}")
            try:
                connection = card.createConnection()
                connection.connect()
                print("Connected to card")

                # if password is set, authenticate
                if is_password_set(connection):
                    authenticate_with_password(connection, PASSPHRASE)

                # Write NDEF message to tag
                write_ndef_message(connection, create_ndef_record(NFC_URL))

                # if password is not set, set password
                if not is_password_set(connection):
                    set_password(connection, PASSPHRASE)

                # Get card information
                # info = decode_atr(toHexString(card.atr))
                # print(f"Card Name: {info['Card Name']}, Standard: {
                #       info['Standard']}, RID: {info['RID']}")

                # # Get card UID
                # SELECT = [0xFF, 0xCA, 0x00, 0x00, 0x00]
                # response, sw1, sw2 = connection.transmit(SELECT)
                # uid = toHexString(response)
                # print(f"Card UID: {uid}")

                # Authenticate with the password
                # authenticate_with_password(connection, PASSPHRASE)
                # Remove password protection from the tag
                # remove_password(connection, PASSPHRASE)

                cards_processed += 1
                print(f"Total cards flashed: {cards_processed}")

            except Exception as e:
                print(f"An error occurred: {e}")


def main():
    print("Starting NFC card processing...")
    cardmonitor = CardMonitor()
    cardobserver = NTAG215Observer()
    cardmonitor.addObserver(cardobserver)

    try:
        input("Press Enter to stop...\n")
    finally:
        cardmonitor.deleteObserver(cardobserver)
        print(f"Stopped NFC card processing. Total cards processed: {
              cards_processed}")


if __name__ == "__main__":
    # get and print a list of readers attached to the system
    # sc_readers = readers()
    # print(sc_readers)
    cards_processed: int = 0
    main()
