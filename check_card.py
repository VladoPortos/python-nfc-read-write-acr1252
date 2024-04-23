from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import toHexString
from smartcard.CardConnection import CardConnection
import os
import ndef
from dotenv import load_dotenv
from preferredsoundplayer import *

# Load environment variables from .env file
load_dotenv()
# Access variables
NFC_URL: str = os.getenv('NFC_URL', 'https://some-random-url.com')
PASSPHRASE: str = os.getenv('NFC_PASSPHRASE', 'YourSecurePassphrase')


def read_ndef_message(connection: CardConnection, expected_message: bytes) -> bool:
    """Reads the NDEF message from the NFC tag and compares it to the expected message."""
    print("Expected NDEF message:", expected_message.hex())
    # Start reading from the expected starting page of NDEF message
    read_command = [0xFF, 0xB0, 0x00, 4, 0x04]
    message = b''
    try:
        while True:  # Loop to read all parts of the NDEF message
            response, sw1, sw2 = connection.transmit(read_command)
            if sw1 == 0x90 and sw2 == 0x00:
                message += bytes(response[:4])  # Append only the NDEF data
                # print(f"Read data from page {read_command[3]}: {bytes(response[:4]).hex()}")
                if 0xFE in response:  # Look for end byte of NDEF message within the response
                    break
                read_command[3] += 1  # Move to the next page
            else:
                print(f"Failed to read at page {
                      read_command[3]}: SW1={sw1:02X}, SW2={sw2:02X}")
                return False

        print("Read NDEF message:", message.hex())
        if message == expected_message:
            print("Verification successful: Data matches the expected NDEF message.")
            return True
        else:
            print("Verification failed: Data does not match the expected NDEF message.")
            return False
    except Exception as e:
        print(f"Error during reading: {e}")
        return False


def beep(success: bool) -> None:
    """
    Plays a sound based on the success status.

    Args:
        success (bool): Indicates whether the operation was successful or not.

    Returns:
        None
    """
    if success:
        soundplay('ok.wav')
    else:
        soundplay('error.wav')


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
    initial_message = b'\x03' + \
        message_length.to_bytes(1, 'big') + encoded_message + b'\xFE'

    # Calculate padding to align to the nearest block size (assuming 4 bytes per block)
    padding_length = -len(initial_message) % 4
    complete_message = initial_message + (b'\x00' * padding_length)
    return complete_message

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

                expected_ndef_message = create_ndef_record(NFC_URL)

                if read_ndef_message(connection, expected_ndef_message):
                    beep(True)  # On success
                else:
                    beep(False)  # On failure

                cards_processed += 1
                print(f"Total cards processed: {cards_processed}")

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
        print("Stopped NFC card processing. Total cards processed:", cards_processed)


if __name__ == "__main__":
    cards_processed = 0
    main()
