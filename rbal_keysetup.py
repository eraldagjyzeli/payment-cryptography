# python3 -m pip install psec
# python3 -m pip install binascii
# python3 -m pip install boto3
# python3 -m pip install pycryptodome

import hashlib
import sys
from Crypto.CMAC import CMAC
from Crypto.Cipher import AES
from binascii import unhexlify, hexlify
import boto3

def generate_cmac_b(message, key):
c = CMAC.new(key, ciphermod=AES)
c.update(message)
return c.digest().hex()

def calculate_ccv_aes(aes_key: str) -> str:
    message = bytes.fromhex("00000000000000000000000000000000")
    kcv = generate_cmac_b(message, bytes.fromhex(aes_key))
    return kcv.hex().upper()[0:6]

def xor_hex_strings(hex_str1, hex_str2):
    # Convert hex strings to byte arrays
    bytes1 = bytes.fromhex(hex_str1)
    bytes2 = bytes.fromhex(hex_str2)
    
    # Ensure both byte arrays are of the same length
    if len(bytes1) != len(bytes2):
        raise ValueError("Hex strings must be of the same length")
    
    # Perform XOR operation between the byte arrays
    xor_result = bytes(a ^ b for a, b in zip(bytes1, bytes2))
    
    # Convert the result back to a hexadecimal string
    xor_hex_str = xor_result.hex().upper()
    
    return xor_hex_str

if __name__ == "__main__":
    zone_master_key_components = []
    for i in range(3):
        component = input(f"Enter component {i+1} of the Zone Master Key: ")
        component = component.replace(' ', '')
        print("component: ", component)
        ccv_entered = input("Enter the CCV: ")

        ccv_value = calculate_ccv_aes(component)
        print("CCV: ", ccv_value)
        if ccv_value == ccv_entered:
            print("CCV is valid.")
        else:
            print("CCV is invalid.")

        zone_master_key_components.append(component)
        #print("zone_master_key_components: ", zone_master_key_components)

    xor_result = xor_hex_strings(zone_master_key_components[0], zone_master_key_components[1])
    zmk = xor_hex_strings(xor_result, zone_master_key_components[2])
    print("ZMK: ", zmk)
    kcv_value = calculate_ccv_aes(zmk)
    print("ZMK KCV: ", kcv_value)

    # Prompt the user to input Y or N to validate kcv_value
    user_input = input("Is ZMK KCV valid? (Y/N): ").strip().upper()

    # Check the user's input
    if user_input == 'Y':
        # Continue with the rest of the code
        print("kcv_value is valid. Continuing...")
        # Your existing code here
    elif user_input == 'N':
        # Exit the program
        print("kcv_value is not valid. Exiting...")
        sys.exit(1)
    else:
        # Handle invalid input
        print("Invalid input. Please enter Y or N.")
        sys.exit(1)

    # Prompt the user to enter PEK (ZPK) value
    pek_value = input(f"Enter ZPK (Zone Pin Key): ")
    pek_kcv_value = calculate_ccv_aes(pek_value)
    print("ZPK KCV: ", pek_kcv_valuekcv_value)

     # Prompt the user to input Y or N to validate kcv_value
    user_input = input("Is ZPK KCV valid? (Y/N): ").strip().upper()

    # Check the user's input
    if user_input == 'Y':
        # Continue with the rest of the code
        print("kcv_value is valid. Continuing...")
        # Your existing code here
    elif user_input == 'N':
        # Exit the program
        print("kcv_value is not valid. Exiting...")
        sys.exit(1)
    else:
        # Handle invalid input
        print("Invalid input. Please enter Y or N.")
        sys.exit(1)

    """
    This script is intended to import all the keys needed for the AWS Payment Cryptography 
    """
    import import_tr34_raw_key_to_apc as tr34
    import import_tr31_raw_key_to_apc as tr31
    import boto3

    """ Key encryption key which will be used to import subsequent keys """
    KEK = zmk
    """ KEK = '8A8349794C9EE9A4C2927098F249FED6' """

    """ Base Derivation Key which will be used to generate DUKPT """
    BDK = '8A8349794C9EE9A4C2927098F249FED6'
    bdkAlias = 'alias/MerchantTerminal_BDK'

    """ Pin Encryption Key. For the samples, the same key will be shared between ATM, Pin tranlation service and Issuer. 
    This is to show that ATM can directly talk to issuer service to set and verify pin. 
    ATM can also go through intermediate PinTranslateService which makes call to Issuer to set and verify Pin. """
    PEK = 'B0096P0TE00E0000740F3483D8009BEF31D00DD09EE41A1FC378B925E44F674471C2277090BD3D3F1ABB2A79502442EB'
    pinTranslateServicePekAlias = "alias/pinTranslateServicePek"
    issuerPekAlias = 'alias/issuerPek'

    issuerGenerationAlias = 'alias/issuerPinValidationKey'

    """ MAC key for HMAC verification """
    MAC = '75BDAEF54587CAE6563A5CE57B4B9F9F'
    """ MAC = '8A8349794C9EE9A4C2927098F249FED6' """
    macAlias = 'alias/tr31_macValidationKey'


    apc_client = boto3.client('payment-cryptography')

    def GeneratePvk(issuerGenerationAlias):
        #create PVK
        keyModesOfUse = {'Generate':True,'Verify':True}
        keyAttributes = {'KeyAlgorithm':'TDES_2KEY','KeyUsage':'TR31_V2_VISA_PIN_VERIFICATION_KEY','KeyClass':'SYMMETRIC_KEY','KeyModesOfUse':keyModesOfUse}

        PvkKeyARN = apc_client.create_key(Exportable=True,KeyAttributes=keyAttributes)['Key']['KeyArn']

        try:
            aliasList = apc_client.get_alias(AliasName=issuerGenerationAlias)

            if 'KeyArn' in aliasList['Alias']:
                keyDetails = apc_client.get_key(KeyIdentifier=aliasList['Alias']['KeyArn'])
                if (keyDetails['Key']['KeyState'] == 'CREATE_COMPLETE'):
                    apc_client.delete_key(KeyIdentifier=aliasList['Alias']['KeyArn'], DeleteKeyInDays=3)
            apc_client.update_alias(AliasName=aliasList['Alias']['AliasName'],KeyArn=PvkKeyARN)

        except apc_client.exceptions.ResourceNotFoundException:
            aliasList = apc_client.create_alias(AliasName=issuerGenerationAlias,KeyArn=PvkKeyARN)
        return PvkKeyARN,issuerGenerationAlias

    if __name__ == "__main__":

        print("")
        print("*********Importing a KEK for importing subsequent keys*********")
        print("")

        tr34_response = tr34.importTr34("ONLINE",KEK,"E","K0","B","","")
        print("KEK/KPBK/ZMK ARN:",tr34_response[0])


        print("")
        print("*********Importing a BDK for DUKPT*********")
        print("")
        response = tr31.importTR31(KEK,BDK,"E","B0","X","T","ONLINE",tr34_response[0],None,bdkAlias)
        print("BDK ARN:",response[0])
        print("Alias",response[1])


        print("")
        print("*********Importing a PEK for communicating with ATM*********")
        print("")
        response = tr31.importTR31a(KEK,PEK,"E","P0","B","T","ONLINE",tr34_response[0],None,pinTranslateServicePekAlias)
        print("PEK(ATM PEK) ARN:",response[0])
        print("Alias:",response[1])

        print("")
        print("*********Importing a PEK for Pin Translate Service to Issuer communication. This service sits between between issuer and ATM) *********")
        print("")
        response = tr31.importTR31a(KEK,PEK,"E","P0","B","T","ONLINE",tr34_response[0],None,issuerPekAlias)
        print("PEK(ATM PEK) ARN:",response[0])
        print("Alias:",response[1])

        print("")
        print("*********Generating a PGK for generating a PVV*********")
        print("")

        response = GeneratePvk(issuerGenerationAlias)

        print("Pin Verification Value ARN",response[0])
        print("Pin Verification Value Alias",response[1])

        print("")
        print("*********Generating a MAC key for MAC verification********")
        print("")

        response =  tr34.importTr34("ONLINE",MAC,"E","M3","C","")

        try:
            alias_res = apc_client.get_alias(AliasName=macAlias)
        except apc_client.exceptions.ResourceNotFoundException:
            alias_res = apc_client.create_alias(AliasName=macAlias)

        
        macResponse = apc_client.update_alias(AliasName=macAlias,KeyArn=response[0])
        print("MAC Key Alias:",macResponse['Alias']['AliasName'])
        print("MAC Key ARN:",macResponse['Alias']['KeyArn'])

        
        print("")
        print("*********Done*********")
        print("")

