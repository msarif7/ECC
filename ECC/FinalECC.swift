import Foundation
import Security
import CryptoKit

class EccUtility {
    private var privateKey: SecKey?
    private var publicKey: SecKey?
    private var certificate: SecCertificate?
    private var KEY_ALIAS = "MY ECC KEY"
    let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
    private var error: Unmanaged<CFError>?
    
    func generateKey() {
        // Specify parameters for private key generation
        let privateKeyParams: [String: Any] = [
            kSecAttrIsPermanent as String: true, // Key should be stored permanently in Keychain
            kSecAttrApplicationTag as String: KEY_ALIAS, // A unique tag to identify this key
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave, // Key should be stored in the Secure Enclave (if available)
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, // Key type is Elliptic Curve Cryptography (ECC)
            kSecAttrKeySizeInBits as String: 256 // Key size is 256 bits
        ]

        // Generate a random ECC key pair, with the specified private and public key parameters
        guard let privateKeyData = SecKeyCreateRandomKey(privateKeyParams as CFDictionary, &error),
            let publicKeyData = SecKeyCopyPublicKey(privateKeyData) else {
                // If key generation fails, print the error message and return
                print("Failed to generate ECC key pair: \(String(describing: error?.takeRetainedValue()))")
                return
        }

        // Assign the generated keys to their respective variables
        self.privateKey = privateKeyData
        self.publicKey = publicKeyData
    }

    func signData(data: Data) -> Data? {
        // Attempt to sign the data using the private key
        guard let signature = SecKeyCreateSignature(privateKey!, algorithm, data as CFData, &error) as Data? else {
            // If signing fails, print an error message and return nil
            print("Failed to sign data: \(String(describing: error?.takeRetainedValue()))")
            return nil
        }
        
        // Return the signature
        return signature
    }

    func verifyData(data: Data, signature: Data) -> Bool {
        // Verify the signature using the public key
        return SecKeyVerifySignature(publicKey!, algorithm, data as CFData, signature as CFData, &error)
    }

}
