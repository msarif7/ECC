import Foundation
import Security
import CryptoKit

class EccUtility {
    private var privateKey: SecKey?
    private var publicKey: SecKey?
    private var certificate: SecCertificate?

    func createCertificate() {
        // Define an optional variable to hold any errors that occur during the key copy
        var error: Unmanaged<CFError>?

        // Attempt to get the public key data using SecKeyCopyExternalRepresentation
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey!, &error) as Data? else {
            // If an error occurs, print an error message and return nil
            print("Failed to get public key data: \(error?.takeRetainedValue().localizedDescription ?? "Unknown error")")
            return
        }

        // Calculate the SHA-256 hash of the public key data
        let publicKeyHash = SHA256.hash(data: publicKeyData)

        // Convert the hash to a Data object
        let publicKeyHashData = Data(publicKeyHash)

        // Generate a 5-byte serial number for the certificate
        let serialNumber = Data([UInt8](repeating: 0, count: 5).map { _ in UInt8(arc4random_uniform(256)) })

        // Create a dictionary of attributes for the certificate
        let certificateAttributes: CFDictionary = [
            // Specify that the certificate's key type is ECDSA
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            // Specify that the key size is 256 bits
            kSecAttrKeySizeInBits as String: 256,
            // Specify that the certificate should be stored in the Secure Enclave
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            // Specify the hash of the public key as an attribute
            kSecAttrPublicKeyHash as String: publicKeyHashData as CFData,
            // Specify the serial number as an attribute
            kSecAttrSerialNumber as String: serialNumber as CFData,
            // Specify the subject name for the certificate
            kSecAttrSubject as String: "My Entity" as CFString
        ] as CFDictionary

        do {
            // Use NSKeyedArchiver to serialize the certificate attributes as data
            let certificateData = try NSKeyedArchiver.archivedData(withRootObject: certificateAttributes, requiringSecureCoding: false)
            
            // Create a SecCertificate object using the serialized data
            if let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) {
                // If the certificate is successfully created, assign it to the certificate property
                self.certificate = certificate
            } else {
                // If creating the certificate fails, print an error message and return nil
                print("Failed to create certificate")
                return
            }
        } catch {
            // If an error occurs during serialization, print an error message and return nil
            print("Failed to archive certificate attributes: \(error)")
            return
        }
    }
    
    func generateKey() {
        // Specify parameters for private key generation
        let privateKeyParams: [String: Any] = [
            kSecAttrIsPermanent as String: true, // Key should be stored permanently in Keychain
            kSecAttrApplicationTag as String: "com.example.privatekey", // A unique tag to identify this key
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave, // Key should be stored in the Secure Enclave (if available)
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, // Key type is Elliptic Curve Cryptography (ECC)
            kSecAttrKeySizeInBits as String: 256 // Key size is 256 bits
        ]

       
        var error: Unmanaged<CFError>?

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
        // Sign the data using the private key
        var error: Unmanaged<CFError>?
        
        // Select the algorithm for signing, in this case "ecdsaSignatureMessageX962SHA256"
        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        
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
        var error: Unmanaged<CFError>?
        
        // Select the algorithm for verifying, in this case "ecdsaSignatureMessageX962SHA256"
        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        
        // Verify the signature using the public key
        return SecKeyVerifySignature(publicKey!, algorithm, data as CFData, signature as CFData, &error)
    }

}
