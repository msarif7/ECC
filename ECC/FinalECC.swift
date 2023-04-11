import Foundation
import Security
import CryptoKit

class EccUtility {
    private var privateKey: SecKey?
    private var publicKey: SecKey?
    private var certificate: SecCertificate?

    func createCertificate() {
        var error: Unmanaged<CFError>?


        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey!, &error) as Data? else {
            print("Failed to get public key data: \(error?.takeRetainedValue().localizedDescription ?? "Unknown error")")
            return
        }

        let publicKeyHash = SHA256.hash(data: publicKeyData)
        let publicKeyHashData = Data(publicKeyHash)
        
        let serialNumber = Data([UInt8](repeating: 0, count: 5).map { _ in UInt8(arc4random_uniform(256)) })

        let certificateAttributes: CFDictionary = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrPublicKeyHash as String: publicKeyHashData as CFData,
            kSecAttrSerialNumber as String: serialNumber as CFData,
            kSecAttrSubject as String: "My Entity" as CFString
        ] as CFDictionary

        do {
            let certificateData = try NSKeyedArchiver.archivedData(withRootObject: certificateAttributes, requiringSecureCoding: false)
            if let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) {
                self.certificate = certificate
            } else {
                print("Failed to create certificate")
                return
            }
        } catch {
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

        // Declare variables to hold the generated private and public keys, as well as any error that may occur
        var privateKey: SecKey?
        var publicKey: SecKey?
        var error: Unmanaged<CFError>?

        // Generate a random ECC key pair, with the specified private and public key parameters
        guard let privateKeyData = SecKeyCreateRandomKey(privateKeyParams as CFDictionary, &error),
            let publicKeyData = SecKeyCopyPublicKey(privateKeyData) else {
                // If key generation fails, print the error message and return
                print("Failed to generate ECC key pair: \(String(describing: error?.takeRetainedValue()))")
                return
        }

        // Assign the generated keys to their respective variables
        privateKey = privateKeyData
        publicKey = publicKeyData

        // Specify parameters for adding the private key to the Keychain
        let privateKeyAddQuery: [String: Any] = [
            kSecValueRef as String: privateKey!, // The key to be added to the Keychain
            kSecAttrApplicationTag as String: "com.example.privatekey", // The unique tag of the key being added
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, // The key should be accessible only when the device is unlocked
            kSecClass as String: kSecClassKey, // The item to be added is a key
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, // The key type is ECC
            kSecReturnPersistentRef as String: true // Return a persistent reference to the key
        ]

        // Specify parameters for adding the public key to the Keychain
        let publicKeyAddQuery: [String: Any] = [
            kSecValueRef as String: publicKey!, // The key to be added to the Keychain
            kSecAttrApplicationTag as String: "com.example.publickey", // The unique tag of the key being added
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, // The key should be accessible only when the device is unlocked
            kSecClass as String: kSecClassKey, // The item to be added is a key
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, // The key type is ECC
            kSecReturnPersistentRef as String: true// Return a persistent reference to the key
        ]
        
        // This initializes a variable to hold the result of the Keychain operation.
        var result: AnyObject?

        // This adds the private key to the Keychain.
        var status = SecItemAdd(privateKeyAddQuery as CFDictionary, &result)

        // If adding the private key fails, it prints an error message.
        if status != errSecSuccess {
            print("Failed to add private key to Keychain: \(status)")
        }

        // This adds the public key to the Keychain.
        status = SecItemAdd(publicKeyAddQuery as CFDictionary, &result)

        // If adding the public key fails, it prints an error message.
        if status != errSecSuccess {
            print("Failed to add public key to Keychain: \(status)")
        }
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
