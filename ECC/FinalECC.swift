import Foundation
import Security
import CryptoKit

class EccUtility {
    private var privateKey: SecKey?
    private var publicKey: SecKey?
    private var certificate: SecCertificate?

    init?() {
        // Generate ECC key pair within Secure Enclave
        let privateKeyParams: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: "com.example.privatekey",
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(privateKeyParams as CFDictionary, &error) else {
            print("Failed to generate ECC key pair: \(String(describing: error?.takeRetainedValue()))")
            return
        }
        self.privateKey = privateKey
        let publicKey = SecKeyCopyPublicKey(privateKey)
        self.publicKey = publicKey
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

    func signData(data: Data) -> Data? {
            // Sign the data using the private key
        var error: Unmanaged<CFError>?
        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        guard let signature = SecKeyCreateSignature(privateKey!, algorithm, data as CFData, &error) as Data? else {
            print("Failed to sign data: \(String(describing: error?.takeRetainedValue()))")
            return nil
        }
        return signature
    }

    func verifyData(data: Data, signature: Data) -> Bool {
        // Verify the signature using the public key
        var error: Unmanaged<CFError>?
        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        return SecKeyVerifySignature(publicKey!, algorithm, data as CFData, signature as CFData, &error)
    }
}
