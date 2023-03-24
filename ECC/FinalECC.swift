import Foundation
import Security

class EccUtility2 {
    private var privateKey: SecKey?
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

        // Create a certificate with the public key
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            print("Failed to retrieve public key")
            return
        }
        let subject = [
            [kSecOIDCountryName as String: "US"],
            [kSecOIDOrganizationName as String: "My Company"],
            [kSecOIDCommonName as String: "My Self-Signed Certificate"]
        ] as CFArray
        let certificateAttributes: [CFString: Any] = [
            kSecAttrSubject: subject,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrPublicKey: publicKey,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecAttrSerialNumber: Data([0x01, 0x02, 0x03, 0x04, 0x05]),
            kSecAttrCertificateType: kSecAttrCertificateTypeECSECPrimeRandom
        ]
        guard let certificate = SecCertificateCreateWithData(nil, certificateAttributes as! CFData) else {
            print("Failed to create certificate")
            return
        }
        self.certificate = certificate
    }

    func exportCertificate() -> Data? {
        // Export the certificate as DER-encoded data
        var exportError: Unmanaged<CFError>?
        guard let exportData = SecItemExport([kSecValueRef: certificate as Any,
                                              kSecReturnData: true] as CFDictionary, &exportError) as Data? else {
            print("Failed to export certificate: \(String(describing: exportError?.takeRetainedValue()))")
            return nil
        }
        return exportData
    }

    func signData(data: Data) -> Data? {
        // Sign the data using the private key
        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        guard let signature = SecKeyCreateSignature(privateKey!, algorithm, data as CFData, &error) as Data? else {
            print("Failed to sign data: \(String(describing: error?.takeRetainedValue()))")
            return nil
        }
        return signature
    }
}
