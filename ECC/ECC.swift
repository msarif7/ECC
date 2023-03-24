import Foundation
import Security

class EccUtility {
    public var privateKey: SecKey?
    public var publicKey: SecKey?
    public var certificate: SecCertificate?
    
    func generateData () {
        print("Start")
        // Generate ECC key pair within Secure Enclave
        let privateKeyParams: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: "com.example.privatekey",
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        let publicKeyParams: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: "com.example.publickey",
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(privateKeyParams as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey)
        else {
            print("Failed to generate ECC key pair: \(String(describing: error?.takeRetainedValue() ?? "" as! CFError))")
            return
        }
        
        guard let data = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
            print("Error creating external representation: \(error!.takeRetainedValue() as Error)")
            return
        }

        guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
            print("Error creating certificate")
            return
        }
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.certificate = certificate
        
        // Print base64 encoded certificate
        guard let certData = SecCertificateCopyData(certificate) as Data? else {
            print("Failed to retrieve certificate data")
            return
        }
        let base64Cert = certData.base64EncodedString()
        print("Base64 encoded certificate: \(base64Cert)")
        
        // Sign data with private key within Secure Enclave
        let dataToSign = "Some data to sign".data(using: .utf8)!
        let signParams: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]
        var signError: Unmanaged<CFError>?
        guard let signedData = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, dataToSign as CFData, &signError) else {
            print("Failed to sign data: \(signError?.takeRetainedValue() ?? "" as! CFError)")
            return
        }
        print("Signed data: \(signedData as NSData)")
        print("Private key: \(String(describing: privateKey))")
        print("Public key: \(String(describing: publicKey))")
        print("Certificate: \(String(describing: certificate))")
        
    }
}
