import Testing
import CertificateAuthority
import Foundation
import CryptoKeyUtils
import SwiftyTLV
import Crypto

struct CertificateAuthorityTests {
    @Test func selfSigned_P256() throws {
//        let privateKey = P256.Signing.PrivateKey()
//        let rootPrivKey = try ECPrivateKey(der: privateKey.derRepresentation)
        
        let rootPrivKey = try ECPrivateKey(.hexString(x: "F778AC28178A4308FC79B601D3A189BC45E415D25352898AFF3A978167FF029C",
                                                      y: "1C0F8891D0650AE9D8B28951A1425823C8E28EE5310C51803A143896B5E636CB",
                                                      d: "7AACAE663AF3AD83D0EE6DCE7AD802143F75D531750D2A675E11EB396082FE54",
                                                      curve: .secp256r1))
        let issuer = X509Entity(countryName: "PL",
                                stateOrProvinceName: "Lodzkie",
                                city: "Lodz",
                                organizationName: "Mega Corporation",
                                organizationalUnitName: "Mega Ceritficates Department",
                                commonName: "Root R1")
        
        let validFrom = "2025-04-14T10:44:00+0000"
        let validTo = "2035-04-14T10:44:00+0000"
        let dateFormatter = ISO8601DateFormatter()
        
        let certificateKeyID = Data(repeating: 0x87, count: 20)
        let serialNumber = Data(hexString: "00F839A788D633C6BB")
        let certificate = X509Certificate(serialNumber: serialNumber,
                                          issuer: issuer,
                                          validity: X509Validity(from: dateFormatter.date(from:validFrom)!, to: dateFormatter.date(from:validTo)!),
                                          subject: issuer,
                                          publicKey: rootPrivKey.publicKey,
                                          extensions: [
                                            BasicConstraints(isCritical: true, isCertificateAuthority: true, amountOfChildCAs: 1),
                                            SubjectKeyIdentifier(keyID: certificateKeyID),
                                            AuthorityKeyIdentifier(issuerKeyID: certificateKeyID,
                                                                   issuerSerialNumber: serialNumber,
                                                                   issuer: issuer)
                                          ])
        
        let newCert = try certificate.asn1(issuerKey: rootPrivKey)
        
        let expected = """
            MIIClKADAgECAgkA+DmniNYzxrswCgYIKoZIzj0EAwIwgYIxGTAXBgNVBAoTEE1l
            Z2EgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1lZ2EgQ2VyaXRmaWNhdGVzIERlcGFy
            dG1lbnQxEDAOBgNVBAMTB1Jvb3QgUjExCzAJBgNVBAYTAlBMMQ0wCwYDVQQHEwRM
            b2R6MRAwDgYDVQQIEwdMb2R6a2llMB4XDTI1MDQxNDEwNDQwMFoXDTM1MDQxNDEw
            NDQwMFowgYIxGTAXBgNVBAoTEE1lZ2EgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1l
            Z2EgQ2VyaXRmaWNhdGVzIERlcGFydG1lbnQxEDAOBgNVBAMTB1Jvb3QgUjExCzAJ
            BgNVBAYTAlBMMQ0wCwYDVQQHEwRMb2R6MRAwDgYDVQQIEwdMb2R6a2llMFkwEwYH
            KoZIzj0CAQYIKoZIzj0DAQcDQgAE93isKBeKQwj8ebYB06GJvEXkFdJTUomK/zqX
            gWf/ApwcD4iR0GUK6diyiVGhQlgjyOKO5TEMUYA6FDiWteY2y6OB8DCB7TASBgNV
            HRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSHh4eHh4eHh4eHh4eHh4eHh4eHhzCB
            twYDVR0jBIGvMIGsgBSHh4eHh4eHh4eHh4eHh4eHh4eHh6GBiKSBhTCBgjEZMBcG
            A1UEChMQTWVnYSBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWVnYSBDZXJpdGZpY2F0
            ZXMgRGVwYXJ0bWVudDEQMA4GA1UEAxMHUm9vdCBSMTELMAkGA1UEBhMCUEwxDTAL
            BgNVBAcTBExvZHoxEDAOBgNVBAgTB0xvZHpraWWCCQD4OaeI1jPGuw==
            """
            .removed(text: "\r")
            .removed(text: "\n")
        let unchangablePart = try newCert.child(at: 0)?.data.base64EncodedString(options: .lineLength64Characters)
            .removed(text: "\r")
            .removed(text: "\n")
        #expect(unchangablePart == expected)
        
        let certificatePath = FileManager.default.currentDirectoryPath + "/\(UUID().uuidString).pem"
        let certificateURL = URL(fileURLWithPath: certificatePath)
        defer {
            try? FileManager.default.removeItem(at: certificateURL)
        }
        try certificate.pem(issuerKey: rootPrivKey).data(using: .utf8)?.write(to: certificateURL)
        
        let result = Shell().exec("openssl verify -CAfile \(certificatePath) \(certificatePath)")
        #expect(result.contains("OK"))
    }
    
    @Test func extensionHelpers() throws {
        let privateKey = try self.privateKey
        let serialNumber = Data(repeating: 0xA0, count: 12)
        let cert = X509Certificate(serialNumber: serialNumber,
                                   issuer: issuer,
                                   validity: X509Validity(from: Date(), to: Date().addingTimeInterval(300)),
                                   subject: issuer,
                                   publicKey: privateKey.publicKey)
        let keyID = Data(repeating: 7, count: 18)
        cert.configure(basicConstraints: BasicConstraints(isCertificateAuthority: true, amountOfChildCAs: 0))
        cert.alternativeNames = ["domain.com"]
        cert.keyUsage = [.digitalSignature, .keyCertSign]
        cert.extendedKeyUsage = [.serverAuth, .clientAuth]
        cert.subjectKeyIdentifier = keyID
        cert.configure(authorityKeyIdentifier: AuthorityKeyIdentifier(issuerKeyID: keyID,
                                                                      issuerSerialNumber: serialNumber,
                                                                      issuer: issuer))
        
    }
}

extension CertificateAuthorityTests {
    var issuer: X509Entity {
        X509Entity(countryName: "PL",
                   stateOrProvinceName: "Lodzkie",
                   city: "Lodz",
                   organizationName: "Mega Corporation",
                   organizationalUnitName: "Mega Ceritficates Department",
                   commonName: "Root R1")
    }
    
    var privateKey: ECPrivateKey {
        get throws {
            try ECPrivateKey(der: P256.Signing.PrivateKey().derRepresentation)
        }
    }
}
