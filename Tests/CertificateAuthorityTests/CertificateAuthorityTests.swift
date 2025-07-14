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
            MIIClKADAgECAgkA+DmniNYzxrswCgYIKoZIzj0EAwIwgYIxGTAXBgNVBAoMEE1l
            Z2EgQ29ycG9yYXRpb24xJTAjBgNVBAsMHE1lZ2EgQ2VyaXRmaWNhdGVzIERlcGFy
            dG1lbnQxEDAOBgNVBAMMB1Jvb3QgUjExCzAJBgNVBAYTAlBMMQ0wCwYDVQQHDARM
            b2R6MRAwDgYDVQQIDAdMb2R6a2llMB4XDTI1MDQxNDEwNDQwMFoXDTM1MDQxNDEw
            NDQwMFowgYIxGTAXBgNVBAoMEE1lZ2EgQ29ycG9yYXRpb24xJTAjBgNVBAsMHE1l
            Z2EgQ2VyaXRmaWNhdGVzIERlcGFydG1lbnQxEDAOBgNVBAMMB1Jvb3QgUjExCzAJ
            BgNVBAYTAlBMMQ0wCwYDVQQHDARMb2R6MRAwDgYDVQQIDAdMb2R6a2llMFkwEwYH
            KoZIzj0CAQYIKoZIzj0DAQcDQgAE93isKBeKQwj8ebYB06GJvEXkFdJTUomK/zqX
            gWf/ApwcD4iR0GUK6diyiVGhQlgjyOKO5TEMUYA6FDiWteY2y6OB8DCB7TASBgNV
            HRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSHh4eHh4eHh4eHh4eHh4eHh4eHhzCB
            twYDVR0jBIGvMIGsgBSHh4eHh4eHh4eHh4eHh4eHh4eHh6GBiKSBhTCBgjEZMBcG
            A1UECgwQTWVnYSBDb3Jwb3JhdGlvbjElMCMGA1UECwwcTWVnYSBDZXJpdGZpY2F0
            ZXMgRGVwYXJ0bWVudDEQMA4GA1UEAwwHUm9vdCBSMTELMAkGA1UEBhMCUEwxDTAL
            BgNVBAcMBExvZHoxEDAOBgNVBAgMB0xvZHpraWWCCQD4OaeI1jPGuw==
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
    
}

