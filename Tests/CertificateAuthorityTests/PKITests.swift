//
//  PKITests.swift
//  CertificateAuthority
//
//  Created by: tomieq on 16/05/2026
//
import Foundation
import CryptoKit
import CryptoKeyUtils
import Testing
@testable import CertificateAuthority

struct PKITests {
    private func generateCA() throws -> (certificate: X509Certificate, privateKey: ECPrivateKey) {
        let privateKey = P256.Signing.PrivateKey()
        let caPrivateKey = try ECPrivateKey(der: privateKey.derRepresentation)
        let issuer = X509Entity(
            organizationName: "Cassini Global, Inc.",
            organizationalUnitName: "Cassini Security",
            commonName: "Cassini CA R1"
        )

        let validFrom = "2025-04-14T10:44:00+0000"
        let validTo = "2035-04-14T10:44:00+0000"
        let dateFormatter = ISO8601DateFormatter()

        let certificateKeyID = Data.random(length: 40)
        let serialNumber = Data.random(length: 16)

        let certificate = X509Certificate(
            serialNumber: serialNumber,
            issuer: issuer,
            validity: X509Validity(
                from: dateFormatter.date(from: validFrom)!,
                to: dateFormatter.date(from: validTo)!),
            subject: issuer,
            publicKey: caPrivateKey.publicKey,
            extensions: [
                BasicConstraints(isCertificateAuthority: true, amountOfChildCAs: 0),
                SubjectKeyIdentifier(keyID: certificateKeyID)
            ])
        return (certificate, caPrivateKey)
    }

    @Test func newRootCA() throws {
        let (certificate, caPrivateKey) = try generateCA()
        let certPem = try certificate.pem(issuerKey: caPrivateKey)
        print(certificate)
        print(try caPrivateKey.pem(format: .pkcs8))
        print(certPem)
    }

    let caPrivateKeyPem = """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfZJbphIrYB/Iialo
    gAjnU3afpau25L9WYuBAP9ppFruhRANCAARzAhJtlW/Iy3cZv5ijfwSrcgUMeA5g
    wdvXtfujT+viWQG4LXh7ncupwrDio2sgL/JUbf3ykcTs+iDtjnkKBQS4
    -----END PRIVATE KEY-----
    """

    let caCertificatePem = """
    -----BEGIN CERTIFICATE-----
    MIIBbDCCARegAwIBAgIQbFIiOtYEEN0hpQrYy+NXnjAKBggqhkjOPQQDAjAVMRMw
    EQYDVQQDEwpSb290IENBIFIxMB4XDTI1MDQxNDEwNDQwMFoXDTM1MDQxNDEwNDQw
    MFowFTETMBEGA1UEAxMKUm9vdCBDQSBSMTBZMBMGByqGSM49AgEGCCqGSM49AwEH
    A0IABHMCEm2Vb8jLdxm/mKN/BKtyBQx4DmDB29e1+6NP6+JZAbgteHudy6nCsOKj
    ayAv8lRt/fKRxOz6IO2OeQoFBLijSTBHMBIGA1UdEwEB/wQIMAYBAf8CAQAwMQYD
    VR0OBCoEKLTxcEWy0U50NZDnAscubEtQWlUIuI7ypMd49nnZYQ+PKgl2QSeKudcw
    CgYIKoZIzj0EAwIDQwAwQI0Ns23IGrSL5CE8e8lTYzuxqOJao9z9rw2NIRg52jGY
    QNI12qSyKXleXUflol2mOUNSXwwL3vsBAzbe6ADQcAQ=
    -----END CERTIFICATE-----
    """

    @Test
    func printCaCertificate() throws {
        print(self.caCertificatePem)
        let caCertificate = try X509Certificate(pem: self.caCertificatePem)
        print(caCertificate)
    }

    @Test func newLeaf() throws {
        enum Mode {
            case generateNewCA
            case useExistingCA
        }

        let mode = Mode.generateNewCA

        let caPrivateKey: ECPrivateKey
        let caCertificate: X509Certificate

        switch mode {
        case .generateNewCA:
            (caCertificate, caPrivateKey) = try self.generateCA()
        case .useExistingCA:
            caPrivateKey = try ECPrivateKey(pem: self.caPrivateKeyPem)
            caCertificate = try X509Certificate(pem: self.caCertificatePem)
        }

        let leafPrivateKey = P256.Signing.PrivateKey()
        let leafPrivKey = try ECPrivateKey(der: leafPrivateKey.derRepresentation)

        let subject = X509Entity(
            organizationName: "Lotus Computer Science",
            organizationalUnitName: "Lotus Research",
            commonName: "localhost"
        )

        let validFrom = "2025-04-14T10:44:00+0000"
        let validTo = "2035-04-14T10:44:00+0000"
        let dateFormatter = ISO8601DateFormatter()

        let certificateKeyID = Data.random(length: 40)
        let serialNumber = Data.random(length: 16)

        let certificate = X509Certificate(
            serialNumber: serialNumber,
            issuer: caCertificate.issuer,
            validity: X509Validity(
                from: dateFormatter.date(from: validFrom)!,
                to: dateFormatter.date(from: validTo)!),
            subject: subject,
            publicKey: leafPrivKey.publicKey,
            extensions: [
                SubjectKeyIdentifier(keyID: certificateKeyID),
                SubjectAlternativeName(names: ["localhost"]),
                AuthorityKeyIdentifier(
                    issuerKeyID: {
                        let keyIDExtension: SubjectKeyIdentifier? = caCertificate.getExtension()
                        return keyIDExtension?.keyID
                    }(),
                    issuerSerialNumber: caCertificate.serialNumber,
                    issuer: caCertificate.subject
                )
            ])

        let caPem: String
        switch mode {
        case .generateNewCA:
            caPem = try caCertificate.pem(issuerKey: caPrivateKey)
        case .useExistingCA:
            caPem = self.caCertificatePem
        }
        print("\n\n===== Objects:\n\n")
        print(caCertificate)
        print(certificate)
        print("\n\n===== CA:\n\n")
        print(try caPrivateKey.pem(format: .pkcs8))
        print(caPem)
        print("\n\n===== Install to server:\n\n")
        print(try leafPrivKey.pem(format: .pkcs8))

        print(try certificate.pem(issuerKey: caPrivateKey))
        print(caPem)
    }
}
