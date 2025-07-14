//
//  X509Certificate.swift
//  CryptoKeyUtils
//
//  Created by Tomasz Kucharski on 12/07/2025.
//
import Foundation
import SwiftyTLV
import CryptoKeyUtils
import Crypto

public enum X509CertificateError: Error {
    case invalidFormat
    case missingSerialNumber
    case missingIssuer
    case missingValidity
    case missingSubject
    case missingPublicKey
    case unsupportedPublicKeyFormat
    case missingExtensions
}

public struct X509Certificate {
    public let serialNumber: Data
    public let issuer: X509Entity
    public let validity: X509Validity
    public let subject: X509Entity
    public let publicKey: ECPublicKey
    public let extensions: [X509Extension]
    
    public init (serialNumber: Data,
          issuer: X509Entity,
          validity: X509Validity,
          subject: X509Entity,
          publicKey: ECPublicKey,
          extensions: [X509Extension] = [])
    {
        self.serialNumber = serialNumber
        self.issuer = issuer
        self.validity = validity
        self.subject = subject
        self.publicKey = publicKey
        self.extensions = extensions
    }
    
    public init(asn1 asn: ASN1) throws {
        let container = asn.children
        
        guard let certificate = container.first?.children else {
            throw X509CertificateError.invalidFormat
        }
        guard case .integer(let serialNumber) = certificate[safeIndex: X509Section.serialNumber.rawValue] else {
            throw X509CertificateError.missingSerialNumber
        }
        self.serialNumber = serialNumber
        
        guard case .sequence(let issuerRows) = certificate[safeIndex: X509Section.issuer.rawValue] else {
            throw X509CertificateError.missingIssuer
        }
        self.issuer = X509Entity(asn: issuerRows)
        guard case .sequence(let validityRows) = certificate[safeIndex: X509Section.dateValidity.rawValue] else {
            throw X509CertificateError.missingValidity
        }
        self.validity = try X509Validity(asn: validityRows)
        
        guard case .sequence(let subjectRows) = certificate[safeIndex: X509Section.subject.rawValue] else {
            throw X509CertificateError.missingSubject
        }
        self.subject = X509Entity(asn: subjectRows)
        
        guard case .sequence(let publicKeyRows) = certificate[safeIndex: X509Section.publicKey.rawValue] else {
            throw X509CertificateError.missingPublicKey
        }
        self.publicKey = try ECPublicKey(der: try ASN1.sequence(publicKeyRows).data)
        
        guard case .contextSpecificConstructed(3, let extensionContainer) = certificate[safeIndex: X509Section.extensions.rawValue] else {
            throw X509CertificateError.missingExtensions
        }
        self.extensions = try extensionContainer.first?.children.compactMap { sequence -> X509Extension? in
            guard case .objectIdentifier(let oid) = sequence.child(at: 0) else { return nil }
            return try X509ExtensionType(rawValue: oid)?.x509Extension.init(asn1: sequence)
        } ?? []
    }
}

public extension X509Certificate {
    func asn1(issuerKey: ECPrivateKey) throws -> ASN1 {
        let toBeSigned = ASN1.sequence([
            .sequence([
                .contextSpecificConstructed(tag: 0, [.integer(Data([0x02]))]),
                .integer(self.serialNumber),
                .sequence([.objectIdentifier("1.2.840.10045.4.3.2")]), // ecdsa-with-SHA256
                .sequence(issuer.asn1),
                .sequence(validity.asn1),
                .sequence(subject.asn1),
                try publicKey.asn1,
                .contextSpecificConstructed(tag: 3, [.sequence(try extensions.map { try $0.asn1 })])
            ]),
            .sequence([.objectIdentifier("1.2.840.10045.4.3.2")])
        ])
        let privateKey = try P256.Signing.PrivateKey(derRepresentation: issuerKey.der(format: .pkcs8))
        let digest = SHA256.hash(data: try toBeSigned.data)
        let signature = try privateKey.signature(for: digest)
        let rawSignature = signature.rawRepresentation
        let tlv = BerTlv(tag: Data([0, 0x30]), value: rawSignature)
        return .sequence(toBeSigned.children + [.bitString(tlv.data)])
    }
    
    
    static let pemHeader = "-----BEGIN CERTIFICATE-----\n"
    static let pemFooter = "\n-----END CERTIFICATE-----"
    
    func der(issuerKey: ECPrivateKey) throws -> Data {
        try asn1(issuerKey: issuerKey).data
    }
    
    func pem(issuerKey: ECPrivateKey) throws -> String {
        let base64Key = try der(issuerKey: issuerKey).base64EncodedString(options: .lineLength64Characters)
        return Self.pemHeader + base64Key + Self.pemFooter
    }
}
