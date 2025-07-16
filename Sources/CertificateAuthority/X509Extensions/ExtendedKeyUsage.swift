//
//  ExtendedKeyUsage.swift
//  CertificateAuthority
//
//  Created by Tomasz Kucharski on 15/07/2025.
//
import Foundation
import SwiftyTLV
import SwiftExtensions

public enum ExtendedKeyUsagePurpose: String {
    // Indicates that a certificate can be used as an SSL server certificate
    case serverAuth = "1.3.6.1.5.5.7.3.1"
    // Indicates that a certificate can be used as a Secure Sockets Layer (SSL) client certificate
    case clientAuth = "1.3.6.1.5.5.7.3.2"
    // Indicates that a certificate can be used for code signing
    case codeSigning = "1.3.6.1.5.5.7.3.3"
    // Indicates that a certificate can be used for protecting email (signing, encryption, key agreement)
    case emailProtection = "1.3.6.1.5.5.7.3.4"
    // Indicates that a certificate can be used to bind the hash of an object to a time from a trusted
    case timeStamping = "1.3.6.1.5.5.7.3.8"
    // Indicates that a X.509 Certificates corresponding private key may be used by an authority to sign OCSP-Responses
    case ocspSigning = "1.3.6.1.5.5.7.3.9"
}

public enum ExtendedKeyUsageError: Error {
    case invalidFormat
    case missingUsageData
}

public struct ExtendedKeyUsage: X509Extension {
    public let isCritical: Bool
    public let purposes: [ExtendedKeyUsagePurpose]
    
    public init(isCritical: Bool = false, purposes: [ExtendedKeyUsagePurpose]) {
        self.isCritical = isCritical
        self.purposes = purposes
    }
    
    public init(asn1: ASN1) throws {
        let envelope = try X509ExtensionEnvelope(asn1: asn1)
        self.isCritical = envelope.isCritical
        
        guard let container = try? ASN1(data: envelope.body) else {
            throw KeyUsageError.invalidFormat
        }
        purposes = container.children.compactMap {
            guard case .objectIdentifier(let oid) = $0 else { return nil }
            return ExtendedKeyUsagePurpose(rawValue: oid)
        }
    }
}

extension ExtendedKeyUsage {
    public var asn1: ASN1 {
        get throws {
            try X509ExtensionEnvelope(type: .extendedKeyUsage,
                                      isCritical: isCritical,
                                      body: .sequence(
                                        purposes.map { .objectIdentifier($0.rawValue) }
                                      )).asn1
        }
    }
}
