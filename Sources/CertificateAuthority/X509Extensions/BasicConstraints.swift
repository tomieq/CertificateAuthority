//
//  BasicConstraints.swift
//  CryptoKeyUtils
//
//  Created by Tomasz Kucharski on 12/07/2025.
//
import SwiftyTLV
import SwiftExtensions

public enum BasicConstraintsError: Error {
    case invalidIdentifier
    case missingIsCritical
    case missingCertificateAuthorityData
}

public struct BasicConstraints: X509Extension {
    public let isCritical: Bool
    public let isCertificateAuthority: Bool
    public let amountOfChildCAs: UInt8?
    
    public init(isCritical: Bool, isCertificateAuthority: Bool, amountOfChildCAs: UInt8? = nil) {
        self.isCritical = isCritical
        self.isCertificateAuthority = isCertificateAuthority
        self.amountOfChildCAs = amountOfChildCAs
    }
    
    public init(asn1: ASN1) throws {
        let envelope = try X509ExtensionEnvelope(asn1: asn1)
        self.isCritical = envelope.isCritical
        
        let sections = try ASN1(data: envelope.body).children
        var section = 0
        if case .boolean(let isCertificateAuthority) = sections[safeIndex: section] {
            self.isCertificateAuthority = isCertificateAuthority
            section.increment()
        } else {
            self.isCertificateAuthority = false
        }
        
        if case .integer(let data) = sections[safeIndex: section] {
            self.amountOfChildCAs = try data.uInt8
        } else {
            self.amountOfChildCAs = nil
        }
    }
}

extension BasicConstraints {
    public var asn1: ASN1 {
        get throws {
            var content = ASN1.sequence([])
            
            if isCertificateAuthority {
                try content.append(.boolean(isCertificateAuthority))
            }
            if let amountOfChildCAs {
                try content.append(.integer(amountOfChildCAs.data))
            }
            return try X509ExtensionEnvelope(type: .basicConstraints,
                                             isCritical: isCritical,
                                             body: content).asn1
        }
    }
}
