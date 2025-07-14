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
        let elements = asn1.children
        guard case .objectIdentifier(X509ExtensionType.basicConstraints.rawValue) = elements[safeIndex: 0] else {
            throw BasicConstraintsError.invalidIdentifier
        }
        guard case .boolean(let isCritical) = elements[safeIndex: 1] else {
            throw BasicConstraintsError.missingIsCritical
        }
        self.isCritical = isCritical
        
        guard case .octetString(let octetString) = elements[safeIndex: 2] else {
            throw BasicConstraintsError.missingCertificateAuthorityData
        }
        let caElements = try ASN1(data: octetString).children
        var section = 0
        if case .boolean(let isCertificateAuthority) = caElements[safeIndex: section] {
            self.isCertificateAuthority = isCertificateAuthority
            section.increment()
        } else {
            self.isCertificateAuthority = false
        }
        
        if case .integer(let data) = caElements[safeIndex: section] {
            self.amountOfChildCAs = try data.uInt8
        } else {
            self.amountOfChildCAs = nil
        }
    }
}

extension BasicConstraints {
    public var asn1: ASN1 {
        get throws {
            var content: [ASN1] = []
            
            if isCertificateAuthority {
                content.append(.boolean(isCertificateAuthority))
            }
            if let amountOfChildCAs = amountOfChildCAs {
                content.append(.integer(amountOfChildCAs.data))
            }
            return ASN1.sequence([
                .objectIdentifier(X509ExtensionType.basicConstraints.rawValue),
                .boolean(isCritical),
                .octetString(try ASN1.sequence(content).data)
            ])
        }
    }
}
