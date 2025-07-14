//
//  X509ExtensionEnvelope.swift
//  CertificateAuthority
//
//  Created by Tomasz Kucharski on 14/07/2025.
//
import Foundation
import SwiftyTLV

public enum X509ExtensionEnvelopeError: Error {
    case invalidIdentifier
    case unsupportedExtension(String)
    case missingBody
}

struct X509ExtensionEnvelope: X509Extension {
    let type: X509ExtensionType
    let isCritical: Bool
    let body: Data
    
    init (type: X509ExtensionType, isCritical: Bool, body: Data) {
        self.type = type
        self.isCritical = isCritical
        self.body = body
    }
    init (type: X509ExtensionType, isCritical: Bool, body: ASN1) throws {
        self.type = type
        self.isCritical = isCritical
        self.body = try body.data
    }
    
    init(asn1: ASN1) throws {
        let elements = asn1.children
        guard case .objectIdentifier(let oid) = elements[safeIndex: 0] else {
            throw X509ExtensionEnvelopeError.invalidIdentifier
        }
        self.type = try X509ExtensionType(rawValue: oid).orThrow(X509ExtensionEnvelopeError.unsupportedExtension(oid))
        
        var section = 1
        if case .boolean(let isCritical) = elements[safeIndex: section] {
            self.isCritical = isCritical
            section.increment()
        } else {
            self.isCritical = false
        }
        
        guard case .octetString(let body) = elements[safeIndex: section] else {
            throw X509ExtensionEnvelopeError.missingBody
        }
        self.body = body
    }
    
    var asn1: ASN1 {
        get throws {
            var asn = ASN1.sequence([.objectIdentifier(type.rawValue)])
            if isCritical { try asn.append(.boolean(isCritical)) }
            try asn.append(.octetString(body))
            return asn
        }
        
    }
}
