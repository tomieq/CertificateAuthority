//
//  SubjectKeyIdentifier.swift
//  CryptoKeyUtils
//
//  Created by Tomasz Kucharski on 12/07/2025.
//
import Foundation
import SwiftyTLV

public enum SubjectKeyIdentifierError: Error {
    case invalidFormat
    case missingKeyID
}

public struct SubjectKeyIdentifier: X509Extension {
    public let isCritical: Bool
    public let keyID: Data
    
    public init(isCritical: Bool = false, keyID: Data) {
        self.isCritical = isCritical
        self.keyID = keyID
    }
    
    public init(asn1: ASN1) throws {
        let envelope = try X509ExtensionEnvelope(asn1: asn1)
        self.isCritical = envelope.isCritical
        
        guard let container = try? ASN1(data: envelope.body) else {
            throw SubjectKeyIdentifierError.invalidFormat
        }
        guard case .octetString(let keyID) = container else {
            throw SubjectKeyIdentifierError.missingKeyID
        }
        self.keyID = keyID
    }
}

extension SubjectKeyIdentifier {
    public var asn1: ASN1 {
        get throws {
            try X509ExtensionEnvelope(type: .subjectKeyIdentifier,
                                      isCritical: isCritical,
                                      body: .octetString(keyID)).asn1
        }
    }
}
