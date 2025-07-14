//
//  SubjectKeyIdentifier.swift
//  CryptoKeyUtils
//
//  Created by Tomasz Kucharski on 12/07/2025.
//
import Foundation
import SwiftyTLV

public enum SubjectKeyIdentifierError: Error {
    case invalidIdentifier
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
        let elements = asn1.children
        guard case .objectIdentifier(X509ExtensionType.subjectKeyIdentifier.rawValue) = elements[safeIndex: 0] else {
            throw SubjectKeyIdentifierError.invalidIdentifier
        }
        var index = 1
        if case .boolean(let isCritical) = elements[safeIndex: index] {
            index.increment()
            self.isCritical = isCritical
        } else {
            self.isCritical = false
        }
        guard case .octetString(let keyContainer) = elements[safeIndex: index], let keyASN = try? ASN1(data: keyContainer), case .octetString(let keyID) = keyASN else {
            throw SubjectKeyIdentifierError.missingKeyID
        }
        self.keyID = keyID
    }
}

extension SubjectKeyIdentifier {
    public var asn1: ASN1 {
        get throws {
            var content: [ASN1] = [
                .objectIdentifier(X509ExtensionType.subjectKeyIdentifier.rawValue)
            ]
            if isCritical { content.append(.boolean(isCritical)) }
            content.append(.octetString(try ASN1.octetString(keyID).data))
            return ASN1.sequence(content)
        }
    }
}
