//
//  AuthorityKeyIdentifier.swift
//  CryptoKeyUtils
//
//  Created by Tomasz Kucharski on 12/07/2025.
//

import Foundation
import SwiftyTLV

public enum AuthorityKeyIdentifierError: Error {
    case invalidIdentifier
    case missingDetails
    case missingKeyID
    case missingIssuer
    case missingIssuerSerialNumber
}

public struct AuthorityKeyIdentifier: X509Extension {
    public let isCritical: Bool
    public let issuerKeyID: Data
    public let issuerSerialNumber: Data
    public let issuer: X509Entity
    
    public init(isCritical: Bool = false, issuerKeyID: Data, issuerSerialNumber: Data, issuer: X509Entity) {
        self.isCritical = isCritical
        self.issuerKeyID = issuerKeyID
        self.issuerSerialNumber = issuerSerialNumber
        self.issuer = issuer
    }
    
    public init(asn1: ASN1) throws {
        let elements = asn1.children
        guard case .objectIdentifier(X509ExtensionType.authorityKeyIdentifier.rawValue) = elements[safeIndex: 0] else {
            throw AuthorityKeyIdentifierError.invalidIdentifier
        }
        var index = 1
        if case .boolean(let isCritical) = elements[safeIndex: index] {
            index.increment()
            self.isCritical = isCritical
        } else {
            self.isCritical = false
        }
        guard case .octetString(let details) = elements[safeIndex: index] else {
            throw AuthorityKeyIdentifierError.missingDetails
        }
        
        let content = try ASN1(data: details).children
        // keyID
        guard case .contextSpecificPrimitive(let customTLV) = content[safeIndex: 0] , case .customTlv(let tlv) = customTLV else {
            throw AuthorityKeyIdentifierError.missingKeyID
        }
        self.issuerKeyID = tlv.value
        
        guard case .contextSpecificConstructed(tag: 1, let container) = content[safeIndex: 1], case .contextSpecificConstructed(tag: 4, let sequence) = container.first, let issuerASN1 = sequence.first?.children else {
            throw AuthorityKeyIdentifierError.missingIssuer
        }
        self.issuer = X509Entity(asn: issuerASN1)
        
        guard case .contextSpecificPrimitive(let container) = content[safeIndex: 2], case .integer(let serialNumber) = container else {
            throw AuthorityKeyIdentifierError.missingIssuerSerialNumber
        }
        self.issuerSerialNumber = serialNumber
    }
}

extension AuthorityKeyIdentifier {
    public var asn1: ASN1 {
        get throws {
            var content: [ASN1] = [
                .objectIdentifier(X509ExtensionType.authorityKeyIdentifier.rawValue)
            ]
            if isCritical { content.append(.boolean(isCritical)) }
            
            // all are optional
            let issuerInfo = ASN1.sequence([
                .contextSpecificPrimitive(.customTlv(BerTlv(tag: 0.data, value: issuerKeyID))),
                .contextSpecificConstructed(tag: 1, [
                    .contextSpecificConstructed(tag: 4, [.sequence(issuer.asn1)])
                ]),
                .contextSpecificPrimitive(.integer(issuerSerialNumber))
            ])
            content.append(.octetString(try issuerInfo.data))
            return ASN1.sequence(content)
        }
    }
}
