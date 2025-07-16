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
}

// all parameteres are optional, you can provide whichever you want
// if you don't want to provide any parameter, just do not add this extension to the certificate
public struct AuthorityKeyIdentifier: X509Extension {
    public let type: X509ExtensionType = .authorityKeyIdentifier
    public let isCritical: Bool
    public let issuerKeyID: Data?
    public let issuerSerialNumber: Data?
    public let issuer: X509Entity?
    
    public init(isCritical: Bool = false, issuerKeyID: Data?, issuerSerialNumber: Data?, issuer: X509Entity?) {
        self.isCritical = isCritical
        self.issuerKeyID = issuerKeyID
        self.issuerSerialNumber = issuerSerialNumber
        self.issuer = issuer
    }
    
    public init(asn1: ASN1) throws {
        let envelope = try X509ExtensionEnvelope(asn1: asn1)
        self.isCritical = envelope.isCritical
        
        let sections = try ASN1(data: envelope.body).children

        // keyID
        var section = 0
        if case .contextSpecificPrimitive(let customTLV) = sections[safeIndex: section] , case .customTlv(let tlv) = customTLV {
            section.increment()
            self.issuerKeyID = tlv.value
        } else {
            self.issuerKeyID = nil
        }
        
        // issuer
        if case .contextSpecificConstructed(tag: 1, let container) = sections[safeIndex: section], case .contextSpecificConstructed(tag: 4, let sequence) = container.first, let issuerASN1 = sequence.first?.children {
            self.issuer = X509Entity(asn: issuerASN1)
            section.increment()
        } else {
            self.issuer = nil
        }

        // serial number
        if case .contextSpecificPrimitive(let container) = sections[safeIndex: section], case .integer(let serialNumber) = container {
            self.issuerSerialNumber = serialNumber
        } else {
            self.issuerSerialNumber = nil
        }
        
    }
}

extension AuthorityKeyIdentifier {
    public var asn1: ASN1 {
        get throws {
            var content = ASN1.sequence([])
            if let issuerKeyID {
                try content.append(.contextSpecificPrimitive(.customTlv(BerTlv(tag: 0.data, value: issuerKeyID))))
            }
            if let issuer {
                try content.append(.contextSpecificConstructed(tag: 1, [
                    .contextSpecificConstructed(tag: 4, [.sequence(issuer.asn1)])
                ]))
            }
            if let issuerSerialNumber {
                try content.append(.contextSpecificPrimitive(.integer(issuerSerialNumber)))
            }
            return try X509ExtensionEnvelope(type: .authorityKeyIdentifier,
                                             isCritical: isCritical,
                                             body: content).asn1
        }
    }
}
