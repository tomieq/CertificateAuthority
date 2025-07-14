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
        var section = 0
        if case .contextSpecificPrimitive(let customTLV) = content[safeIndex: section] , case .customTlv(let tlv) = customTLV {
            section.increment()
            self.issuerKeyID = tlv.value
        } else {
            self.issuerKeyID = nil
        }
        
        // issuer
        if case .contextSpecificConstructed(tag: 1, let container) = content[safeIndex: section], case .contextSpecificConstructed(tag: 4, let sequence) = container.first, let issuerASN1 = sequence.first?.children {
            self.issuer = X509Entity(asn: issuerASN1)
            section.increment()
        } else {
            self.issuer = nil
        }

        // serial number
        if case .contextSpecificPrimitive(let container) = content[safeIndex: section], case .integer(let serialNumber) = container {
            self.issuerSerialNumber = serialNumber
        } else {
            self.issuerSerialNumber = nil
        }
        
    }
}

extension AuthorityKeyIdentifier {
    public var asn1: ASN1 {
        get throws {
            var content: [ASN1] = [ .objectIdentifier(X509ExtensionType.authorityKeyIdentifier.rawValue) ]
            if isCritical { content.append(.boolean(isCritical)) }
            
            var issuerContent: [ASN1] = []
            if let issuerKeyID {
                issuerContent.append(.contextSpecificPrimitive(.customTlv(BerTlv(tag: 0.data, value: issuerKeyID))))
            }
            
            if let issuer {
                issuerContent.append(.contextSpecificConstructed(tag: 1, [
                    .contextSpecificConstructed(tag: 4, [.sequence(issuer.asn1)])
                ]))
            }
            if let issuerSerialNumber {
                issuerContent.append(.contextSpecificPrimitive(.integer(issuerSerialNumber)))
            }
            
            // all are optional
            let issuerInfo = ASN1.sequence(issuerContent)
            content.append(.octetString(try issuerInfo.data))
            return ASN1.sequence(content)
        }
    }
}
