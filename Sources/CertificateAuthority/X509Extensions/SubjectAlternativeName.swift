//
//  SubjectAlternativeName.swift
//  CertificateAuthority
//
//  Created by Tomasz Kucharski on 16/07/2025.
//

import SwiftyTLV
import SwiftExtensions

public class SubjectAlternativeName: X509Extension {
    public let type: X509ExtensionType = .subjectAlternativeName
    public let isCritical: Bool
    public var names: [String]
    
    public init(isCritical: Bool = false, names: [String]) {
        self.isCritical = isCritical
        self.names = names
    }
    
    required public init(asn1: ASN1) throws {
        let envelope = try X509ExtensionEnvelope(asn1: asn1)
        self.isCritical = envelope.isCritical
        
        let sections = try ASN1(data: envelope.body).children
        names = sections.compactMap {
            guard case .contextSpecificPrimitive(let integer) = $0, case .integer(let data) = integer else { return nil }
            return String(data: data, encoding: .utf8)
        }
        print(names)
    }
}

extension SubjectAlternativeName {
    public var asn1: ASN1 {
        get throws {
            var content = ASN1.sequence([])
            try names.compactMap{ $0.data(using: .utf8) }.forEach {
                try content.append(.contextSpecificPrimitive(
                    .integer($0)))
            }
            return try X509ExtensionEnvelope(type: .subjectAlternativeName,
                                             isCritical: isCritical,
                                             body: content).asn1
        }
    }
}
