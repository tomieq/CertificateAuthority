//
//  KeyUsage.swift
//  CertificateAuthority
//
//  Created by Tomasz Kucharski on 14/07/2025.
//

import Foundation
import SwiftyTLV
import SwiftExtensions

public enum KeyUsagePurpose: UInt16, CaseIterable {
    case digitalSignature = 0x0080 // bit 0
    case nonRepudiation   = 0x0040 // bit 1
    case keyEncipherment  = 0x0020 // bit 2
    case dataEncipherment = 0x0010 // bit 3
    case keyAgreement     = 0x0008 // bit 4
    case keyCertSign      = 0x0004 // bit 5 certificate sign
    case cRLSign          = 0x0002 // bit 6
    case encipherOnly     = 0x0001 // bit 7
    case decipherOnly     = 0x8000 // bit 8
}

public enum KeyUsageError: Error {
    case invalidFormat
    case missingUsageData
}

public class KeyUsage: X509Extension {
    public let type: X509ExtensionType = .keyUsage
    public let isCritical: Bool
    public var purpose: [KeyUsagePurpose]
    
    public init(isCritical: Bool = false, purpose: [KeyUsagePurpose]) {
        self.isCritical = isCritical
        self.purpose = purpose
    }
    
    required public init(asn1: ASN1) throws {
        let envelope = try X509ExtensionEnvelope(asn1: asn1)
        self.isCritical = envelope.isCritical
        
        guard let container = try? ASN1(data: envelope.body) else {
            throw KeyUsageError.invalidFormat
        }
        guard case .bitString(var container) = container else {
            throw KeyUsageError.missingUsageData
        }
        _ = container.consume(bytes: 1)
        var purposeBits = container
        if purposeBits.count == 1 {
            purposeBits = Data([0x00, container.bytes[0]])
        }
        self.purpose = try KeyUsagePurpose.allCases.filter { try purposeBits.uInt16.isBitSet(mask: $0.rawValue) }
    }
}

extension KeyUsage {
    public var asn1: ASN1 {
        get throws {
            let purposeUInt16 = purpose.map{ $0.rawValue }.reduce(0, +)
            let purposeBits = purposeUInt16.data
            var container = [purposeUInt16.trailingZeroBitCount.uInt8]
            if purposeBits[0] == 0 {
                container.append(purposeBits[1])
            } else {
                container.append(contentsOf: purposeBits)
            }

            return try X509ExtensionEnvelope(type: .keyUsage,
                                      isCritical: isCritical,
                                             body: .bitString(container.data)).asn1
        }
    }
}
