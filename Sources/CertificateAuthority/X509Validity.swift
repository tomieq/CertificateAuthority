//
//  X509Validity.swift
//  CryptoKeyUtils
//
//  Created by Tomasz Kucharski on 12/07/2025.
//
import Foundation
import SwiftyTLV



public struct X509Validity {
    public let from: Date
    public let to: Date
    
    public init(from: Date, to: Date) {
        self.from = from
        self.to = to
    }
}

public enum X509ValidityError: Error {
    case missingFromTime
    case missingToTime
}

extension X509Validity {
    init(asn pair: [ASN1]) throws {
        guard case .utcTime(let from) = pair[safeIndex: 0] else {
            throw X509ValidityError.missingFromTime
        }
        self.from = from
        guard case .utcTime(let to) = pair[safeIndex: 1] else {
            throw X509ValidityError.missingToTime
        }
        self.to = to
    }
}

public extension X509Validity {
    var asn1: [ASN1] {
        [.utcTime(from), .utcTime(to)]
    }
}
