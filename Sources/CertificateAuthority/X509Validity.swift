//
//  X509Validity.swift
//  CryptoKeyUtils
//
//  Created by Tomasz Kucharski on 12/07/2025.
//
import Foundation
import SwiftyTLV



public class X509Validity {
    public var from: Date
    public var to: Date
    
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
    convenience init(asn pair: [ASN1]) throws {
        guard case .utcTime(let from) = pair[safeIndex: 0] else {
            throw X509ValidityError.missingFromTime
        }
        guard case .utcTime(let to) = pair[safeIndex: 1] else {
            throw X509ValidityError.missingToTime
        }
        self.init(from: from, to: to)
    }
}

public extension X509Validity {
    var asn1: [ASN1] {
        [.utcTime(from), .utcTime(to)]
    }
}
