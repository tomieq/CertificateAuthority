//
//  X509Entity.swift
//  CryptoKeyUtils
//
//  Created by Tomasz Kucharski on 12/07/2025.
//
import SwiftyTLV

public enum X509EntityElement: String {
    case countryCode = "2.5.4.6"
    case province = "2.5.4.8"
    case city = "2.5.4.7"
    case organizationName = "2.5.4.10"
    case organizationalUnitName = "2.5.4.11"
    case commonName = "2.5.4.3"
}

public class X509Entity {
    var elements: [X509EntityElement: String] = [:]
    
    public subscript (key: X509EntityElement) -> String? {
        get {
            elements[key]
        } set {
            elements[key] = newValue
        }
    }
    

}

extension X509Entity {
    public convenience init(countryName: String? = nil,
                stateOrProvinceName: String? = nil,
                city: String? = nil,
                organizationName: String? = nil,
                organizationalUnitName: String? = nil,
                commonName: String) {
        self.init()
        self[.countryCode] = countryName
        self[.province] = stateOrProvinceName
        self[.city] = city
        self[.organizationName] = organizationName
        self[.organizationalUnitName] = organizationalUnitName
        self[.commonName] = commonName
    }
}

extension X509Entity {
    convenience init(asn rows: [ASN1]) {
        self.init()
        for row in rows {
            if case .set(let set) = row, case .sequence(let pair) = set.first {
                if case .objectIdentifier(let oid) = pair.first, let code = X509EntityElement(rawValue: oid) {
                    switch pair[safeIndex: 1] {
                    case .printableString(let value), .utf8String(let value):
                        self[code] = value
                    default:
                        break
                    }
                }
            }
        }
    }
}

public extension X509Entity {
    var asn1: [ASN1] {
        var rows: [ASN1] = []
        for (key, value) in elements.sorted(by: { $0.key.rawValue < $1.key.rawValue }) {
            rows.append(.set([
                .sequence([
                    .objectIdentifier(key.rawValue),
                    .printableString(value)
                ])
            ]))
        }
        return rows
    }
}

extension X509Entity: CustomStringConvertible {
    public var description: String {
        "X509Entity: [\(elements.map { "\($0.key): \($0.value)" }.joined(separator: ", "))]"
    }
}
