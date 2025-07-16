//
//  X509Extension.swift
//  CryptoKeyUtils
//
//  Created by Tomasz Kucharski on 12/07/2025.
//
import SwiftyTLV

public protocol X509Extension {
    init(asn1: ASN1) throws
    var asn1: ASN1 { get throws }
    var type: X509ExtensionType { get }
}
