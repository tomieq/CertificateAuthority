//
//  X509Section.swift
//  CryptoKeyUtils
//
//  Created by Tomasz Kucharski on 12/07/2025.
//

enum X509Section: Int {
    case version
    case serialNumber
    case signatureAlg
    case issuer
    case dateValidity
    case subject
    case publicKey
    case extensions
}
