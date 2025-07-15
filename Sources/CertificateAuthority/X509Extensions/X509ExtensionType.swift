//
//  X509ExtensionType.swift
//  CryptoKeyUtils
//
//  Created by Tomasz Kucharski on 12/07/2025.
//

enum X509ExtensionType: String {
    case basicConstraints = "2.5.29.19"
    case subjectKeyIdentifier = "2.5.29.14"
    case keyUsage = "2.5.29.15"
    case authorityKeyIdentifier = "2.5.29.35"
}

extension X509ExtensionType {
    var x509Extension: X509Extension.Type {
        switch self {
        case .basicConstraints:
            BasicConstraints.self
        case .subjectKeyIdentifier:
            SubjectKeyIdentifier.self
        case .authorityKeyIdentifier:
            AuthorityKeyIdentifier.self
        case .keyUsage:
            KeyUsage.self
        }
    }
}
