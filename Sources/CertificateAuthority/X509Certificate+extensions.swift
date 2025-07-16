//
//  X509Certificate+extensions.swift
//  CertificateAuthority
//
//  Created by Tomasz Kucharski on 16/07/2025.
//
import SwiftExtensions
import Foundation

extension X509Certificate {
    public var alternativeNames: [String]? {
        get {
            extensions
                .first { $0.type == .subjectAlternativeName }
                .cast(to: SubjectAlternativeName.self)?.names
        }
        set {
            newValue
                .onValue { names in
                    // create or update extension
                    extensions
                        .first { $0.type == .subjectAlternativeName }
                        .cast(to: SubjectAlternativeName.self)
                        .onNil {
                            extensions.append(SubjectAlternativeName(isCritical: false, names: names))
                        }.onValue {
                            $0.names = names
                        }
                }
                .onNil {
                    // remove extension
                    extensions.removeAll { $0.type == .subjectAlternativeName }
                }
        }
    }
    
    public var keyUsage: [KeyUsagePurpose]? {
        get {
            extensions
                .first { $0.type == .keyUsage }
                .cast(to: KeyUsage.self)?.purpose
        }
        set {
            newValue
                .onValue { keyUsagePurpose in
                    // create or update extension
                    extensions
                        .first { $0.type == .keyUsage }
                        .cast(to: KeyUsage.self)
                        .onNil {
                            extensions.append(KeyUsage(isCritical: true, purpose: keyUsagePurpose))
                        }.onValue {
                            $0.purpose = keyUsagePurpose
                        }
                }
                .onNil {
                    // remove extension
                    extensions.removeAll { $0.type == .keyUsage }
                }
        }
    }
    
    public var extendedKeyUsage: [ExtendedKeyUsagePurpose]? {
        get {
            extensions
                .first { $0.type == .extendedKeyUsage }
                .cast(to: ExtendedKeyUsage.self)?.purposes
        }
        set {
            newValue
                .onValue { keyUsagePurpose in
                    // create or update extension
                    extensions
                        .first { $0.type == .extendedKeyUsage }
                        .cast(to: ExtendedKeyUsage.self)
                        .onNil {
                            extensions.append(ExtendedKeyUsage(isCritical: false, purposes: keyUsagePurpose))
                        }.onValue {
                            $0.purposes = keyUsagePurpose
                        }
                }
                .onNil {
                    // remove extension
                    extensions.removeAll { $0.type == .extendedKeyUsage }
                }
        }
    }
    
    public var subjectKeyIdentifier: Data? {
        get {
            extensions
                .first { $0.type == .subjectKeyIdentifier }
                .cast(to: SubjectKeyIdentifier.self)?.keyID
        }
        set {
            newValue
                .onValue { newKeyID in
                    // create or update extension
                    extensions
                        .first { $0.type == .subjectKeyIdentifier }
                        .cast(to: SubjectKeyIdentifier.self)
                        .onNil {
                            extensions.append(SubjectKeyIdentifier(isCritical: false, keyID: newKeyID))
                        }.onValue {
                            $0.keyID = newKeyID
                        }
                }
                .onNil {
                    // remove extension
                    extensions.removeAll { $0.type == .subjectKeyIdentifier }
                }
        }
    }
    
    public var isCA: Bool {
        extensions
            .first { $0.type == .basicConstraints }
            .cast(to: BasicConstraints.self)?.isCertificateAuthority ?? false
    }
    
    public func configure(authorityKeyIdentifier newValue: AuthorityKeyIdentifier?) {
        newValue
            .onValue { newValue in
                // create or replace extension
                extensions
                    .first { $0.type == .authorityKeyIdentifier }
                    .onNil {
                        extensions.append(newValue)
                    }
                    .onValue { _ in
                        extensions.removeAll { $0.type == .authorityKeyIdentifier }
                        extensions.append(newValue)
                    }
            }
            .onNil {
                // remove extension
                extensions.removeAll { $0.type == .authorityKeyIdentifier }
            }
    }
    
    public func configure(basicConstraints newValue: BasicConstraints?) {
        newValue
            .onValue { newValue in
                // create or replace extension
                extensions
                    .first { $0.type == .basicConstraints }
                    .onNil {
                        extensions.append(newValue)
                    }
                    .onValue { _ in
                        extensions.removeAll { $0.type == .basicConstraints }
                        extensions.append(newValue)
                    }
            }
            .onNil {
                // remove extension
                extensions.removeAll { $0.type == .basicConstraints }
            }
    }
    
    public func getExtension<T: X509Extension>() -> T? {
        extensions.first{ $0 is T } as? T
    }
}
