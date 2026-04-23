//
//  X509Certificate+String.swift
//  CertificateAuthority
// 
//  Created by: tomieq on 23/04/2026
//
import SwiftExtensions

extension X509Certificate: CustomStringConvertible {
    public var description: String {
        var output = "Serial number:\n\t\(serialNumber.hexString)"
        output.append("\nIssuer:\n\t\(issuer.description.replacingOccurrences(of: ", ", with: "\n\t"))")
        output.append("\nValidity:\n\t\(validity.description.replacingOccurrences(of: ", ", with: "\n\t"))")
        output.append("\nSubject:\n\t\(subject.description.replacingOccurrences(of: ", ", with: "\n\t"))")
        output.append("\nPublic Key:\n\t\(publicKey)")
        output.append("\nExtensions:\n\t\(extensions.count)")
        for ext in self.extensions {
            output.append("\n\(ext)")
        }
        return "X509Certificate {\n\t\(output.replacingOccurrences(of: "\n", with: "\n\t"))\n}"
    }
}

