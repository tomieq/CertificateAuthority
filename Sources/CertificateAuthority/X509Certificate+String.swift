//
//  X509Certificate+String.swift
//  CertificateAuthority
// 
//  Created by: tomieq on 23/04/2026
//

extension X509Certificate: CustomStringConvertible {
    public var description: String {
        var output = "Serial number:\n\t\(serialNumber.hexString)"
        output.append("\nIssuer:\n\t\(issuer)")
        output.append("\nValidity:\n\t\(validity)")
        output.append("\nSubject:\n\t\(subject)")
        output.append("\nPublic Key:\n\t\(publicKey)")
        output.append("\nExtensions:\n\t\(extensions.count)")
        for ext in self.extensions {
            output.append("\n\(ext)")
        }
        return output
    }
}

