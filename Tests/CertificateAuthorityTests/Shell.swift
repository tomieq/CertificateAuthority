//
//  Shell.swift
//  CertificateAuthority
//
//  Created by Tomasz Kucharski on 14/07/2025.
//

import Foundation

struct Shell {
    @discardableResult
    func exec(_ command: String) -> String {
        print("-> \(command)")
        let task = Process()
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        task.arguments = ["-c", command]
        task.launchPath = "/bin/bash"
        task.launch()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)!
        return output.trimmingCharacters(in: .newlines)
    }
}
