//
//  ContentView.swift
//  ECC
//
//  Created by MSA Software on 3/23/23.
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundColor(.accentColor)
            Text("Hello, world!")
        }
        .padding()
        .onAppear {
            let eccUtility = EccUtility()
            eccUtility?.generateKey()
            let dataToSign = "Hello,world!".data(using: .utf8)!
            guard let signature = eccUtility?.signData(data: dataToSign) else {
                        print("Failed to sign data")
                        return
                    }
            // Verify the signature using the public key
            let signatureIsValid = eccUtility?.verifyData(data: dataToSign, signature: signature)
            print(signatureIsValid!)
            
        }
        
    }
}
            
struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }

}
