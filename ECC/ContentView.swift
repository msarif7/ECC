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
            eccUtility.generateData()
            print("Private key: \(String(describing: eccUtility.privateKey))")
            print("Public key: \(String(describing: eccUtility.publicKey))")
            print("Certificate: \(String(describing: eccUtility.certificate))")
        }
        
    }
}
            
    

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }

}
