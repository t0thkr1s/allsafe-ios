//
//  Allsafe_iOSApp.swift
//  Allsafe-iOS
//
//  Created by Kristóf on 2025. 08. 05..
//

import SwiftUI

@main
struct Allsafe_iOSApp: App {
    let persistenceController = PersistenceController.shared

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(\.managedObjectContext, persistenceController.container.viewContext)
        }
    }
}
