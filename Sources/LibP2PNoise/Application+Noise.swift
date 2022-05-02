//
//  Application+Noise.swift
//  
//
//  Created by Brandon Toms on 5/1/22.
//

import LibP2P

extension Application.SecurityUpgraders.Provider {
    public static var noise: Self {
        .init { app in
            app.security.use{
                return NoiseUpgrader(application: $0)
            }
        }
    }
}
