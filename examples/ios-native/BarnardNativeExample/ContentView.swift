// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import Barnard
import SwiftUI

/// Minimal native iOS example (barnard#56): start/stop scan+advertise
/// against the Flutter-free `Barnard` SwiftPM package and print events.
/// No Flutter runtime involved.
@MainActor
final class BarnardExampleModel: ObservableObject {
  private let engine = BarnardEngine()

  @Published var isScanning = false
  @Published var isAdvertising = false
  @Published var log: [String] = []

  init() {
    engine.onEvent = { [weak self] event in
      guard let self = self else { return }
      Task { @MainActor in
        self.handle(event)
      }
    }
  }

  private func handle(_ event: BarnardEvent) {
    switch event {
    case .state(let state):
      isScanning = state.isScanning
      isAdvertising = state.isAdvertising
      append("state: scanning=\(state.isScanning) advertising=\(state.isAdvertising) reason=\(state.reasonCode ?? "-")")
    case .detection(let detection):
      append("detection: rpid=\(detection.rpid) rssi=\(detection.rssi) enin=\(detection.enin)")
    case .rssiUpdate(let update):
      append("rssi_update: rpid=\(update.rpid) rssi=\(update.rssi)")
    case .error(let error):
      append("error: \(error.code) \(error.message)")
    case .constraint(let constraint):
      append("constraint: \(constraint.code) \(constraint.message ?? "")")
    }
  }

  private func append(_ line: String) {
    print("[Barnard] \(line)")
    log.append(line)
    if log.count > 200 {
      log.removeFirst(log.count - 200)
    }
  }

  func requestPermissionsThenStart() {
    engine.requestPermissions { [weak self] status in
      guard let self = self else { return }
      Task { @MainActor in
        self.append("permissions: canScan=\(status.canScan) canAdvertise=\(status.canAdvertise)")
        if status.canScan && status.canAdvertise {
          self.engine.startAuto()
        }
      }
    }
  }

  func stopAuto() {
    engine.stopAuto()
  }
}

struct ContentView: View {
  @StateObject private var model = BarnardExampleModel()

  var body: some View {
    NavigationView {
      VStack(spacing: 12) {
        HStack {
          Text("Scanning: \(model.isScanning ? "on" : "off")")
          Spacer()
          Text("Advertising: \(model.isAdvertising ? "on" : "off")")
        }
        .padding(.horizontal)

        HStack {
          Button("Start") { model.requestPermissionsThenStart() }
          Button("Stop") { model.stopAuto() }
        }

        List(model.log.reversed(), id: \.self) { line in
          Text(line).font(.system(.footnote, design: .monospaced))
        }
      }
      .navigationTitle("Barnard Native")
    }
  }
}
