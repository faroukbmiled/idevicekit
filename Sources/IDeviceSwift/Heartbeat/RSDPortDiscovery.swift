//
//  RSDPortDiscovery.swift
//  IDeviceKit
//
//  Created by Ryuk
//

import Foundation
import dnssd

// Newer iOS versions don't always serve remote pairing on 49152, so ask Bonjour where it is.
final class RSDPortDiscovery {
	private struct Service {
		let name: String
		let type: String
		let domain: String
		let interface: UInt32

		var isLoopback: Bool {
			var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
			guard if_indextoname(interface, &name) != nil else { return false }
			return String(cString: name).hasPrefix("lo")
		}
	}

	private static let _serviceType = "_remotepairing._tcp"

	private var _services: [Service] = []
	private var _browseDone = false
	private var _resolvedPort: UInt16?

	static func ports(timeout: TimeInterval = 2) -> [UInt16] {
		let discovery = RSDPortDiscovery()
		let deadline = Date().addingTimeInterval(timeout)

		discovery._browse(until: deadline)

		let services = discovery._services.sorted { $0.isLoopback && !$1.isLoopback }
		var ports: [UInt16] = []
		for service in services.prefix(4) {
			if let port = discovery._resolve(service, until: deadline), !ports.contains(port) {
				ports.append(port)
			}
		}
		return ports
	}

	private func _browse(until deadline: Date) {
		var ref: DNSServiceRef?
		let context = Unmanaged.passUnretained(self).toOpaque()

		let error = DNSServiceBrowse(&ref, 0, 0, Self._serviceType, nil, { _, flags, interface, error, name, type, domain, context in
			guard let context else { return }
			let discovery = Unmanaged<RSDPortDiscovery>.fromOpaque(context).takeUnretainedValue()

			guard error == kDNSServiceErr_NoError else {
				discovery._browseDone = true
				return
			}
			if flags & kDNSServiceFlagsAdd != 0, let name, let type, let domain {
				discovery._services.append(Service(
					name: String(cString: name),
					type: String(cString: type),
					domain: String(cString: domain),
					interface: interface
				))
			}
			if flags & kDNSServiceFlagsMoreComing == 0, !discovery._services.isEmpty {
				discovery._browseDone = true
			}
		}, context)

		guard error == kDNSServiceErr_NoError, let ref else { return }
		defer { DNSServiceRefDeallocate(ref) }

		Self._pump(ref, until: deadline) { !self._browseDone }
	}

	private func _resolve(_ service: Service, until deadline: Date) -> UInt16? {
		var ref: DNSServiceRef?
		let context = Unmanaged.passUnretained(self).toOpaque()
		_resolvedPort = nil

		let error = DNSServiceResolve(&ref, 0, service.interface, service.name, service.type, service.domain, { _, _, _, error, _, _, port, _, _, context in
			guard let context, error == kDNSServiceErr_NoError else { return }
			Unmanaged<RSDPortDiscovery>.fromOpaque(context).takeUnretainedValue()._resolvedPort = UInt16(bigEndian: port)
		}, context)

		guard error == kDNSServiceErr_NoError, let ref else { return nil }
		defer { DNSServiceRefDeallocate(ref) }

		Self._pump(ref, until: deadline) { self._resolvedPort == nil }
		return _resolvedPort.flatMap { $0 == 0 ? nil : $0 }
	}

	private static func _pump(_ ref: DNSServiceRef, until deadline: Date, while pending: () -> Bool) {
		var descriptor = pollfd(fd: DNSServiceRefSockFD(ref), events: Int16(POLLIN), revents: 0)

		while pending() {
			let remaining = deadline.timeIntervalSinceNow
			guard remaining > 0,
				  poll(&descriptor, 1, Int32(remaining * 1000)) > 0,
				  DNSServiceProcessResult(ref) == kDNSServiceErr_NoError
			else { return }
		}
	}
}

