import "package:meta/meta.dart";

@immutable
class BarnardPermissionStatus {
  const BarnardPermissionStatus({
    required this.platform,
    required this.permissions,
    required this.requiredPermissions,
    required this.missingPermissions,
    required this.requestablePermissions,
    required this.blockedPermissions,
    required this.canScan,
    required this.canAdvertise,
  });

  factory BarnardPermissionStatus.fromMap(Map<Object?, Object?> map) {
    final Map<String, BarnardPermissionDecision> permissions =
        <String, BarnardPermissionDecision>{};
    final Object? rawPermissions = map["permissions"];
    if (rawPermissions is Map) {
      rawPermissions.forEach((Object? key, Object? value) {
        if (key == null) return;
        permissions[key.toString()] = BarnardPermissionDecision.fromName(
          value?.toString(),
        );
      });
    }

    return BarnardPermissionStatus(
      platform: (map["platform"] as String?) ?? "unknown",
      permissions: Map<String, BarnardPermissionDecision>.unmodifiable(
        permissions,
      ),
      requiredPermissions: _stringList(map["requiredPermissions"]),
      missingPermissions: _stringList(map["missingPermissions"]),
      requestablePermissions: _stringList(map["requestablePermissions"]),
      blockedPermissions: _stringList(map["blockedPermissions"]),
      canScan: map["canScan"] == true,
      canAdvertise: map["canAdvertise"] == true,
    );
  }

  final String platform;
  final Map<String, BarnardPermissionDecision> permissions;
  final List<String> requiredPermissions;
  final List<String> missingPermissions;
  final List<String> requestablePermissions;
  final List<String> blockedPermissions;
  final bool canScan;
  final bool canAdvertise;

  bool get allGranted => missingPermissions.isEmpty;
  bool get canRequest => requestablePermissions.isNotEmpty;
  bool get hasBlockedPermissions => blockedPermissions.isNotEmpty;
}

enum BarnardPermissionDecision {
  granted,
  denied,
  notDetermined,
  restricted,
  unsupported,
  unknown;

  static BarnardPermissionDecision fromName(String? name) {
    return switch (name) {
      "granted" => BarnardPermissionDecision.granted,
      "denied" => BarnardPermissionDecision.denied,
      "notDetermined" => BarnardPermissionDecision.notDetermined,
      "restricted" => BarnardPermissionDecision.restricted,
      "unsupported" => BarnardPermissionDecision.unsupported,
      _ => BarnardPermissionDecision.unknown,
    };
  }
}

List<String> _stringList(Object? value) {
  if (value is! List) return const <String>[];
  return List<String>.unmodifiable(value.whereType<String>());
}
