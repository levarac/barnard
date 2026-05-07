import React, { useEffect, useState, useCallback } from 'react';
import {
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  View,
  Button,
  Alert,
  Platform,
} from 'react-native';
import {
  BarnardManager,
  DetectionEvent,
  BarnardCapabilities,
  BarnardPermissionStatus,
  BarnardState,
} from 'barnard';

interface Detection {
  id: string;
  detectedDisplayId: string | null;
  rssi: number;
  enin: number;
  timestamp: string;
  transport: string;
}

const permissionStatusLabel = (status: BarnardPermissionStatus | null): string => {
  if (!status) return 'Checking';
  if (status.missingPermissions.length === 0) return 'Allowed';
  if (status.missingPermissions.includes('ios.bluetooth')) {
    return 'Not determined';
  }
  return status.missingPermissions.join(', ');
};

const App = () => {
  const [manager] = useState(() => new BarnardManager());
  const [capabilities, setCapabilities] = useState<BarnardCapabilities | null>(null);
  const [state, setState] = useState<BarnardState>({ isScanning: false, isAdvertising: false });
  const [myDisplayId, setMyDisplayId] = useState<string>('—');
  const [currentEnin, setCurrentEnin] = useState<number | null>(null);
  const [currentEventCode, setCurrentEventCode] = useState<string | null>(null);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [permissionsGranted, setPermissionsGranted] = useState(false);
  const [permissionStatus, setPermissionStatus] = useState<BarnardPermissionStatus | null>(null);

  const refreshPermissions = useCallback(async () => {
    const status = await manager.getPermissionStatus();
    setPermissionStatus(status);
    setPermissionsGranted(status.missingPermissions.length === 0);
    return status;
  }, [manager]);

  const requestPermissions = useCallback(async () => {
    const status = await manager.requestPermissions();
    setPermissionStatus(status);
    const granted = status.missingPermissions.length === 0;
    setPermissionsGranted(granted);
    if (!granted) {
      Alert.alert('Permissions Required', 'Please grant all Bluetooth permissions');
    }
    return granted;
  }, [manager]);

  const refreshIdentity = useCallback(async () => {
    try {
      const [displayId, enin, code] = await Promise.all([
        manager.getMyDisplayId(),
        manager.getCurrentEnin(),
        manager.getCurrentEventCode(),
      ]);
      setMyDisplayId(displayId);
      setCurrentEnin(enin);
      setCurrentEventCode(code);
    } catch (err) {
      console.warn('identity refresh failed', err);
    }
  }, [manager]);

  useEffect(() => {
    refreshPermissions();

    manager.getCapabilities().then((caps) => {
      setCapabilities(caps);
      console.log('Capabilities:', caps);
    });

    refreshIdentity();

    const unsubDetection = manager.onDetection((event: DetectionEvent) => {
      console.log('Detection:', event.detectedDisplayId, event.rssi, event.enin);
      setDetections((prev) => {
        const newDetection: Detection = {
          id: event.rpid,
          detectedDisplayId: event.detectedDisplayId,
          rssi: event.rssi,
          enin: event.enin,
          timestamp: new Date(event.timestamp).toLocaleTimeString(),
          transport: event.transport,
        };
        return [newDetection, ...prev].slice(0, 20);
      });
    });

    const unsubState = manager.onStateChange((event) => {
      console.log('State change:', event.state);
      setState(event.state);
      if (event.state.eventCode !== undefined) {
        setCurrentEventCode(event.state.eventCode ?? null);
      }
    });

    const unsubConstraint = manager.onConstraint((event) => {
      console.log('Constraint:', event.code, event.message);
      Alert.alert('Constraint', `${event.code}: ${event.message}`);
    });

    const unsubError = manager.onError((event) => {
      console.log('Error:', event.code, event.message);
      Alert.alert('Error', `${event.code}: ${event.message}`);
    });

    const unsubDebug = manager.onDebug((event) => {
      console.log('Debug:', event.level, event.name, event.data);
    });

    const id = setInterval(refreshIdentity, 3000);

    return () => {
      clearInterval(id);
      unsubDetection();
      unsubState();
      unsubConstraint();
      unsubError();
      unsubDebug();
      manager.dispose();
    };
  }, [manager, refreshIdentity, refreshPermissions]);

  const handleStartAuto = async () => {
    if (!permissionsGranted) {
      const granted = await requestPermissions();
      if (!granted) return;
    }
    try {
      const result = await manager.startAuto({
        scan: { allowDuplicates: true },
        advertise: { formatVersion: 1 },
      });
      console.log('Started:', result);
      await refreshIdentity();
    } catch (error) {
      console.error('Start failed:', error);
      Alert.alert('Start Failed', String(error));
    }
  };

  const handleStopAuto = async () => {
    try {
      await manager.stopAuto();
      setDetections([]);
    } catch (error) {
      console.error('Stop failed:', error);
    }
  };

  const handleExportTek = async () => {
    try {
      const tek = await manager.exportCurrentTek();
      Alert.alert('TEK exported', tek);
    } catch (error) {
      Alert.alert('Export failed', String(error));
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView contentContainerStyle={styles.scrollContent}>
        <Text style={styles.title}>Barnard v2 Demo</Text>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Identity (v2)</Text>
          <Text style={styles.infoText}>myDisplayId: {myDisplayId}</Text>
          <Text style={styles.infoText}>currentEnin: {currentEnin ?? '—'}</Text>
          <Text style={styles.infoText}>eventCode: {currentEventCode ?? '—'}</Text>
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Capabilities</Text>
          {capabilities && (
            <View>
              <Text style={styles.infoText}>
                Transports: {capabilities.supportedTransports.join(', ')}
              </Text>
              <Text style={styles.infoText}>
                GATT Fallback: {capabilities.supportsGattFallback ? 'Yes' : 'No'}
              </Text>
            </View>
          )}
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>State</Text>
          <Text style={styles.infoText}>
            Scanning: {state.isScanning ? '✓' : '✗'}
          </Text>
          <Text style={styles.infoText}>
            Advertising: {state.isAdvertising ? '✓' : '✗'}
          </Text>
          <Text style={styles.infoText}>
            Permissions: {permissionsGranted ? '✓' : '✗'}
          </Text>
          <Text style={styles.infoText}>
            Bluetooth: {permissionStatusLabel(permissionStatus)}
          </Text>
          {!permissionsGranted && (
            <View style={styles.buttonRow}>
              <Button title="Allow Bluetooth" onPress={requestPermissions} />
            </View>
          )}
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Controls</Text>
          <View style={styles.buttonRow}>
            <Button
              title={state.isScanning || state.isAdvertising ? 'Stop All' : 'Start All'}
              onPress={state.isScanning || state.isAdvertising ? handleStopAuto : handleStartAuto}
              color={state.isScanning || state.isAdvertising ? '#dc3545' : '#28a745'}
            />
          </View>
          <View style={styles.buttonRow}>
            <Button title="Export TEK" onPress={handleExportTek} />
          </View>
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>
            Detections ({detections.length})
          </Text>
          {detections.length === 0 ? (
            <Text style={styles.emptyText}>No detections yet</Text>
          ) : (
            detections.map((detection, index) => (
              <View key={`${detection.id}-${index}`} style={styles.detectionItem}>
                <Text style={styles.detectionId}>
                  {detection.detectedDisplayId ?? '(no B003)'}
                </Text>
                <Text style={styles.detectionInfo}>
                  RSSI: {detection.rssi} dBm | ENIN: {detection.enin} | {detection.timestamp}
                </Text>
              </View>
            ))
          )}
        </View>
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  scrollContent: {
    padding: 16,
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 20,
    color: '#333',
  },
  section: {
    backgroundColor: '#fff',
    borderRadius: 8,
    padding: 16,
    marginBottom: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: '600',
    marginBottom: 12,
    color: '#333',
  },
  infoText: {
    fontSize: 14,
    marginBottom: 6,
    color: '#666',
  },
  buttonRow: {
    flexDirection: 'row',
    marginBottom: 8,
  },
  buttonSpacer: {
    width: 8,
  },
  emptyText: {
    fontSize: 14,
    fontStyle: 'italic',
    color: '#999',
    textAlign: 'center',
  },
  detectionItem: {
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
    paddingVertical: 8,
  },
  detectionId: {
    fontSize: 16,
    fontWeight: '600',
    color: '#007AFF',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  detectionInfo: {
    fontSize: 12,
    color: '#666',
    marginTop: 2,
  },
});

export default App;
