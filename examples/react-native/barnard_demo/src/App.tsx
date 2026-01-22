import React, { useEffect, useState, useCallback } from 'react';
import {
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  View,
  Button,
  PermissionsAndroid,
  Platform,
  Alert,
} from 'react-native';
import {
  BarnardManager,
  DetectionEvent,
  BarnardCapabilities,
  BarnardState,
} from 'react-native-barnard';

interface Detection {
  id: string;
  displayId: string;
  rssi: number;
  timestamp: string;
  transport: string;
}

const App = () => {
  const [manager] = useState(() => new BarnardManager());
  const [capabilities, setCapabilities] = useState<BarnardCapabilities | null>(null);
  const [state, setState] = useState<BarnardState>({ isScanning: false, isAdvertising: false });
  const [detections, setDetections] = useState<Detection[]>([]);
  const [permissionsGranted, setPermissionsGranted] = useState(false);

  const requestPermissions = useCallback(async () => {
    if (Platform.OS === 'android') {
      if (Platform.Version >= 31) {
        const result = await PermissionsAndroid.requestMultiple([
          PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
          PermissionsAndroid.PERMISSIONS.BLUETOOTH_ADVERTISE,
          PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
        ]);
        const granted = Object.values(result).every(
          status => status === PermissionsAndroid.RESULTS.GRANTED
        );
        setPermissionsGranted(granted);
        if (!granted) {
          Alert.alert('Permissions Required', 'Please grant all Bluetooth permissions');
        }
        return granted;
      } else {
        const result = await PermissionsAndroid.requestMultiple([
          PermissionsAndroid.PERMISSIONS.BLUETOOTH,
          PermissionsAndroid.PERMISSIONS.BLUETOOTH_ADMIN,
          PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
        ]);
        const granted = Object.values(result).every(
          status => status === PermissionsAndroid.RESULTS.GRANTED
        );
        setPermissionsGranted(granted);
        if (!granted) {
          Alert.alert('Permissions Required', 'Please grant all Bluetooth permissions');
        }
        return granted;
      }
    }
    setPermissionsGranted(true);
    return true;
  }, []);

  useEffect(() => {
    requestPermissions();

    // Get capabilities
    manager.getCapabilities().then(caps => {
      setCapabilities(caps);
      console.log('Capabilities:', caps);
    });

    // Subscribe to detections
    const unsubDetection = manager.onDetection((event: DetectionEvent) => {
      console.log('Detection:', event.displayId, event.rssi);
      setDetections(prev => {
        const newDetection: Detection = {
          id: event.rpid,
          displayId: event.displayId,
          rssi: event.rssi,
          timestamp: new Date(event.timestamp).toLocaleTimeString(),
          transport: event.transport,
        };
        // Keep last 20 detections
        return [newDetection, ...prev].slice(0, 20);
      });
    });

    // Subscribe to state changes
    const unsubState = manager.onStateChange(event => {
      console.log('State change:', event.state);
      setState(event.state);
    });

    // Subscribe to constraints
    const unsubConstraint = manager.onConstraint(event => {
      console.log('Constraint:', event.code, event.message);
      Alert.alert('Constraint', `${event.code}: ${event.message}`);
    });

    // Subscribe to errors
    const unsubError = manager.onError(event => {
      console.log('Error:', event.code, event.message);
      Alert.alert('Error', `${event.code}: ${event.message}`);
    });

    // Subscribe to debug events
    const unsubDebug = manager.onDebug(event => {
      console.log('Debug:', event.level, event.name, event.data);
    });

    return () => {
      unsubDetection();
      unsubState();
      unsubConstraint();
      unsubError();
      unsubDebug();
      manager.dispose();
    };
  }, [manager, requestPermissions]);

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

  const handleStartScan = async () => {
    if (!permissionsGranted) {
      const granted = await requestPermissions();
      if (!granted) return;
    }
    try {
      await manager.startScan({ allowDuplicates: true });
    } catch (error) {
      Alert.alert('Start Scan Failed', String(error));
    }
  };

  const handleStopScan = async () => {
    try {
      await manager.stopScan();
    } catch (error) {
      console.error('Stop scan failed:', error);
    }
  };

  const handleStartAdvertise = async () => {
    if (!permissionsGranted) {
      const granted = await requestPermissions();
      if (!granted) return;
    }
    try {
      await manager.startAdvertise({ formatVersion: 1 });
    } catch (error) {
      Alert.alert('Start Advertise Failed', String(error));
    }
  };

  const handleStopAdvertise = async () => {
    try {
      await manager.stopAdvertise();
    } catch (error) {
      console.error('Stop advertise failed:', error);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView contentContainerStyle={styles.scrollContent}>
        <Text style={styles.title}>Barnard Demo</Text>

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
            <Button
              title={state.isScanning ? 'Stop Scan' : 'Start Scan'}
              onPress={state.isScanning ? handleStopScan : handleStartScan}
            />
            <View style={styles.buttonSpacer} />
            <Button
              title={state.isAdvertising ? 'Stop Adv' : 'Start Adv'}
              onPress={state.isAdvertising ? handleStopAdvertise : handleStartAdvertise}
            />
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
                <Text style={styles.detectionId}>{detection.displayId}</Text>
                <Text style={styles.detectionInfo}>
                  RSSI: {detection.rssi} dBm | {detection.timestamp}
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
