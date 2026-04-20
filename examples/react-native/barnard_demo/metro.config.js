const path = require('path');
const {getDefaultConfig, mergeConfig} = require('@react-native/metro-config');

const projectRoot = __dirname;
const barnardPkgRoot = path.resolve(projectRoot, '../../../packages/react-native/barnard');

// Metro does not follow symlinks outside the project root by default, so we
// tell it about the in-tree barnard package here. Required because
// `"barnard": "file:../../../packages/react-native/barnard"` resolves to
// a path outside this project root.
const config = {
  projectRoot,
  watchFolders: [barnardPkgRoot],
  resolver: {
    nodeModulesPaths: [path.resolve(projectRoot, 'node_modules')],
    extraNodeModules: {
      barnard: barnardPkgRoot,
    },
  },
};

module.exports = mergeConfig(getDefaultConfig(projectRoot), config);
