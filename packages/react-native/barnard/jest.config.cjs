module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  clearMocks: true,
  roots: ['<rootDir>/__tests__'],
  modulePathIgnorePatterns: ['<rootDir>/lib/'],
};
