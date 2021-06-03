const path = require('path');
const webpack = require('webpack')

module.exports = {
  mode: "production",
  entry: "./lib/main.js",
  devtool: "source-map",
  output: {
    filename: 'dcc-sdk.min.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'DCC',
    libraryTarget: 'umd',
  },
  target: 'web',

  optimization: {
    minimize: true
  },
  node: {
    net: 'empty',
  },
  plugins: [
    new webpack.ProvidePlugin({
      process: 'process/browser'
    })
  ],
};