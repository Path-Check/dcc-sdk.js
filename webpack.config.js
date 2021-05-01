const path = require('path');
const webpack = require('webpack')

module.exports = {
  mode: "production",
  entry: "./lib/index.js",
  devtool: "source-map",
  output: {
    filename: 'eu.min.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'EU',
    libraryTarget: 'umd',
  },
  target: 'web',
  optimization: {
    minimize: false
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